using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace Callosotomy.Service;

/// <summary>
/// Listens to Windows' kernel network event stream (ETW) and keeps a running tally of every
/// TCP and UDP flow: which process, which remote address and port, bytes each way.
/// This catches what the connection table can't: UDP destinations (QUIC/HTTP3, DNS, games,
/// calls) and connections too short to be caught between table reads.
///
/// Cost: Windows pushes events to us; we only add numbers to a dictionary. The session runs only
/// while the monitor is open and stops itself after <see cref="IdleStop"/> without a request.
/// </summary>
internal sealed class NetworkEvents : IDisposable
{
    private const string SessionName = "Callosotomy-Network";
    private const int MaxFlows = 10000;
    private static readonly TimeSpan IdleStop = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan FlowLifetime = TimeSpan.FromMinutes(2);

    private readonly ILogger<NetworkEvents> _log;
    private readonly object _lock = new();
    private readonly Dictionary<FlowKey, Flow> _flows = new();
    private readonly Timer _idleTimer;
    private TraceEventSession? _session;
    private Thread? _thread;
    private DateTime _lastTouch;
    private HashSet<IPAddress> _localAddresses = new();
    private bool _unavailable;

    public readonly record struct FlowKey(uint Pid, bool Tcp, IPAddress Remote, int RemotePort);

    public sealed class Flow
    {
        public long Sent;
        public long Received;
        public bool Inbound;
        public DateTime First;
        public DateTime Last;
        public IPAddress? Local;
        public int LocalPort;
    }

    public NetworkEvents(ILogger<NetworkEvents> log)
    {
        _log = log;
        _idleTimer = new Timer(_ => StopIfIdle(), null, Timeout.Infinite, Timeout.Infinite);
        NetworkChange.NetworkAddressChanged += (_, _) => RefreshLocalAddresses();
    }

    /// <summary>True while events are flowing. False if the session couldn't start (the table still works).</summary>
    public bool Active { get { lock (_lock) return _session is not null; } }

    /// <summary>Called on every monitor request: starts the session if needed and keeps it alive.</summary>
    public void Touch()
    {
        lock (_lock)
        {
            _lastTouch = DateTime.UtcNow;
            if (_session is not null || _unavailable) return;
            try
            {
                RefreshLocalAddresses();
                // Reusing the name stops any session a crashed earlier run left behind.
                var session = new TraceEventSession(SessionName) { StopOnDispose = true };
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
                var k = session.Source.Kernel;
                k.TcpIpSend += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, e.size, 0, false);
                k.TcpIpRecv += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, 0, e.size, false);
                k.TcpIpAccept += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, 0, 0, true);
                k.TcpIpConnect += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, 0, 0, false);
                k.TcpIpSendIPV6 += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, e.size, 0, false);
                k.TcpIpRecvIPV6 += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, 0, e.size, false);
                k.TcpIpAcceptIPV6 += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, 0, 0, true);
                k.TcpIpConnectIPV6 += e => Add(e.ProcessID, true, e.saddr, e.sport, e.daddr, e.dport, 0, 0, false);
                k.UdpIpSend += e => Add(e.ProcessID, false, e.saddr, e.sport, e.daddr, e.dport, e.size, 0, false);
                k.UdpIpRecv += e => Add(e.ProcessID, false, e.saddr, e.sport, e.daddr, e.dport, 0, e.size, false);
                k.UdpIpSendIPV6 += e => Add(e.ProcessID, false, e.saddr, e.sport, e.daddr, e.dport, e.size, 0, false);
                k.UdpIpRecvIPV6 += e => Add(e.ProcessID, false, e.saddr, e.sport, e.daddr, e.dport, 0, e.size, false);

                _session = session;
                _thread = new Thread(() =>
                {
                    try { session.Source.Process(); }
                    catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException) { }
                })
                { IsBackground = true, Name = "Callosotomy network events", Priority = ThreadPriority.BelowNormal };
                _thread.Start();
                _idleTimer.Change(TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
                Log.EventsStarted(_log);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or System.Runtime.InteropServices.COMException or NotSupportedException)
            {
                // Fall back to the connection table alone; don't retry on every request.
                _unavailable = true;
                Log.EventsUnavailable(_log, ex);
            }
        }
    }

    /// <summary>Flows seen within the last two minutes.</summary>
    public List<KeyValuePair<FlowKey, Flow>> Snapshot()
    {
        lock (_lock)
        {
            var cutoff = DateTime.UtcNow - FlowLifetime;
            foreach (var k in _flows.Where(kv => kv.Value.Last < cutoff).Select(kv => kv.Key).ToList()) _flows.Remove(k);
            return _flows.Select(kv => new KeyValuePair<FlowKey, Flow>(kv.Key, new Flow
            {
                Sent = kv.Value.Sent, Received = kv.Value.Received, Inbound = kv.Value.Inbound,
                First = kv.Value.First, Last = kv.Value.Last, Local = kv.Value.Local, LocalPort = kv.Value.LocalPort,
            })).ToList();
        }
    }

    private void Add(int pid, bool tcp, IPAddress src, int sport, IPAddress dst, int dport, long sent, long received, bool inbound)
    {
        if (pid < 0 || src is null || dst is null) return;
        // The kernel reports source and destination as seen on the wire; the remote end is
        // whichever address isn't one of ours.
        bool srcIsLocal = IPAddress.IsLoopback(src) || _localAddresses.Contains(src);
        var (remote, rport, local, lport) = srcIsLocal ? (dst, dport, src, sport) : (src, sport, dst, dport);
        if (IPAddress.IsLoopback(remote)) return;

        var key = new FlowKey((uint)pid, tcp, remote, rport);
        var now = DateTime.UtcNow;
        lock (_lock)
        {
            if (!_flows.TryGetValue(key, out var f))
            {
                if (_flows.Count >= MaxFlows) return; // full: drop new flows rather than grow
                _flows[key] = f = new Flow { First = now, Local = local, LocalPort = lport };
            }
            f.Sent += sent;
            f.Received += received;
            f.Inbound |= inbound;
            f.Last = now;
        }
    }

    private void RefreshLocalAddresses()
    {
        var set = new HashSet<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var a in nic.GetIPProperties().UnicastAddresses)
                    set.Add(a.Address.ScopeId != 0 ? new IPAddress(a.Address.GetAddressBytes()) : a.Address);
        }
        catch (NetworkInformationException)
        {
            return;
        }
        _localAddresses = set;
    }

    private void StopIfIdle()
    {
        lock (_lock)
        {
            if (_session is null || DateTime.UtcNow - _lastTouch < IdleStop) return;
            StopLocked();
            Log.EventsStopped(_log);
        }
    }

    private void StopLocked()
    {
        _idleTimer.Change(Timeout.Infinite, Timeout.Infinite);
        _session?.Dispose(); // stops the session; Process() returns and the thread ends
        _session = null;
        _flows.Clear();
    }

    public void Dispose()
    {
        lock (_lock) StopLocked();
        _idleTimer.Dispose();
    }
}
