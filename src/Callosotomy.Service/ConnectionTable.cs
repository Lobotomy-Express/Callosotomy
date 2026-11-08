using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using Callosotomy.Core;

namespace Callosotomy.Service;

/// <summary>
/// Reads Windows' TCP and UDP tables with the owning process and, for shared svchost.exe
/// processes, the owning service. Only runs when the monitor asks or after a rule change.
/// Identities are cached per process (keyed by PID and start time, so a reused PID is never
/// mistaken for the old process).
/// </summary>
internal sealed partial class ConnectionTable
{
    private const int MaxRows = 2000;
    private readonly DnsMap _dns;
    private readonly Dictionary<(uint Pid, long Started), (AppIdentity Id, string Name)> _processes = new();
    private readonly Dictionary<(uint Pid, ulong Tag), (AppIdentity Id, string Name)> _services = new();
    private readonly Dictionary<string, string> _serviceNames = new(StringComparer.OrdinalIgnoreCase);

    public ConnectionTable(DnsMap dns) => _dns = dns;

    /// <summary>A raw row: enough to identify, show and (for IPv4 TCP) cut a connection.</summary>
    internal readonly record struct Row(
        bool Tcp, bool V6, uint State, IPAddress Local, int LocalPort, IPAddress Remote, int RemotePort,
        uint Pid, ulong ServiceTag, byte[] Raw);

    public ConnectionSnapshot Snapshot(IReadOnlyList<KeyValuePair<NetworkEvents.FlowKey, NetworkEvents.Flow>>? flows = null, bool liveEvents = false)
    {
        lock (_processes)
        {
            var rows = ReadAll();
            flows ??= Array.Empty<KeyValuePair<NetworkEvents.FlowKey, NetworkEvents.Flow>>();
            var flowSockets = flows.Where(f => !f.Key.Tcp).Select(f => (f.Key.Pid, f.Value.LocalPort)).ToHashSet();
            var listeners = rows.Where(r => r.Tcp && r.State == StateListen)
                .Select(r => (r.Pid, r.LocalPort)).ToHashSet();
            var list = new List<ConnectionInfo>();
            foreach (var r in rows)
            {
                if (list.Count >= MaxRows) break;
                if (r.Tcp && r.State is not (StateEstablished or StateSynSent or StateListen)) continue;
                if (IPAddress.IsLoopback(r.Remote) || (r.State == StateListen && IPAddress.IsLoopback(r.Local))) continue;
                if (!r.Tcp && IPAddress.IsLoopback(r.Local)) continue;
                if (!r.Tcp && flowSockets.Contains((r.Pid, r.LocalPort))) continue; // shown with real destinations below
                var (id, name) = Identify(r);
                bool listening = r.Tcp && r.State == StateListen;
                list.Add(new ConnectionInfo
                {
                    Pid = (int)r.Pid,
                    App = id,
                    DisplayName = name,
                    Protocol = r.Tcp ? "TCP" : "UDP",
                    LocalAddress = r.Local.ToString(),
                    LocalPort = r.LocalPort,
                    RemoteAddress = r.Tcp && !listening ? r.Remote.ToString() : "",
                    RemotePort = r.Tcp && !listening ? r.RemotePort : 0,
                    State = !r.Tcp ? "Open" : listening ? "Listening" : "Established",
                    Inbound = listening || (r.Tcp && listeners.Contains((r.Pid, r.LocalPort))),
                    Host = r.Tcp && !listening ? _dns.HostOf(r.Remote) : null,
                });
            }
            MergeFlows(list, rows, flows);
            TrimCaches(rows);
            return new ConnectionSnapshot { Connections = list, Truncated = list.Count >= MaxRows, LiveEvents = liveEvents };
        }
    }

    /// <summary>Adds byte counts to table rows and adds flows the table doesn't have (UDP, short-lived TCP).</summary>
    private void MergeFlows(List<ConnectionInfo> list, List<Row> rows, IReadOnlyList<KeyValuePair<NetworkEvents.FlowKey, NetworkEvents.Flow>> flows)
    {
        if (flows.Count == 0) return;
        var index = new Dictionary<NetworkEvents.FlowKey, int>();
        for (int i = 0; i < list.Count; i++)
        {
            var c = list[i];
            if (c.State == "Established" && IPAddress.TryParse(c.RemoteAddress, out var ip))
                index[new NetworkEvents.FlowKey((uint)c.Pid, true, ip, c.RemotePort)] = i;
        }
        var udpSockets = new Dictionary<(uint, int), Row>();
        foreach (var r in rows.Where(r => !r.Tcp)) udpSockets[(r.Pid, r.LocalPort)] = r;

        var now = DateTime.UtcNow;
        foreach (var (key, flow) in flows.OrderByDescending(f => f.Value.Last))
        {
            int ago = (int)Math.Max(0, (now - flow.Last).TotalSeconds);
            if (index.TryGetValue(key, out int i))
            {
                list[i] = list[i] with { BytesSent = flow.Sent, BytesReceived = flow.Received, SecondsAgo = ago };
                continue;
            }
            if (list.Count >= MaxRows) break;

            (AppIdentity Id, string Name) who = !key.Tcp && udpSockets.TryGetValue((key.Pid, flow.LocalPort), out var sock)
                ? Identify(sock)
                : IdentifyPid(key.Pid);
            list.Add(new ConnectionInfo
            {
                Pid = (int)key.Pid,
                App = who.Id,
                DisplayName = who.Name,
                Protocol = key.Tcp ? "TCP" : "UDP",
                LocalAddress = flow.Local?.ToString() ?? "",
                LocalPort = flow.LocalPort,
                RemoteAddress = key.Remote.ToString(),
                RemotePort = key.RemotePort,
                State = key.Tcp ? "Recent" : "Active",
                Inbound = flow.Inbound,
                Host = _dns.HostOf(key.Remote),
                BytesSent = flow.Sent,
                BytesReceived = flow.Received,
                SecondsAgo = ago,
            });
        }
    }

    private (AppIdentity, string) IdentifyPid(uint pid)
    {
        if (pid is 0 or 4) return (new AppIdentity(AppKind.Program, "System"), "Windows (System)");
        long started = ProcessStart(pid);
        if (!_processes.TryGetValue((pid, started), out var proc))
        {
            proc = IdentifyProcess(pid);
            _processes[(pid, started)] = proc;
        }
        return proc;
    }

    /// <summary>
    /// Cuts established IPv4 TCP connections the policies now block, so switching an app off
    /// takes effect for connections it already had open. Returns how many were cut.
    /// </summary>
    public int DropBlocked(IReadOnlyCollection<AppPolicy> policies, Func<string, IReadOnlyList<IPAddress>> resolve)
    {
        if (policies.Count == 0) return 0;
        var byKey = policies.ToDictionary(p => p.Identity.Key);
        int dropped = 0;
        lock (_processes)
        {
            foreach (var r in ReadAll())
            {
                if (!r.Tcp || r.V6 || r.State != StateEstablished || IPAddress.IsLoopback(r.Remote)) continue;
                var (id, _) = Identify(r);
                if (!byKey.TryGetValue(id.Key, out var policy)) continue;
                var (allowed, _) = AppRuleEngine.Decide(policy, inbound: false, AppRuleEngine.Proto.Tcp, r.RemotePort, r.Remote, _dns.HostOf(r.Remote), resolve);
                var (allowedIn, _) = AppRuleEngine.Decide(policy, inbound: true, AppRuleEngine.Proto.Tcp, r.RemotePort, r.Remote, _dns.HostOf(r.Remote), resolve);
                if (allowed && allowedIn) continue;
                var kill = new MibTcpRow
                {
                    State = StateDeleteTcb,
                    LocalAddr = BinaryPrimitives.ReadUInt32LittleEndian(r.Raw.AsSpan(4)),
                    LocalPort = BinaryPrimitives.ReadUInt32LittleEndian(r.Raw.AsSpan(8)),
                    RemoteAddr = BinaryPrimitives.ReadUInt32LittleEndian(r.Raw.AsSpan(12)),
                    RemotePort = BinaryPrimitives.ReadUInt32LittleEndian(r.Raw.AsSpan(16)),
                };
                if (SetTcpEntry(ref kill) == 0) dropped++;
            }
        }
        return dropped;
    }

    // ---- Identity ----------------------------------------------------------------------

    private (AppIdentity Id, string Name) Identify(Row r)
    {
        if (r.Pid is 0 or 4) return (new AppIdentity(AppKind.Program, "System"), "Windows (System)");

        long started = ProcessStart(r.Pid);
        if (!_processes.TryGetValue((r.Pid, started), out var proc))
        {
            proc = IdentifyProcess(r.Pid);
            _processes[(r.Pid, started)] = proc;
        }

        // svchost.exe hosts many services: ask Windows which one owns this socket.
        if (proc.Id.Kind == AppKind.Program && r.ServiceTag != 0
            && Path.GetFileName(proc.Id.Value).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (!_services.TryGetValue((r.Pid, r.ServiceTag), out var svc))
            {
                string? service = OwningService(r);
                svc = service is null ? proc : (new AppIdentity(AppKind.Service, service), ServiceDisplayName(service));
                _services[(r.Pid, r.ServiceTag)] = svc;
            }
            return svc;
        }
        return proc;
    }

    private static (AppIdentity, string) IdentifyProcess(uint pid)
    {
        IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return (new AppIdentity(AppKind.Program, "System"), $"Protected process {pid}");
        try
        {
            string? path = ImagePath(h);
            string? package = PackageSid(h);
            if (package is not null)
                return (new AppIdentity(AppKind.Package, package), FriendlyName(path) ?? "Store app");
            if (path is null) return (new AppIdentity(AppKind.Program, "System"), $"Process {pid}");
            return (new AppIdentity(AppKind.Program, path), FriendlyName(path) ?? Path.GetFileNameWithoutExtension(path));
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static string? FriendlyName(string? path)
    {
        if (path is null) return null;
        try
        {
            string? d = FileVersionInfo.GetVersionInfo(path).FileDescription?.Trim();
            if (string.IsNullOrEmpty(d)) return null;
            d = new string(d.Where(c => !char.IsControl(c)).Take(AppRuleLimits.MaxDisplayName).ToArray());
            return d.Length > 0 ? d : null;
        }
        catch (Exception ex) when (ex is FileNotFoundException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private string ServiceDisplayName(string service)
    {
        if (_serviceNames.TryGetValue(service, out var cached)) return cached;
        string name;
        try
        {
            using var sc = new ServiceController(service);
            name = sc.DisplayName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            name = service;
        }
        name = new string(name.Where(c => !char.IsControl(c)).Take(AppRuleLimits.MaxDisplayName).ToArray());
        return _serviceNames[service] = name;
    }

    private void TrimCaches(List<Row> rows)
    {
        if (_processes.Count < 4096 && _services.Count < 4096) return;
        var live = rows.Select(r => r.Pid).ToHashSet();
        foreach (var k in _processes.Keys.Where(k => !live.Contains(k.Pid)).ToList()) _processes.Remove(k);
        foreach (var k in _services.Keys.Where(k => !live.Contains(k.Pid)).ToList()) _services.Remove(k);
    }

    private static unsafe string? ImagePath(IntPtr h)
    {
        char* buffer = stackalloc char[1024];
        uint size = 1024;
        return QueryFullProcessImageName(h, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }

    private static unsafe string? PackageSid(IntPtr h)
    {
        uint len = 256;
        char* family = stackalloc char[256];
        if (GetPackageFamilyName(h, ref len, family) != 0 || len <= 1) return null;
        string name = new string(family, 0, (int)len - 1);
        if (DeriveAppContainerSidFromAppContainerName(name, out IntPtr sid) != 0) return null;
        try
        {
            return ConvertSidToStringSid(sid, out IntPtr str) ? Marshal.PtrToStringUni(str) is { } s ? Free(str, s) : null : null;
        }
        finally
        {
            FreeSid(sid);
        }

        static string Free(IntPtr p, string s) { LocalFree(p); return s; }
    }

    private static long ProcessStart(uint pid)
    {
        IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (h == IntPtr.Zero) return 0;
        try { return GetProcessTimes(h, out long created, out _, out _, out _) ? created : 0; }
        finally { CloseHandle(h); }
    }

    private static unsafe string? OwningService(Row r)
    {
        int size = 0;
        fixed (byte* row = r.Raw)
        {
            uint rc = Call(row, IntPtr.Zero, ref size);
            if (rc != ErrorInsufficientBuffer || size <= 0 || size > 65536) return null;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (Call(row, buf, ref size) != 0) return null;
                string? name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf)); // pModuleName = service name
                return name is { Length: > 0 and <= 256 } && AppRuleLimits.ValidateIdentity(new AppIdentity(AppKind.Service, name)) is null ? name : null;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        uint Call(byte* row, IntPtr buffer, ref int sz) => (r.Tcp, r.V6) switch
        {
            (true, false) => GetOwnerModuleFromTcpEntry(row, 0, buffer, ref sz),
            (true, true) => GetOwnerModuleFromTcp6Entry(row, 0, buffer, ref sz),
            (false, false) => GetOwnerModuleFromUdpEntry(row, 0, buffer, ref sz),
            _ => GetOwnerModuleFromUdp6Entry(row, 0, buffer, ref sz),
        };
    }

    // ---- Table reading -----------------------------------------------------------------

    private const uint StateListen = 2, StateSynSent = 3, StateEstablished = 5, StateDeleteTcb = 12;
    private const int AfInet = 2, AfInet6 = 23;
    private const int TcpTableOwnerModuleAll = 8, UdpTableOwnerModule = 2;
    private const uint ErrorInsufficientBuffer = 122;

    // Row layouts (x64): see MIB_TCPROW_OWNER_MODULE, MIB_TCP6ROW_OWNER_MODULE,
    // MIB_UDPROW_OWNER_MODULE and MIB_UDP6ROW_OWNER_MODULE in iphlpapi.
    private static List<Row> ReadAll()
    {
        var rows = new List<Row>();
        Read(tcp: true, v6: false, 160, rows);
        Read(tcp: true, v6: true, 192, rows);
        Read(tcp: false, v6: false, 160, rows);
        Read(tcp: false, v6: true, 176, rows);
        return rows;
    }

    private static void Read(bool tcp, bool v6, int rowSize, List<Row> rows)
    {
        int size = 0;
        int af = v6 ? AfInet6 : AfInet;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            byte[] buf = new byte[Math.Max(size, 4096)];
            int len = buf.Length;
            uint rc = tcp
                ? GetExtendedTcpTable(buf, ref len, false, af, TcpTableOwnerModuleAll, 0)
                : GetExtendedUdpTable(buf, ref len, false, af, UdpTableOwnerModule, 0);
            if (rc == ErrorInsufficientBuffer) { size = len + 4096; continue; }
            if (rc != 0) return;

            int count = BinaryPrimitives.ReadInt32LittleEndian(buf);
            for (int i = 0; i < count; i++)
            {
                int o = 8 + (i * rowSize);
                if (o + rowSize > len) break;
                byte[] raw = buf.AsSpan(o, rowSize).ToArray();
                rows.Add(Parse(tcp, v6, raw));
            }
            return;
        }
    }

    private static Row Parse(bool tcp, bool v6, byte[] b)
    {
        static int Port(byte[] b, int o) => (b[o] << 8) | b[o + 1];
        static uint U32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
        static ulong U64(byte[] b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));

        return (tcp, v6) switch
        {
            (true, false) => new Row(true, false, U32(b, 0), new IPAddress(b.AsSpan(4, 4)), Port(b, 8),
                new IPAddress(b.AsSpan(12, 4)), Port(b, 16), U32(b, 20), U64(b, 32), b),
            (true, true) => new Row(true, true, U32(b, 48), new IPAddress(b.AsSpan(0, 16)), Port(b, 20),
                new IPAddress(b.AsSpan(24, 16)), Port(b, 44), U32(b, 52), U64(b, 64), b),
            (false, false) => new Row(false, false, 0, new IPAddress(b.AsSpan(0, 4)), Port(b, 4),
                IPAddress.Any, 0, U32(b, 8), U64(b, 32), b),
            _ => new Row(false, true, 0, new IPAddress(b.AsSpan(0, 16)), Port(b, 20),
                IPAddress.IPv6Any, 0, U32(b, 24), U64(b, 48), b),
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort;
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(byte[] table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(byte[] table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static unsafe partial uint GetOwnerModuleFromTcpEntry(byte* row, int cls, IntPtr buffer, ref int size);

    [LibraryImport("iphlpapi.dll")]
    private static unsafe partial uint GetOwnerModuleFromTcp6Entry(byte* row, int cls, IntPtr buffer, ref int size);

    [LibraryImport("iphlpapi.dll")]
    private static unsafe partial uint GetOwnerModuleFromUdpEntry(byte* row, int cls, IntPtr buffer, ref int size);

    [LibraryImport("iphlpapi.dll")]
    private static unsafe partial uint GetOwnerModuleFromUdp6Entry(byte* row, int cls, IntPtr buffer, ref int size);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint SetTcpEntry(ref MibTcpRow row);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr h);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(IntPtr process, uint flags, char* buffer, ref uint size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(IntPtr h, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll")]
    private static unsafe partial int GetPackageFamilyName(IntPtr process, ref uint length, char* name);

    [LibraryImport("userenv.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);

    [LibraryImport("advapi32.dll")]
    private static partial IntPtr FreeSid(IntPtr sid);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr LocalFree(IntPtr p);
}
