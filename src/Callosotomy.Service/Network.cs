using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Callosotomy.Core;

namespace Callosotomy.Service;

internal static partial class Network
{
    /// <summary>Gateways, DNS and DHCP servers of every connected adapter.</summary>
    public static IReadOnlyList<IPAddress> Infrastructure()
    {
        var result = new HashSet<IPAddress>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;
            var props = nic.GetIPProperties();
            foreach (var g in props.GatewayAddresses) result.Add(Strip(g.Address));
            foreach (var d in props.DnsAddresses) result.Add(Strip(d));
            foreach (var d in props.DhcpServerAddresses) result.Add(Strip(d));
        }
        result.RemoveWhere(a => a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any));
        return result.ToList();
    }

    private static IPAddress Strip(IPAddress a) =>
        a.AddressFamily == AddressFamily.InterNetworkV6 && a.ScopeId != 0 ? new IPAddress(a.GetAddressBytes()) : a;

    /// <summary>
    /// Cuts established IPv4 TCP connections the new mode blocks. Firewall rules stop new
    /// connections; this makes sure an attacker's already-open session dies too.
    /// Windows offers no equivalent API for IPv6 or UDP; those flows hit the new rules on their next packet.
    /// </summary>
    public static int DropConnections(IsolationMode mode, IReadOnlyList<IPAddress> infrastructure)
    {
        if (mode == IsolationMode.None) return 0;
        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint rc = GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
                if (rc == ErrorInsufficientBuffer) continue;
                if (rc != 0) return 0;

                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                int dropped = 0;
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buffer + 4 + (i * rowSize));
                    if (row.State != StateEstablished) continue;
                    var remote = new IPAddress(row.RemoteAddr);
                    if (!FirewallPlan.ShouldDrop(mode, remote, infrastructure)) continue;

                    var kill = new MibTcpRow
                    {
                        State = StateDeleteTcb,
                        LocalAddr = row.LocalAddr,
                        LocalPort = row.LocalPort,
                        RemoteAddr = row.RemoteAddr,
                        RemotePort = row.RemotePort,
                    };
                    if (SetTcpEntry(ref kill) == 0) dropped++;
                }
                return dropped;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return 0;
    }

    /// <summary>
    /// True when a TCP connection to the probe endpoint succeeds, i.e. the block is not holding.
    /// Sends no data; the connection is closed immediately.
    /// </summary>
    public static async Task<bool> ProbeLeaksAsync(IPEndPoint target, CancellationToken ct)
    {
        using var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(1500));
        try
        {
            await socket.ConnectAsync(target, timeout.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint StateEstablished = 5;
    private const uint StateDeleteTcb = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint SetTcpEntry(ref MibTcpRow row);
}
