using System.Net;
using System.Runtime.InteropServices;
using Callosotomy.Core;

namespace Callosotomy.Service;

/// <summary>
/// Learns which addresses belong to which host names by reading Windows' own DNS cache.
/// It never sends a DNS query: every lookup uses DNS_QUERY_NO_WIRE_QUERY, which answers from the
/// cache only, so nothing leaks to the network and no time is spent waiting for servers.
/// Addresses are remembered for a day after they were last seen, so a rule keeps working while
/// apps reuse an address they resolved earlier.
/// </summary>
internal sealed partial class DnsMap
{
    private const int MaxEntries = 20000;
    private static readonly TimeSpan Retention = TimeSpan.FromHours(24);

    private readonly object _lock = new();
    private readonly Dictionary<IPAddress, (string Host, DateTime Seen)> _byAddress = new();
    private DateTime _lastRefresh;

    /// <summary>Re-reads the cache, at most once every <paramref name="minInterval"/>. Returns true if anything new was learned.</summary>
    public bool Refresh(TimeSpan minInterval)
    {
        lock (_lock)
        {
            if (DateTime.UtcNow - _lastRefresh < minInterval) return false;
            _lastRefresh = DateTime.UtcNow;
        }

        var found = new List<(IPAddress, string)>();
        foreach (string name in CachedNames())
        {
            foreach (var addr in CachedAddresses(name)) found.Add((addr, name));
        }

        bool changed = false;
        var now = DateTime.UtcNow;
        lock (_lock)
        {
            foreach (var (addr, name) in found)
            {
                if (!_byAddress.TryGetValue(addr, out var old) || old.Host != name) changed = true;
                _byAddress[addr] = (name, now);
            }
            foreach (var stale in _byAddress.Where(kv => now - kv.Value.Seen > Retention).Select(kv => kv.Key).ToList())
                _byAddress.Remove(stale);
            if (_byAddress.Count > MaxEntries)
            {
                foreach (var old in _byAddress.OrderBy(kv => kv.Value.Seen).Take(_byAddress.Count - MaxEntries).Select(kv => kv.Key).ToList())
                    _byAddress.Remove(old);
            }
        }
        return changed;
    }

    public string? HostOf(IPAddress address)
    {
        lock (_lock) return _byAddress.TryGetValue(address, out var v) ? v.Host : null;
    }

    /// <summary>Every known address whose host name matches a domain pattern.</summary>
    public IReadOnlyList<IPAddress> Resolve(string pattern)
    {
        lock (_lock)
            return _byAddress.Where(kv => AppRuleLimits.DomainMatches(pattern, kv.Value.Host)).Select(kv => kv.Key).ToList();
    }

    // ---- Windows DNS cache -------------------------------------------------------------

    private const uint DnsQueryNoWireQuery = 0x10;
    private const ushort TypeA = 1, TypeAaaa = 28;

    private static List<string> CachedNames()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!DnsGetCacheDataTable(out IntPtr entry)) return names.ToList();
            while (entry != IntPtr.Zero)
            {
                IntPtr next = Marshal.ReadIntPtr(entry);
                IntPtr namePtr = Marshal.ReadIntPtr(entry, IntPtr.Size);
                string? name = Marshal.PtrToStringUni(namePtr);
                if (name is { Length: > 0 and <= 253 } && names.Count < 5000) names.Add(name.TrimEnd('.'));
                DnsFree(namePtr, 0);
                DnsFree(entry, 0);
                entry = next;
            }
        }
        catch (EntryPointNotFoundException)
        {
            // Older or future Windows without this export: domain names are simply not shown.
        }
        return names.ToList();
    }

    private static List<IPAddress> CachedAddresses(string name)
    {
        var result = new List<IPAddress>();
        foreach (ushort type in new[] { TypeA, TypeAaaa })
        {
            if (DnsQuery(name, type, DnsQueryNoWireQuery, IntPtr.Zero, out IntPtr records, IntPtr.Zero) != 0 || records == IntPtr.Zero)
                continue;
            try
            {
                // DNS_RECORD: pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved, then the data union.
                int dataOffset = (2 * IntPtr.Size) + 16;
                for (IntPtr r = records; r != IntPtr.Zero; r = Marshal.ReadIntPtr(r))
                {
                    ushort t = (ushort)Marshal.ReadInt16(r, 2 * IntPtr.Size);
                    if (t == TypeA)
                    {
                        byte[] b = new byte[4];
                        Marshal.Copy(r + dataOffset, b, 0, 4);
                        result.Add(new IPAddress(b));
                    }
                    else if (t == TypeAaaa)
                    {
                        byte[] b = new byte[16];
                        Marshal.Copy(r + dataOffset, b, 0, 16);
                        result.Add(new IPAddress(b));
                    }
                }
            }
            finally
            {
                DnsRecordListFree(records, 1);
            }
        }
        return result;
    }

    [LibraryImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DnsGetCacheDataTable(out IntPtr table);

    [LibraryImport("dnsapi.dll", EntryPoint = "DnsQuery_W", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [LibraryImport("dnsapi.dll")]
    private static partial void DnsRecordListFree(IntPtr list, int freeType);

    [LibraryImport("dnsapi.dll")]
    private static partial void DnsFree(IntPtr data, int freeType);
}
