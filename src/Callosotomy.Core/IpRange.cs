using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Callosotomy.Core;

/// <summary>
/// An inclusive range of IPv4 or IPv6 addresses. IPv4 values live in the low 32 bits.
/// </summary>
public readonly record struct IpRange(bool IsV6, UInt128 Start, UInt128 End) : IComparable<IpRange>
{
    public static readonly UInt128 MaxV4 = uint.MaxValue;
    public static readonly UInt128 MaxV6 = UInt128.MaxValue;

    public static IpRange AllV4 => new(false, 0, MaxV4);
    public static IpRange AllV6 => new(true, 0, MaxV6);

    /// <summary>Parses "a.b.c.d", "a.b.c.d/n", "a-b", or the IPv6 equivalents.</summary>
    public static IpRange Parse(string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        text = text.Trim();

        int dash = text.IndexOf('-', StringComparison.Ordinal);
        if (dash > 0)
        {
            var (v6a, a) = ToValue(IPAddress.Parse(text[..dash]));
            var (v6b, b) = ToValue(IPAddress.Parse(text[(dash + 1)..]));
            if (v6a != v6b) throw new FormatException("Range mixes IPv4 and IPv6.");
            if (a > b) throw new FormatException("Range start is after its end.");
            return new IpRange(v6a, a, b);
        }

        int slash = text.IndexOf('/', StringComparison.Ordinal);
        if (slash > 0)
        {
            var (v6, value) = ToValue(IPAddress.Parse(text[..slash]));
            int bits = v6 ? 128 : 32;
            int prefix = int.Parse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture);
            if (prefix < 0 || prefix > bits) throw new FormatException("Prefix length out of range.");
            UInt128 hostMask = prefix == bits ? 0 : (prefix == 0 ? (v6 ? MaxV6 : MaxV4) : (((UInt128)1 << (bits - prefix)) - 1));
            UInt128 start = value & ~hostMask & (v6 ? MaxV6 : MaxV4);
            return new IpRange(v6, start, start | hostMask);
        }

        var (isV6, single) = ToValue(IPAddress.Parse(text));
        return new IpRange(isV6, single, single);
    }

    public static IpRange FromAddress(IPAddress address)
    {
        var (v6, value) = ToValue(address);
        return new IpRange(v6, value, value);
    }

    public bool Contains(IPAddress address)
    {
        var (v6, value) = ToValue(address);
        return v6 == IsV6 && value >= Start && value <= End;
    }

    /// <summary>Firewall-API syntax: a single address or "start-end".</summary>
    public override string ToString() =>
        Start == End ? Format(Start) : $"{Format(Start)}-{Format(End)}";

    public int CompareTo(IpRange other)
    {
        int c = IsV6.CompareTo(other.IsV6);
        return c != 0 ? c : Start.CompareTo(other.Start);
    }

    public static bool operator <(IpRange left, IpRange right) => left.CompareTo(right) < 0;
    public static bool operator <=(IpRange left, IpRange right) => left.CompareTo(right) <= 0;
    public static bool operator >(IpRange left, IpRange right) => left.CompareTo(right) > 0;
    public static bool operator >=(IpRange left, IpRange right) => left.CompareTo(right) >= 0;

    private string Format(UInt128 value)
    {
        if (!IsV6) return new IPAddress(BinaryPrimitives.ReverseEndianness((uint)value)).ToString();
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(bytes, value);
        return new IPAddress(bytes).ToString();
    }

    internal static (bool IsV6, UInt128 Value) ToValue(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> b4 = stackalloc byte[4];
            address.TryWriteBytes(b4, out _);
            return (false, BinaryPrimitives.ReadUInt32BigEndian(b4));
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Span<byte> b16 = stackalloc byte[16];
            address.TryWriteBytes(b16, out _);
            return (true, BinaryPrimitives.ReadUInt128BigEndian(b16));
        }
        throw new ArgumentException("Only IPv4 and IPv6 addresses are supported.", nameof(address));
    }
}

/// <summary>Set operations over sorted, merged range lists.</summary>
public static class IpRangeSet
{
    /// <summary>Sorts and merges overlapping or adjacent ranges.</summary>
    public static List<IpRange> Normalize(IEnumerable<IpRange> ranges)
    {
        var sorted = ranges.ToList();
        sorted.Sort();
        var result = new List<IpRange>(sorted.Count);
        foreach (var r in sorted)
        {
            if (result.Count > 0)
            {
                var last = result[^1];
                if (last.IsV6 == r.IsV6 && (last.End == (last.IsV6 ? IpRange.MaxV6 : IpRange.MaxV4) || r.Start <= last.End + 1))
                {
                    if (r.End > last.End) result[^1] = last with { End = r.End };
                    continue;
                }
            }
            result.Add(r);
        }
        return result;
    }

    /// <summary>Everything in <paramref name="from"/> that is not in <paramref name="remove"/>.</summary>
    public static List<IpRange> Subtract(IEnumerable<IpRange> from, IEnumerable<IpRange> remove)
    {
        var a = Normalize(from);
        var b = Normalize(remove);
        var result = new List<IpRange>(a.Count + b.Count);
        foreach (var range in a)
        {
            UInt128 cursor = range.Start;
            bool exhausted = false;
            foreach (var cut in b)
            {
                if (cut.IsV6 != range.IsV6 || cut.End < cursor) continue;
                if (cut.Start > range.End) break;
                if (cut.Start > cursor) result.Add(range with { Start = cursor, End = cut.Start - 1 });
                if (cut.End >= range.End) { exhausted = true; break; }
                cursor = cut.End + 1;
            }
            if (!exhausted) result.Add(range with { Start = cursor });
        }
        return result;
    }

    public static List<IpRange> Parse(params string[] items) => Normalize(items.Select(IpRange.Parse));
}
