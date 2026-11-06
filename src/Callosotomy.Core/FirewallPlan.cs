using System.Net;

namespace Callosotomy.Core;

public enum RuleDirection { Inbound = 1, Outbound = 2 }

public enum RuleProtocol { Any = 256, Tcp = 6, Udp = 17 }

/// <summary>One block rule, in the shape the Windows Firewall API expects.</summary>
public sealed record RuleSpec(
    string Name,
    RuleDirection Direction,
    RuleProtocol Protocol,
    string RemoteAddresses,
    string? RemotePorts);

/// <summary>
/// Turns an <see cref="IsolationMode"/> into concrete block rules. Pure and deterministic,
/// so it is unit-tested on any OS.
/// </summary>
public static class FirewallPlan
{
    public const string RulePrefix = "Callosotomy";
    public const string RuleGroup = "Callosotomy";

    /// <summary>Unicast addresses that belong to the local network.</summary>
    internal static readonly IReadOnlyList<IpRange> LocalUnicast = IpRangeSet.Parse(
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "fc00::/7", "fe80::/10");

    /// <summary>Multicast and broadcast: link-local chatter and discovery protocols.</summary>
    internal static readonly IReadOnlyList<IpRange> LocalMulticast = IpRangeSet.Parse(
        "224.0.0.0/4", "255.255.255.255", "ff00::/8");

    /// <summary>Never touched: loopback and the unspecified/"this network" block.</summary>
    internal static readonly IReadOnlyList<IpRange> NeverBlock = IpRangeSet.Parse(
        "0.0.0.0/8", "127.0.0.0/8", "::/128", "::1");

    /// <summary>Every IPv4 address that is not local, multicast or loopback, plus global IPv6.</summary>
    internal static readonly IReadOnlyList<IpRange> Internet = BuildInternet();

    /// <summary>DNS and DNS-over-TLS. Blocked to every address in Internet mode to close DNS tunnelling via the router.</summary>
    internal const string DnsPorts = "53,853";

    /// <summary>All UDP ports except DHCP (67-68) and DHCPv6 (546-547), so the PC keeps its address in Local mode.</summary>
    internal const string UdpPortsExceptDhcp = "1-66,69-545,548-65535";

    private static List<IpRange> BuildInternet()
    {
        var v4 = IpRangeSet.Subtract(
            new[] { IpRange.AllV4 },
            LocalUnicast.Concat(LocalMulticast).Concat(NeverBlock));
        v4.Add(IpRange.Parse("2000::/3"));
        return IpRangeSet.Normalize(v4);
    }

    /// <summary>
    /// Builds the rules for a mode.
    /// </summary>
    /// <param name="mode">The mode to enforce.</param>
    /// <param name="infrastructure">
    /// Gateways, DNS and DHCP servers. Only used by <see cref="IsolationMode.Local"/>,
    /// where they stay reachable so the internet keeps working.
    /// </param>
    public static IReadOnlyList<RuleSpec> Build(IsolationMode mode, IEnumerable<IPAddress>? infrastructure = null)
    {
        var rules = new List<RuleSpec>();
        switch (mode)
        {
            case IsolationMode.None:
                break;

            case IsolationMode.Internet:
            {
                string internet = Join(Internet);
                AddBoth(rules, "Internet", RuleProtocol.Any, internet, null);
                rules.Add(new($"{RulePrefix}:Internet:DNS-TCP", RuleDirection.Outbound, RuleProtocol.Tcp, "*", DnsPorts));
                rules.Add(new($"{RulePrefix}:Internet:DNS-UDP", RuleDirection.Outbound, RuleProtocol.Udp, "*", DnsPorts));
                break;
            }

            case IsolationMode.Local:
            {
                var keep = (infrastructure ?? Array.Empty<IPAddress>())
                    .Where(a => !IPAddress.IsLoopback(a))
                    .Select(IpRange.FromAddress);
                var unicast = IpRangeSet.Subtract(LocalUnicast, keep);
                if (unicast.Count > 0)
                {
                    string u = Join(unicast);
                    // ICMP is left alone so IPv6 neighbour discovery to the gateway keeps working.
                    AddBoth(rules, "Local:TCP", RuleProtocol.Tcp, u, null);
                    AddBoth(rules, "Local:UDP", RuleProtocol.Udp, u, null);
                }
                AddBoth(rules, "Local:Multicast", RuleProtocol.Udp, Join(LocalMulticast), UdpPortsExceptDhcp);
                break;
            }

            case IsolationMode.All:
                AddBoth(rules, "All", RuleProtocol.Any, "*", null);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
        }
        return rules;
    }

    /// <summary>Every rule name this tool could ever create, for clean removal.</summary>
    public static bool IsOurs(string? ruleName) =>
        ruleName is not null && ruleName.StartsWith(RulePrefix + ":", StringComparison.Ordinal);

    /// <summary>True when an established connection to <paramref name="remote"/> should be cut for this mode.</summary>
    public static bool ShouldDrop(IsolationMode mode, IPAddress remote, IEnumerable<IPAddress>? infrastructure = null)
    {
        if (IPAddress.IsLoopback(remote)) return false;
        return mode switch
        {
            IsolationMode.All => true,
            IsolationMode.Internet => Internet.Any(r => r.Contains(remote)),
            IsolationMode.Local => LocalUnicast.Any(r => r.Contains(remote))
                && !(infrastructure ?? Array.Empty<IPAddress>()).Any(i => i.Equals(remote)),
            _ => false,
        };
    }

    private static void AddBoth(List<RuleSpec> rules, string label, RuleProtocol protocol, string addresses, string? ports)
    {
        rules.Add(new($"{RulePrefix}:{label}:Out", RuleDirection.Outbound, protocol, addresses, ports));
        rules.Add(new($"{RulePrefix}:{label}:In", RuleDirection.Inbound, protocol, addresses, ports));
    }

    private static string Join(IEnumerable<IpRange> ranges) => string.Join(',', ranges);
}
