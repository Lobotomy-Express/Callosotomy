using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Callosotomy.Core;

/// <summary>
/// Evaluates app rules (most specific match wins, ties go to Block) and compiles them into
/// Windows Firewall rules.
///
/// Windows Firewall has no precedence between rules: any matching block rule wins. So the
/// compiler splits the space of (protocol, port, address) into cells at every rule boundary,
/// decides each cell with the same evaluator the UI uses, and emits block rules covering exactly
/// the blocked cells. It only ever emits block rules, so an app rule can never open something
/// Windows itself (or the kill switch) blocks.
/// </summary>
public static class AppRuleEngine
{
    public const string RulePrefix = "Callosotomy:App:";
    private const int MaxAddressesPerRule = 500;

    /// <summary>True for firewall rules created from app policies.</summary>
    public static bool IsAppRule(string? name) =>
        name is not null && name.StartsWith(RulePrefix, StringComparison.Ordinal);

    /// <summary>Short stable tag for an identity, used in rule names.</summary>
    public static string Tag(AppIdentity id)
    {
        ArgumentNullException.ThrowIfNull(id);
        byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(id.Key));
        return Convert.ToHexString(h, 0, 6);
    }

    // ---- Evaluation -------------------------------------------------------------------

    /// <summary>Which protocol a cell or connection uses. Other covers ICMP.</summary>
    public enum Proto { Tcp, Udp, Other }

    /// <summary>
    /// Decides one connection. <paramref name="host"/> (if known) matches domain rules by name;
    /// <paramref name="resolve"/> (if given) matches them by the domain's known addresses.
    /// Returns the deciding rule, or null when the app default applied.
    /// </summary>
    public static (bool Allowed, AppRule? Rule) Decide(
        AppPolicy policy, bool inbound, Proto proto, int port, IPAddress address, string? host = null,
        Func<string, IReadOnlyList<IPAddress>>? resolve = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(address);
        AppRule? best = null;
        int bestScore = -1;
        foreach (var r in policy.Rules)
        {
            if (!r.Enabled || !DirectionMatches(r, inbound) || !ProtocolMatches(r, proto) || !PortMatches(r, proto, port)) continue;
            bool hit = r.Destination switch
            {
                DestinationKind.Domain => AppRuleLimits.TryNormalizeDomain(r.Value, out var d)
                    && (AppRuleLimits.DomainMatches(d, host)
                        || (resolve is not null && resolve(d).Any(a => a.Equals(address)))),
                _ => AddressSet(r, resolve).Any(x => x.Contains(address)),
            };
            if (!hit) continue;
            int score = Specificity(r);
            if (score > bestScore || (score == bestScore && r.Action == RuleAction.Block))
            {
                best = r;
                bestScore = score;
            }
        }
        return best is null ? (policy.AllowByDefault, null) : (best.Action == RuleAction.Allow, best);
    }

    /// <summary>Destination detail counts most, then a port, then a protocol.</summary>
    public static int Specificity(AppRule r)
    {
        ArgumentNullException.ThrowIfNull(r);
        int dest = r.Destination switch
        {
            DestinationKind.Address => 4,
            DestinationKind.Domain => 3,
            DestinationKind.Internet or DestinationKind.LocalNetwork => 1,
            _ => 0,
        };
        return (dest * 4) + (AppRuleLimits.IsAnyPort(r.Ports) ? 0 : 2) + (r.Protocol == TrafficProtocol.Any ? 0 : 1);
    }

    private static bool DirectionMatches(AppRule r, bool inbound) =>
        r.Direction == TrafficDirection.Both || (r.Direction == TrafficDirection.Inbound) == inbound;

    private static bool ProtocolMatches(AppRule r, Proto p) => r.Protocol switch
    {
        TrafficProtocol.Tcp => p == Proto.Tcp,
        TrafficProtocol.Udp => p == Proto.Udp,
        _ => true,
    };

    private static bool PortMatches(AppRule r, Proto p, int port)
    {
        if (AppRuleLimits.IsAnyPort(r.Ports)) return true;
        if (p == Proto.Other) return false;
        return AppRuleLimits.TryParsePorts(r.Ports, out var ranges) && ranges.Any(x => port >= x.Lo && port <= x.Hi);
    }

    private static readonly IReadOnlyList<IpRange> Everything = new[] { IpRange.AllV4, IpRange.AllV6 };
    private static readonly IReadOnlyList<IpRange> LocalNetwork =
        IpRangeSet.Normalize(FirewallPlan.LocalUnicast.Concat(FirewallPlan.LocalMulticast));

    private static IReadOnlyList<IpRange> AddressSet(AppRule r, Func<string, IReadOnlyList<IPAddress>>? resolve) => r.Destination switch
    {
        DestinationKind.Anywhere => Everything,
        DestinationKind.Internet => FirewallPlan.Internet,
        DestinationKind.LocalNetwork => LocalNetwork,
        DestinationKind.Address => AppRuleLimits.TryParseAddresses(r.Value, out var a) ? a : Array.Empty<IpRange>(),
        DestinationKind.Domain => AppRuleLimits.TryNormalizeDomain(r.Value, out var d) && resolve is not null
            ? IpRangeSet.Normalize(resolve(d).Select(IpRange.FromAddress))
            : Array.Empty<IpRange>(),
        _ => Array.Empty<IpRange>(),
    };

    // ---- Compilation ------------------------------------------------------------------

    /// <summary>Compiles a policy into firewall block rules for both directions.</summary>
    public static IReadOnlyList<RuleSpec> Compile(AppPolicy policy, Func<string, IReadOnlyList<IPAddress>>? resolve = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var specs = new List<RuleSpec>();
        string tag = Tag(policy.Identity);
        CompileDirection(policy, inbound: false, tag, resolve, specs);
        CompileDirection(policy, inbound: true, tag, resolve, specs);
        return specs;
    }

    private static void CompileDirection(AppPolicy policy, bool inbound, string tag,
        Func<string, IReadOnlyList<IPAddress>>? resolve, List<RuleSpec> specs)
    {
        var rules = policy.Rules.Where(r => r.Enabled && DirectionMatches(r, inbound)).ToList();
        var dir = inbound ? RuleDirection.Inbound : RuleDirection.Outbound;
        string prefix = $"{RulePrefix}{tag}:{(inbound ? "In" : "Out")}:";
        int n = 0;
        RuleSpec Make(RuleProtocol p, string addresses, string? ports) =>
            WithIdentity(new RuleSpec(prefix + (n++).ToString(System.Globalization.CultureInfo.InvariantCulture), dir, p, addresses, ports), policy.Identity);

        // Inbound traffic Windows already blocks needs no extra rules; we only add blocks.
        if (rules.Count == 0)
        {
            if (!policy.AllowByDefault) specs.Add(Make(RuleProtocol.Any, "*", null));
            return;
        }

        var sets = rules.ToDictionary(r => r, r => AddressSet(r, resolve));
        var addrCells = Partition(sets.Values);
        var portCells = PartitionPorts(rules);

        // Decide every cell.
        List<IpRange> DecideAddrs(Proto proto, int port) =>
            IpRangeSet.Normalize(addrCells.Where(cell => !DecideCell(policy, rules, sets, proto, port, cell)));

        var tcp = portCells.Select(pc => (pc, blocked: DecideAddrs(Proto.Tcp, pc.Lo))).ToList();
        var udp = portCells.Select(pc => (pc, blocked: DecideAddrs(Proto.Udp, pc.Lo))).ToList();
        var other = DecideAddrs(Proto.Other, 0);

        // Fast path: identical blocking across every port and protocol becomes one Any-protocol rule.
        string otherKey = Key(other);
        if (tcp.Concat(udp).All(x => Key(x.blocked) == otherKey))
        {
            foreach (var chunk in Chunk(other)) specs.Add(Make(RuleProtocol.Any, chunk, null));
            return;
        }

        foreach (var (proto, cells) in new[] { (RuleProtocol.Tcp, tcp), (RuleProtocol.Udp, udp) })
        {
            // Group port segments that block the same addresses into one rule.
            foreach (var group in cells.Where(c => c.blocked.Count > 0).GroupBy(c => Key(c.blocked)))
            {
                var ports = MergePorts(group.Select(g => g.pc));
                string? portText = ports.Count == 1 && ports[0] == (1, 65535) ? null : string.Join(',', ports.Select(FormatPort));
                foreach (var chunk in Chunk(group.First().blocked)) specs.Add(Make(proto, chunk, portText));
            }
        }

        var v4 = other.Where(r => !r.IsV6).ToList();
        var v6 = other.Where(r => r.IsV6).ToList();
        foreach (var chunk in Chunk(v4)) specs.Add(Make(RuleProtocol.Icmp4, chunk, null));
        foreach (var chunk in Chunk(v6)) specs.Add(Make(RuleProtocol.Icmp6, chunk, null));
    }

    private static bool DecideCell(AppPolicy policy, List<AppRule> rules, Dictionary<AppRule, IReadOnlyList<IpRange>> sets,
        Proto proto, int port, IpRange cell)
    {
        AppRule? best = null;
        int bestScore = -1;
        foreach (var r in rules)
        {
            if (!ProtocolMatches(r, proto) || !PortMatches(r, proto, port)) continue;
            if (!sets[r].Any(s => s.IsV6 == cell.IsV6 && s.Start <= cell.Start && s.End >= cell.Start)) continue;
            int score = Specificity(r);
            if (score > bestScore || (score == bestScore && r.Action == RuleAction.Block)) { best = r; bestScore = score; }
        }
        return best is null ? policy.AllowByDefault : best.Action == RuleAction.Allow;
    }

    /// <summary>Splits all of IPv4 and IPv6 into segments at every boundary of the given sets.</summary>
    private static List<IpRange> Partition(IEnumerable<IReadOnlyList<IpRange>> sets)
    {
        var result = new List<IpRange>();
        foreach (bool v6 in new[] { false, true })
        {
            UInt128 max = v6 ? IpRange.MaxV6 : IpRange.MaxV4;
            var cuts = new SortedSet<UInt128> { 0 };
            foreach (var r in sets.SelectMany(s => s).Where(r => r.IsV6 == v6))
            {
                cuts.Add(r.Start);
                if (r.End < max) cuts.Add(r.End + 1);
            }
            var list = cuts.ToList();
            for (int i = 0; i < list.Count; i++)
                result.Add(new IpRange(v6, list[i], i + 1 < list.Count ? list[i + 1] - 1 : max));
        }
        return result;
    }

    private static List<(int Lo, int Hi)> PartitionPorts(List<AppRule> rules)
    {
        var cuts = new SortedSet<int> { 1 };
        foreach (var r in rules.Where(r => !AppRuleLimits.IsAnyPort(r.Ports)))
        {
            if (!AppRuleLimits.TryParsePorts(r.Ports, out var ranges)) continue;
            foreach (var (lo, hi) in ranges)
            {
                cuts.Add(lo);
                if (hi < 65535) cuts.Add(hi + 1);
            }
        }
        var list = cuts.ToList();
        return list.Select((c, i) => (c, i + 1 < list.Count ? list[i + 1] - 1 : 65535)).ToList();
    }

    private static List<(int Lo, int Hi)> MergePorts(IEnumerable<(int Lo, int Hi)> segs)
    {
        var merged = new List<(int Lo, int Hi)>();
        foreach (var s in segs.OrderBy(s => s.Lo))
        {
            if (merged.Count > 0 && merged[^1].Hi + 1 >= s.Lo) merged[^1] = (merged[^1].Lo, Math.Max(merged[^1].Hi, s.Hi));
            else merged.Add(s);
        }
        return merged;
    }

    private static string FormatPort((int Lo, int Hi) p) =>
        p.Lo == p.Hi ? p.Lo.ToString(System.Globalization.CultureInfo.InvariantCulture)
                     : string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{p.Lo}-{p.Hi}");

    private static string Key(List<IpRange> ranges) => string.Join(',', ranges);

    /// <summary>Address lists as firewall strings, "*" for everything, split to stay under per-rule limits.</summary>
    private static IEnumerable<string> Chunk(List<IpRange> ranges)
    {
        if (ranges.Count == 0) yield break;
        if (IpRangeSet.SameCoverage(ranges, Everything)) { yield return "*"; yield break; }
        for (int i = 0; i < ranges.Count; i += MaxAddressesPerRule)
            yield return string.Join(',', ranges.Skip(i).Take(MaxAddressesPerRule));
    }

    private static RuleSpec WithIdentity(RuleSpec s, AppIdentity id) => id.Kind switch
    {
        AppKind.Program => s with { Program = id.Value },
        AppKind.Service => s with { Service = id.Value },
        _ => s with { PackageSid = id.Value },
    };

    // ---- Permission check ---------------------------------------------------------------

    /// <summary>
    /// True when <paramref name="next"/> allows something <paramref name="previous"/> blocked.
    /// Used where users may tighten but not loosen. Exact: both policies are evaluated on the
    /// combined cell partition.
    /// </summary>
    public static bool Loosens(AppPolicy? previous, AppPolicy next, Func<string, IReadOnlyList<IPAddress>>? resolve = null)
    {
        ArgumentNullException.ThrowIfNull(next);
        if (previous is null) return false; // no policy before means everything was allowed
        foreach (bool inbound in new[] { false, true })
        {
            var a = previous.Rules.Where(r => r.Enabled && DirectionMatches(r, inbound)).ToList();
            var b = next.Rules.Where(r => r.Enabled && DirectionMatches(r, inbound)).ToList();
            var sa = a.ToDictionary(r => r, r => AddressSet(r, resolve));
            var sb = b.ToDictionary(r => r, r => AddressSet(r, resolve));
            var cells = Partition(sa.Values.Concat(sb.Values));
            var ports = PartitionPorts(a.Concat(b).ToList());
            foreach (var proto in new[] { Proto.Tcp, Proto.Udp, Proto.Other })
                foreach (var pc in proto == Proto.Other ? new List<(int, int)> { (0, 0) } : ports)
                    foreach (var cell in cells)
                        if (!DecideCell(previous, a, sa, proto, pc.Item1, cell) && DecideCell(next, b, sb, proto, pc.Item1, cell))
                            return true;
        }
        return false;
    }
}
