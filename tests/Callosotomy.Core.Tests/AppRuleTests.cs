using System.Net;
using Callosotomy.Core;
using Xunit;

namespace Callosotomy.Core.Tests;

public class AppRuleTests
{
    private static readonly AppIdentity Spotify = new(AppKind.Program, @"C:\Users\me\AppData\Roaming\Spotify\Spotify.exe");

    private static readonly Dictionary<string, IReadOnlyList<IPAddress>> Dns = new()
    {
        ["spotify.com"] = new[] { IPAddress.Parse("35.186.224.24"), IPAddress.Parse("2600:1901::1") },
        ["doubleclick.net"] = new[] { IPAddress.Parse("172.217.4.98") },
    };

    private static IReadOnlyList<IPAddress> Resolve(string d) =>
        Dns.TryGetValue(d, out var v) ? v : Array.Empty<IPAddress>();

    private static AppPolicy SpotifyPolicy() => new()
    {
        Identity = Spotify,
        AllowByDefault = false,
        Rules = new[]
        {
            new AppRule { Action = RuleAction.Allow, Protocol = TrafficProtocol.Tcp, Ports = "443", Destination = DestinationKind.Domain, Value = "spotify.com" },
            new AppRule { Action = RuleAction.Allow, Protocol = TrafficProtocol.Tcp, Ports = "8009", Destination = DestinationKind.LocalNetwork },
            new AppRule { Action = RuleAction.Block, Destination = DestinationKind.Domain, Value = "doubleclick.net" },
        },
    };

    [Theory]
    [InlineData("35.186.224.24", 443, true)]   // allowed domain, allowed port
    [InlineData("35.186.224.24", 80, false)]   // allowed domain, other port
    [InlineData("192.168.1.42", 8009, true)]   // casting on the local network
    [InlineData("192.168.1.42", 22, false)]
    [InlineData("8.8.8.8", 443, false)]        // default block
    [InlineData("172.217.4.98", 443, false)]
    public void Decide_follows_most_specific_rule(string ip, int port, bool allowed) =>
        Assert.Equal(allowed, AppRuleEngine.Decide(SpotifyPolicy(), false, AppRuleEngine.Proto.Tcp, port, IPAddress.Parse(ip), null, Resolve).Allowed);

    [Fact]
    public void Decide_matches_domains_by_name_too() =>
        Assert.True(AppRuleEngine.Decide(SpotifyPolicy(), false, AppRuleEngine.Proto.Tcp, 443, IPAddress.Parse("9.9.9.9"), "spclient.wg.spotify.com").Allowed);

    [Fact]
    public void Ties_go_to_block()
    {
        var p = new AppPolicy
        {
            Identity = Spotify,
            Rules = new[]
            {
                new AppRule { Action = RuleAction.Allow, Destination = DestinationKind.Internet },
                new AppRule { Action = RuleAction.Block, Destination = DestinationKind.Internet },
            },
        };
        Assert.False(AppRuleEngine.Decide(p, false, AppRuleEngine.Proto.Tcp, 443, IPAddress.Parse("8.8.8.8")).Allowed);
    }

    [Fact]
    public void Default_block_with_no_rules_is_one_rule_per_direction()
    {
        var specs = AppRuleEngine.Compile(new AppPolicy { Identity = Spotify, AllowByDefault = false });
        Assert.Equal(2, specs.Count);
        Assert.All(specs, s => Assert.Equal("*", s.RemoteAddresses));
        Assert.All(specs, s => Assert.Equal(Spotify.Value, s.Program));
    }

    [Fact]
    public void Default_allow_with_no_rules_emits_nothing() =>
        Assert.Empty(AppRuleEngine.Compile(new AppPolicy { Identity = Spotify }));

    [Fact]
    public void Compiled_rules_are_app_rules_with_unique_names()
    {
        var specs = AppRuleEngine.Compile(SpotifyPolicy(), Resolve);
        Assert.NotEmpty(specs);
        Assert.All(specs, s => Assert.True(AppRuleEngine.IsAppRule(s.Name)));
        Assert.All(specs, s => Assert.False(FirewallPlan.IsKillSwitchRule(s.Name)));
        Assert.Equal(specs.Count, specs.Select(s => s.Name).Distinct().Count());
    }

    [Fact]
    public void Compiled_rules_agree_with_evaluator_on_random_traffic()
    {
        var policies = new[]
        {
            SpotifyPolicy(),
            new AppPolicy
            {
                Identity = new AppIdentity(AppKind.Service, "DiagTrack"),
                AllowByDefault = true,
                Rules = new[]
                {
                    new AppRule { Action = RuleAction.Block, Destination = DestinationKind.Internet },
                    new AppRule { Action = RuleAction.Allow, Protocol = TrafficProtocol.Udp, Ports = "53,123", Destination = DestinationKind.Internet },
                    new AppRule { Action = RuleAction.Block, Direction = TrafficDirection.Both, Protocol = TrafficProtocol.Tcp, Ports = "1000-2000", Destination = DestinationKind.Address, Value = "10.0.0.0/8, 192.168.5.5" },
                },
            },
        };

        var rng = new Random(1234);
        string[] interesting = { "35.186.224.24", "2600:1901::1", "172.217.4.98", "8.8.8.8", "192.168.1.42", "192.168.5.5", "10.1.2.3", "fe80::5", "2a00:1450::1", "224.0.0.251", "127.0.0.1" };
        int[] portsToTry = { 22, 53, 80, 123, 443, 999, 1000, 1500, 2000, 2001, 8009, 65535 };

        foreach (var policy in policies)
        {
            var specs = AppRuleEngine.Compile(policy, Resolve);
            for (int i = 0; i < 600; i++)
            {
                var ip = IPAddress.Parse(interesting[rng.Next(interesting.Length)]);
                if (IPAddress.IsLoopback(ip)) continue;
                var proto = (AppRuleEngine.Proto)rng.Next(3);
                int port = portsToTry[rng.Next(portsToTry.Length)];
                bool inbound = rng.Next(2) == 0;

                bool allowed = AppRuleEngine.Decide(policy, inbound, proto, port, ip, null, Resolve).Allowed;
                bool blockedByFirewall = specs.Any(s => Matches(s, inbound, proto, port, ip));
                Assert.True(allowed != blockedByFirewall, $"{policy.Identity.Value} {(inbound ? "in" : "out")} {proto} {ip}:{port} decide={allowed} firewall-blocks={blockedByFirewall}");
            }
        }
    }

    [Fact]
    public void Loosening_is_detected_and_tightening_is_not()
    {
        var before = SpotifyPolicy();
        var tighter = before with { Rules = before.Rules.Skip(1).ToArray() };
        var looser = before with { AllowByDefault = true };
        Assert.False(AppRuleEngine.Loosens(before, tighter, Resolve));
        Assert.True(AppRuleEngine.Loosens(before, looser, Resolve));
        Assert.False(AppRuleEngine.Loosens(null, looser, Resolve));
    }

    [Theory]
    [InlineData(@"C:\Program Files\App\app.exe", true)]
    [InlineData(@"relative\app.exe", false)]
    [InlineData(@"C:\a\..\b\app.exe", false)]
    [InlineData(@"\\server\share\app.exe", false)]
    [InlineData(@"C:\a\app.dll", false)]
    [InlineData("C:\\a\\ap\np.exe", false)]
    public void Program_paths_are_validated(string path, bool ok) =>
        Assert.Equal(ok, AppRuleLimits.ValidateIdentity(new AppIdentity(AppKind.Program, path)) is null);

    [Theory]
    [InlineData("spotify.com", true)]
    [InlineData("*.spotify.com", true)]
    [InlineData("SPOTIFY.COM.", true)]
    [InlineData("*", false)]
    [InlineData("a*b.com", false)]
    [InlineData("com", false)]
    [InlineData("-bad.com", false)]
    public void Domains_are_validated(string d, bool ok) =>
        Assert.Equal(ok, AppRuleLimits.TryNormalizeDomain(d, out _));

    [Theory]
    [InlineData("443", true)]
    [InlineData("8000-8100, 443", true)]
    [InlineData("Any", true)]
    [InlineData("0", false)]
    [InlineData("70000", false)]
    [InlineData("9-1", false)]
    [InlineData("abc", false)]
    public void Ports_are_validated(string p, bool ok) =>
        Assert.Equal(ok, AppRuleLimits.TryParsePorts(p, out _));

    [Fact]
    public void Port_rules_need_a_protocol()
    {
        var p = new AppPolicy { Identity = Spotify, Rules = new[] { new AppRule { Action = RuleAction.Block, Ports = "443" } } };
        Assert.NotNull(AppRuleLimits.Validate(p));
    }

    private static bool Matches(RuleSpec s, bool inbound, AppRuleEngine.Proto proto, int port, IPAddress ip)
    {
        if ((s.Direction == RuleDirection.Inbound) != inbound) return false;
        bool v6 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        bool protoOk = s.Protocol switch
        {
            RuleProtocol.Any => true,
            RuleProtocol.Tcp => proto == AppRuleEngine.Proto.Tcp,
            RuleProtocol.Udp => proto == AppRuleEngine.Proto.Udp,
            RuleProtocol.Icmp4 => proto == AppRuleEngine.Proto.Other && !v6,
            RuleProtocol.Icmp6 => proto == AppRuleEngine.Proto.Other && v6,
            _ => false,
        };
        if (!protoOk) return false;
        if (s.RemotePorts is not null)
        {
            Assert.True(AppRuleLimits.TryParsePorts(s.RemotePorts, out var pr));
            if (!pr.Any(r => port >= r.Lo && port <= r.Hi)) return false;
        }
        if (s.RemoteAddresses == "*") return true;
        Assert.True(IpRangeSet.TryParseFirewallList(s.RemoteAddresses, out var ranges));
        return ranges.Any(r => r.Contains(ip));
    }
}
