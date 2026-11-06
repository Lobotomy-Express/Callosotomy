using System.Net;
using Callosotomy.Core;
using Xunit;

namespace Callosotomy.Core.Tests;

public class IpRangeTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.0-10.255.255.255")]
    [InlineData("192.168.1.7", "192.168.1.7")]
    [InlineData("0.0.0.0/0", "0.0.0.0-255.255.255.255")]
    [InlineData("fe80::/10", "fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("1.2.3.4-1.2.3.9", "1.2.3.4-1.2.3.9")]
    public void Parse_and_format_round_trip(string input, string expected) =>
        Assert.Equal(expected, IpRange.Parse(input).ToString());

    [Theory]
    [InlineData("1.2.3.9-1.2.3.4")]
    [InlineData("1.2.3.4-::1")]
    [InlineData("10.0.0.0/33")]
    [InlineData("not-an-ip")]
    public void Parse_rejects_bad_input(string input) =>
        Assert.ThrowsAny<FormatException>(() => IpRange.Parse(input));

    [Fact]
    public void Subtract_splits_around_a_hole()
    {
        var result = IpRangeSet.Subtract(IpRangeSet.Parse("192.168.0.0/16"), IpRangeSet.Parse("192.168.1.1"));
        Assert.Equal(new[] { "192.168.0.0-192.168.1.0", "192.168.1.2-192.168.255.255" }, result.Select(r => r.ToString()));
    }

    [Fact]
    public void Subtract_ignores_other_family()
    {
        var result = IpRangeSet.Subtract(IpRangeSet.Parse("10.0.0.0/8"), IpRangeSet.Parse("fe80::1"));
        Assert.Equal("10.0.0.0-10.255.255.255", Assert.Single(result).ToString());
    }

    [Fact]
    public void Subtract_everything_leaves_nothing() =>
        Assert.Empty(IpRangeSet.Subtract(IpRangeSet.Parse("10.0.0.0/24"), IpRangeSet.Parse("10.0.0.0/8")));

    [Fact]
    public void Normalize_merges_adjacent_and_overlapping()
    {
        var result = IpRangeSet.Parse("10.0.0.0/25", "10.0.0.128/25", "10.0.0.5", "0.0.0.0/0");
        Assert.Equal("0.0.0.0-255.255.255.255", Assert.Single(result).ToString());
    }

    [Fact]
    public void Ipv4_mapped_ipv6_is_treated_as_ipv4() =>
        Assert.True(IpRange.Parse("10.0.0.0/8").Contains(IPAddress.Parse("::ffff:10.1.2.3")));
}

public class FirewallPlanTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("2606:4700::1111", true)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("224.0.0.251", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    public void Internet_set_contains_exactly_public_addresses(string ip, bool isInternet) =>
        Assert.Equal(isInternet, FirewallPlan.Internet.Any(r => r.Contains(IPAddress.Parse(ip))));

    [Fact]
    public void None_has_no_rules() => Assert.Empty(FirewallPlan.Build(IsolationMode.None));

    [Fact]
    public void All_blocks_everything_both_ways()
    {
        var rules = FirewallPlan.Build(IsolationMode.All);
        Assert.Equal(2, rules.Count);
        Assert.All(rules, r => Assert.Equal("*", r.RemoteAddresses));
        Assert.All(rules, r => Assert.Equal(RuleProtocol.Any, r.Protocol));
        Assert.Contains(rules, r => r.Direction == RuleDirection.Inbound);
        Assert.Contains(rules, r => r.Direction == RuleDirection.Outbound);
    }

    [Fact]
    public void Internet_mode_closes_the_dns_loophole()
    {
        var rules = FirewallPlan.Build(IsolationMode.Internet);
        Assert.Contains(rules, r => r.Protocol == RuleProtocol.Udp && r.RemotePorts == "53,853" && r.RemoteAddresses == "*");
        Assert.Contains(rules, r => r.Protocol == RuleProtocol.Tcp && r.RemotePorts == "53,853" && r.RemoteAddresses == "*");
    }

    [Fact]
    public void Local_mode_keeps_gateway_and_dns_reachable()
    {
        var infra = new[] { IPAddress.Parse("192.168.1.1"), IPAddress.Parse("fe80::1") };
        var rules = FirewallPlan.Build(IsolationMode.Local, infra);
        var tcpOut = rules.Single(r => r.Name == "Callosotomy:Local:TCP:Out");
        var ranges = tcpOut.RemoteAddresses.Split(',').Select(IpRange.Parse).ToList();
        Assert.DoesNotContain(ranges, r => r.Contains(infra[0]));
        Assert.DoesNotContain(ranges, r => r.Contains(infra[1]));
        Assert.Contains(ranges, r => r.Contains(IPAddress.Parse("192.168.1.2")));
    }

    [Fact]
    public void Local_mode_leaves_dhcp_alone()
    {
        var multicast = FirewallPlan.Build(IsolationMode.Local).Single(r => r.Name == "Callosotomy:Local:Multicast:Out");
        Assert.Equal("1-66,69-545,548-65535", multicast.RemotePorts);
    }

    [Fact]
    public void Every_rule_is_recognised_as_ours_and_names_are_unique()
    {
        foreach (var mode in Enum.GetValues<IsolationMode>())
        {
            var rules = FirewallPlan.Build(mode, new[] { IPAddress.Parse("10.0.0.1") });
            Assert.All(rules, r => Assert.True(FirewallPlan.IsOurs(r.Name)));
            Assert.Equal(rules.Count, rules.Select(r => r.Name).Distinct().Count());
        }
        Assert.False(FirewallPlan.IsOurs("Core Networking - DHCP"));
    }

    [Theory]
    [InlineData(IsolationMode.Internet, "8.8.8.8", true)]
    [InlineData(IsolationMode.Internet, "192.168.1.5", false)]
    [InlineData(IsolationMode.Local, "192.168.1.5", true)]
    [InlineData(IsolationMode.Local, "192.168.1.1", false)]
    [InlineData(IsolationMode.Local, "8.8.8.8", false)]
    [InlineData(IsolationMode.All, "192.168.1.1", true)]
    [InlineData(IsolationMode.All, "127.0.0.1", false)]
    [InlineData(IsolationMode.None, "8.8.8.8", false)]
    public void ShouldDrop_matches_the_mode(IsolationMode mode, string ip, bool expected) =>
        Assert.Equal(expected, FirewallPlan.ShouldDrop(mode, IPAddress.Parse(ip), new[] { IPAddress.Parse("192.168.1.1") }));
}

public class ProtocolTests
{
    [Theory]
    [InlineData("STATUS", Protocol.Verb.Status, IsolationMode.None)]
    [InlineData("SET ALL", Protocol.Verb.Set, IsolationMode.All)]
    [InlineData("SET NONE", Protocol.Verb.Set, IsolationMode.None)]
    [InlineData("SET INTERNET", Protocol.Verb.Set, IsolationMode.Internet)]
    [InlineData("SET LOCAL", Protocol.Verb.Set, IsolationMode.Local)]
    public void Valid_requests_parse(string line, Protocol.Verb verb, IsolationMode mode)
    {
        Assert.True(Protocol.TryParseRequest(line, out var req));
        Assert.Equal(verb, req.Verb);
        Assert.Equal(mode, req.Mode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("status")]
    [InlineData("SET all")]
    [InlineData("SET  ALL")]
    [InlineData("SET ALL ")]
    [InlineData("SET 3")]
    [InlineData("DELETE")]
    public void Anything_else_is_rejected(string? line) =>
        Assert.False(Protocol.TryParseRequest(line, out _));

    [Fact]
    public void Oversized_request_is_rejected() =>
        Assert.False(Protocol.TryParseRequest("SET " + new string('A', 200), out _));

    [Fact]
    public void Status_round_trips()
    {
        var s = new Protocol.Status(IsolationMode.Local, BlockHealth.Repaired, 1_793_962_000_000);
        Assert.True(Protocol.TryParseResponse(Protocol.FormatOk(s), out var back, out _));
        Assert.Equal(s, back);
    }

    [Fact]
    public void Error_response_surfaces_code()
    {
        Assert.False(Protocol.TryParseResponse(Protocol.FormatError(ProtocolErrors.Denied), out _, out var err));
        Assert.Equal("denied", err);
    }

    [Theory]
    [InlineData(IsolationMode.All, IsolationMode.Internet, true)]
    [InlineData(IsolationMode.Internet, IsolationMode.None, true)]
    [InlineData(IsolationMode.Internet, IsolationMode.Internet, true)]
    [InlineData(IsolationMode.None, IsolationMode.All, false)]
    [InlineData(IsolationMode.Local, IsolationMode.Internet, false)]
    [InlineData(IsolationMode.Internet, IsolationMode.All, false)]
    public void Covers_only_when_protection_tightens(IsolationMode target, IsolationMode current, bool expected) =>
        Assert.Equal(expected, target.Covers(current));
}
