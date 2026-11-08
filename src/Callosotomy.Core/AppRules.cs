using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace Callosotomy.Core;

/// <summary>How an app is identified to Windows Firewall.</summary>
public enum AppKind
{
    /// <summary>A program, by full path.</summary>
    Program = 0,
    /// <summary>A Windows service, by service name (covers services hosted in svchost.exe).</summary>
    Service = 1,
    /// <summary>A Microsoft Store app, by package (AppContainer) SID.</summary>
    Package = 2,
}

public enum RuleAction { Allow = 0, Block = 1 }

public enum TrafficDirection { Outbound = 0, Inbound = 1, Both = 2 }

public enum TrafficProtocol { Any = 0, Tcp = 1, Udp = 2 }

public enum DestinationKind { Anywhere = 0, Internet = 1, LocalNetwork = 2, Domain = 3, Address = 4 }

/// <summary>Who the rules apply to.</summary>
public sealed record AppIdentity(AppKind Kind, string Value)
{
    /// <summary>Stable key used for rule names and lookups (case-insensitive for paths and services).</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string Key => Kind switch
    {
        AppKind.Program => "p:" + Value.ToUpperInvariant(),
        AppKind.Service => "s:" + Value.ToUpperInvariant(),
        _ => "k:" + Value.ToUpperInvariant(),
    };
}

/// <summary>One line in an app's rule list.</summary>
public sealed record AppRule
{
    public RuleAction Action { get; init; }
    public TrafficDirection Direction { get; init; } = TrafficDirection.Outbound;
    public TrafficProtocol Protocol { get; init; } = TrafficProtocol.Any;
    /// <summary>"Any", a port ("443"), a range ("8000-8100") or a comma list of those.</summary>
    public string Ports { get; init; } = "Any";
    public DestinationKind Destination { get; init; } = DestinationKind.Anywhere;
    /// <summary>Domain pattern ("spotify.com", "*.spotify.com") or address list ("10.0.0.5, 1.2.3.0/24").</summary>
    public string? Value { get; init; }
    public bool Enabled { get; init; } = true;
}

/// <summary>An app's default plus its exceptions. Most specific matching rule wins; ties go to Block.</summary>
public sealed record AppPolicy
{
    public required AppIdentity Identity { get; init; }
    public string DisplayName { get; init; } = "";
    /// <summary>What happens to traffic no rule matches.</summary>
    public bool AllowByDefault { get; init; } = true;
    public IReadOnlyList<AppRule> Rules { get; init; } = Array.Empty<AppRule>();
}

/// <summary>Validation limits. Generous for people, tight enough that nobody can make the service do unbounded work.</summary>
public static partial class AppRuleLimits
{
    public const int MaxPolicies = 500;
    public const int MaxRulesPerPolicy = 64;
    public const int MaxPortItems = 32;
    public const int MaxAddressItems = 64;
    public const int MaxDisplayName = 128;
    public const int MaxFirewallRulesTotal = 3000;

    private static readonly System.Buffers.SearchValues<char> BadPathChars = System.Buffers.SearchValues.Create("*?\"<>|/");

    [GeneratedRegex(@"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$", RegexOptions.CultureInvariant)]
    private static partial Regex DomainPattern();

    [GeneratedRegex(@"^S-1-15-2(-\d{1,10}){7}$", RegexOptions.CultureInvariant)]
    private static partial Regex PackageSid();

    [GeneratedRegex(@"^[A-Za-z0-9_.\- ]{1,256}$", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceName();

    /// <summary>Checks everything about a policy that doesn't need the operating system. Returns an error or null.</summary>
    public static string? Validate(AppPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.DisplayName.Length > MaxDisplayName || HasControl(policy.DisplayName)) return "bad display name";
        if (ValidateIdentity(policy.Identity) is { } idError) return idError;
        if (policy.Rules.Count > MaxRulesPerPolicy) return "too many rules";
        foreach (var r in policy.Rules)
        {
            if (!Enum.IsDefined(r.Action) || !Enum.IsDefined(r.Direction) || !Enum.IsDefined(r.Protocol) || !Enum.IsDefined(r.Destination))
                return "bad rule";
            if (!TryParsePorts(r.Ports, out _)) return "bad ports";
            if (r.Protocol == TrafficProtocol.Any && !IsAnyPort(r.Ports)) return "ports need TCP or UDP";
            switch (r.Destination)
            {
                case DestinationKind.Domain when !TryNormalizeDomain(r.Value, out _):
                    return "bad domain";
                case DestinationKind.Address when !TryParseAddresses(r.Value, out _):
                    return "bad address";
            }
        }
        return null;
    }

    public static string? ValidateIdentity(AppIdentity? id)
    {
        if (id is null || string.IsNullOrEmpty(id.Value) || HasControl(id.Value)) return "bad identity";
        switch (id.Kind)
        {
            case AppKind.Program:
                string v = id.Value;
                bool absolute = v.Length > 3 && char.IsAsciiLetter(v[0]) && v[1] == ':' && v[2] == '\\';
                if (!absolute || v.Length > 260 || v.Contains("\\..", StringComparison.Ordinal)
                    || v.AsSpan().IndexOfAny(BadPathChars) >= 0
                    || !v.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    return "bad program path";
                return null;
            case AppKind.Service:
                return ServiceName().IsMatch(id.Value) ? null : "bad service name";
            case AppKind.Package:
                return PackageSid().IsMatch(id.Value) ? null : "bad package";
            default:
                return "bad identity";
        }
    }

    public static bool IsAnyPort(string? ports) => string.Equals(ports?.Trim(), "Any", StringComparison.OrdinalIgnoreCase);

    /// <summary>Parses "Any" (returns 1-65535), "443", "8000-8100", or comma lists of those.</summary>
    public static bool TryParsePorts(string? text, out List<(int Lo, int Hi)> ranges)
    {
        ranges = new();
        if (string.IsNullOrWhiteSpace(text)) return false;
        if (IsAnyPort(text)) { ranges.Add((1, 65535)); return true; }
        var items = text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (items.Length == 0 || items.Length > MaxPortItems) return false;
        foreach (var item in items)
        {
            int dash = item.IndexOf('-', StringComparison.Ordinal);
            string a = dash < 0 ? item : item[..dash], b = dash < 0 ? item : item[(dash + 1)..];
            if (!int.TryParse(a, NumberStyles.None, CultureInfo.InvariantCulture, out int lo)
                || !int.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out int hi)
                || lo < 1 || hi > 65535 || lo > hi)
                return false;
            ranges.Add((lo, hi));
        }
        ranges.Sort();
        return true;
    }

    public static bool TryNormalizeDomain(string? text, out string domain)
    {
        domain = (text ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        return domain.Length is > 2 and <= 253 && DomainPattern().IsMatch(domain);
    }

    public static bool TryParseAddresses(string? text, out List<IpRange> ranges)
    {
        ranges = new();
        if (string.IsNullOrWhiteSpace(text)) return false;
        var items = text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (items.Length == 0 || items.Length > MaxAddressItems) return false;
        try
        {
            foreach (var i in items) ranges.Add(IpRange.Parse(i));
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException)
        {
            return false;
        }
        ranges = IpRangeSet.Normalize(ranges);
        return true;
    }

    /// <summary>True when a host name matches a domain pattern: "x.com" matches x.com and its subdomains; "*.x.com" only subdomains.</summary>
    public static bool DomainMatches(string pattern, string? host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        host = host.TrimEnd('.').ToLowerInvariant();
        if (pattern.StartsWith("*.", StringComparison.Ordinal))
            return host.EndsWith(pattern[1..], StringComparison.Ordinal);
        return host == pattern || host.EndsWith("." + pattern, StringComparison.Ordinal);
    }

    private static bool HasControl(string s)
    {
        foreach (char c in s) if (char.IsControl(c)) return true;
        return false;
    }
}
