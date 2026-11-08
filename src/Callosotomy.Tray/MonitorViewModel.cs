using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>One live connection as shown in the monitor.</summary>
internal sealed class ConnectionRow
{
    public required ConnectionInfo Info { get; init; }
    public required string Destination { get; init; }
    public required string Port { get; init; }
    public required string Where { get; init; }
    public required bool Allowed { get; init; }
    public required string Why { get; init; }
    public bool CanAct { get; init; }
    public bool HasRemote => !string.IsNullOrEmpty(Info.RemoteAddress);
    /// <summary>Closed within the last two minutes; shown dimmed.</summary>
    public bool Recent { get; init; }
    public double RowOpacity => Recent ? 0.6 : 1.0;
    public string Activity => Info.SecondsAgo is int s ? (s < 3 ? "now" : s < 60 ? $"{s}s ago" : $"{s / 60}m ago") : "";
    public string Status => Allowed ? "Allowed" : "Blocked";
    public Brush StatusBrush => Allowed ? Brushes.LightGreen : new SolidColorBrush(Color.FromRgb(0xFF, 0x8F, 0x87));
}

/// <summary>One rule in the selected app's list.</summary>
internal sealed class RuleRow
{
    public required AppRule Rule { get; init; }
    public required int Index { get; init; }
    public bool IsAllow => Rule.Action == RuleAction.Allow;
    public string ActionText => IsAllow ? "Allow" : "Block";
    public string DirectionText => Rule.Direction switch { TrafficDirection.Inbound => "In", TrafficDirection.Both => "Both", _ => "Out" };
    public string ProtocolText => Rule.Protocol switch { TrafficProtocol.Tcp => "TCP", TrafficProtocol.Udp => "UDP", _ => "Any" };
    public string PortText => AppRuleLimits.IsAnyPort(Rule.Ports) ? "Any port" : "Port " + Rule.Ports;
    public string DestinationText => Rule.Destination switch
    {
        DestinationKind.Internet => "Internet",
        DestinationKind.LocalNetwork => "Local network",
        DestinationKind.Domain or DestinationKind.Address => Rule.Value ?? "",
        _ => "Anywhere",
    };
    public bool Enabled => Rule.Enabled;
    public bool Editable { get; init; }
}

/// <summary>An app in the left-hand list: everything known about it from connections and rules.</summary>
internal sealed class AppRow
{
    public required AppIdentity Identity { get; init; }
    public required string Name { get; init; }
    public AppPolicy? Policy { get; init; }
    public List<ConnectionInfo> Connections { get; } = new();
    public bool IsProtected { get; init; }
    public bool CanEdit { get; init; }
    public bool IsSelected { get; set; }

    public string Key => Identity.Key;
    public bool AllowByDefault => Policy?.AllowByDefault ?? true;
    public string KindText => IsProtected ? "Protected" : Identity.Kind switch
    {
        AppKind.Service => "Windows service",
        AppKind.Package => "Store app",
        _ => "App",
    };
    public string Detail => Identity.Kind switch
    {
        AppKind.Service => "Service: " + Identity.Value,
        AppKind.Package => "Package: " + Identity.Value,
        _ => Identity.Value,
    };
    public string Initials
    {
        get
        {
            var letters = Name.Where(char.IsLetterOrDigit).Take(2).ToArray();
            return letters.Length == 0 ? "?" : new string(letters);
        }
    }
    public Brush Accent
    {
        get
        {
            // Stable colour per app, from a small palette.
            uint h = 2166136261;
            foreach (char c in Key) h = (h ^ c) * 16777619;
            Color[] palette = { Color.FromRgb(0x4B, 0x8C, 0xF5), Color.FromRgb(0x30, 0xD1, 0x58), Color.FromRgb(0xBF, 0x5A, 0xF2),
                                Color.FromRgb(0xFF, 0x9F, 0x0A), Color.FromRgb(0x64, 0xD2, 0xFF), Color.FromRgb(0xFF, 0x6B, 0x8B) };
            var b = new SolidColorBrush(IsProtected ? Color.FromRgb(0x8E, 0x8E, 0x93) : palette[h % (uint)palette.Length]);
            b.Freeze();
            return b;
        }
    }
    public string CountText => Connections.Count.ToString(CultureInfo.InvariantCulture);
    public string DefaultText => IsProtected ? "Protected: can't be blocked"
        : AllowByDefault ? "Allowed unless a rule blocks it" : "Blocked unless a rule allows it";
    public bool CanToggle => CanEdit && !IsProtected;
}

/// <summary>State and actions of the network monitor window.</summary>
internal sealed class MonitorViewModel : INotifyPropertyChanged
{
    private ConnectionSnapshot _connections = new();
    private PolicySnapshot _policies = new();
    private string _search = "";
    private string? _selectedKey;
    private string? _message;
    private bool _reachable = true;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<AppRow> Apps { get; } = new();
    public AppRow? Selected => Apps.FirstOrDefault(a => a.Key == _selectedKey) ?? Apps.FirstOrDefault();
    public IReadOnlyList<RuleRow> Rules => _rules;
    private IReadOnlyList<RuleRow> _rules = new List<RuleRow>();
    private int _policyVersion;
    public IReadOnlyList<ConnectionRow> SelectedConnections => Selected is { } a ? a.Connections.Select(c => Row(a, c)).ToList() : new List<ConnectionRow>();
    public bool HasSelection => Selected is not null;
    public bool CanEditSelected => Selected?.CanToggle == true;
    public string? Message { get => _message; private set { _message = value; Raise(); } }
    public string Summary => !_reachable ? "Can't reach the protection service"
        : $"{Apps.Count(a => a.Connections.Count > 0)} apps using the network · {Apps.Count(a => a.Policy is not null)} with rules"
          + (_connections.LiveEvents ? " · live" : " · table only")
          + (_connections.Truncated ? " · list truncated" : "");

    public string Search
    {
        get => _search;
        set { _search = value ?? ""; Rebuild(); }
    }

    public void Select(string key)
    {
        _selectedKey = key;
        Rebuild();
    }

    // ---- Refresh -----------------------------------------------------------------------

    public async Task RefreshConnectionsAsync()
    {
        var reply = await ServiceClient.ConnectionsAsync().ConfigureAwait(true);
        _reachable = reply.Value is not null;
        if (reply.Value is not null) _connections = reply.Value;
        Rebuild();
    }

    public async Task RefreshPoliciesAsync()
    {
        int version = _policyVersion;
        var reply = await ServiceClient.PoliciesAsync().ConfigureAwait(true);
        // A change saved while this request was in flight is newer: don't overwrite it with the old list.
        if (reply.Value is not null && version == _policyVersion) _policies = reply.Value;
        Rebuild();
    }

    private void Rebuild()
    {
        var policies = _policies.Policies.ToDictionary(p => p.Identity.Key);
        var protectedKeys = _policies.Protected.ToHashSet(StringComparer.Ordinal);
        var rows = new Dictionary<string, AppRow>(StringComparer.Ordinal);

        AppRow Get(AppIdentity id, string name)
        {
            if (!rows.TryGetValue(id.Key, out var row))
            {
                policies.TryGetValue(id.Key, out var policy);
                rows[id.Key] = row = new AppRow
                {
                    Identity = id,
                    Name = !string.IsNullOrWhiteSpace(policy?.DisplayName) ? policy!.DisplayName : name,
                    Policy = policy,
                    IsProtected = protectedKeys.Contains(id.Key) || LooksProtected(id),
                    CanEdit = _policies.CanEdit,
                };
            }
            return row;
        }

        foreach (var c in _connections.Connections) Get(c.App, c.DisplayName).Connections.Add(c);
        foreach (var p in _policies.Policies) Get(p.Identity, string.IsNullOrEmpty(p.DisplayName) ? Path.GetFileNameWithoutExtension(p.Identity.Value) : p.DisplayName);

        IEnumerable<AppRow> list = rows.Values;
        if (_search.Length > 0)
        {
            list = list.Where(a => a.Name.Contains(_search, StringComparison.OrdinalIgnoreCase)
                || a.Identity.Value.Contains(_search, StringComparison.OrdinalIgnoreCase)
                || a.Connections.Any(c => (c.Host ?? c.RemoteAddress).Contains(_search, StringComparison.OrdinalIgnoreCase)));
        }
        var sorted = list
            .OrderByDescending(a => a.Policy is not null && !a.AllowByDefault)
            .ThenByDescending(a => a.Connections.Count)
            .ThenBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        Apps.Clear();
        foreach (var a in sorted) Apps.Add(a);
        if (_selectedKey is null || Apps.All(a => a.Key != _selectedKey)) _selectedKey = Apps.FirstOrDefault()?.Key;
        foreach (var a in Apps) a.IsSelected = a.Key == _selectedKey;
        RaiseSelection();
        Raise(nameof(Summary));
    }

    /// <summary>The service refuses these anyway; locking them in the UI avoids a confusing error.</summary>
    private static bool LooksProtected(AppIdentity id) =>
        id.Kind == AppKind.Program && (id.Value == "System"
            || Path.GetFileName(id.Value).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
            || id.Value.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase)
            || id.Value.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase));

    private static ConnectionRow Row(AppRow app, ConnectionInfo c)
    {
        bool listening = c.State == "Listening" || string.IsNullOrEmpty(c.RemoteAddress);
        bool tcp = c.Protocol == "TCP";
        if (listening)
        {
            return new ConnectionRow
            {
                Info = c,
                Destination = (tcp ? "Listening for connections" : "Open UDP socket") + $" on port {c.LocalPort}",
                Port = c.LocalPort.ToString(CultureInfo.InvariantCulture),
                Where = c.Protocol,
                Allowed = true,
                Why = "Incoming connections are also governed by Windows Firewall's own rules.",
                CanAct = false,
            };
        }

        var ip = IPAddress.Parse(c.RemoteAddress);
        var (allowed, rule) = app.Policy is null
            ? (true, null)
            : AppRuleEngine.Decide(app.Policy, c.Inbound, tcp ? AppRuleEngine.Proto.Tcp : AppRuleEngine.Proto.Udp, c.RemotePort, ip, c.Host);
        return new ConnectionRow
        {
            Info = c,
            Destination = (c.Host ?? c.RemoteAddress) + (c.Protocol == "UDP" ? "  (UDP)" : ""),
            Port = c.RemotePort.ToString(CultureInfo.InvariantCulture),
            Where = (c.Inbound ? "In · " : "") + (FirewallPlan.IsInternet(ip) ? "Internet" : "Local network")
                    + (c.BytesSent + c.BytesReceived > 0 ? " · " + Size(c.BytesSent + c.BytesReceived) : ""),
            Recent = c.State == "Recent",
            Allowed = allowed,
            Why = rule is null ? "App default" : $"Rule: {(rule.Action == RuleAction.Allow ? "Allow" : "Block")} {new RuleRow { Rule = rule, Index = 0 }.DestinationText}",
            CanAct = app.CanToggle,
        };
    }

    // ---- Actions -----------------------------------------------------------------------

    private static AppPolicy PolicyFor(AppRow a) => a.Policy ?? new AppPolicy { Identity = a.Identity, DisplayName = Trim(a.Name) };

    public Task ToggleAppAsync(AppRow a)
    {
        var p = PolicyFor(a);
        return SaveAsync(a, p with { AllowByDefault = !p.AllowByDefault }, a.AllowByDefault ? $"{a.Name} is now blocked" : $"{a.Name} is now allowed");
    }

    public Task ToggleRuleAsync(RuleRow r) => EditRules(rules => rules[r.Index] = rules[r.Index] with { Enabled = !rules[r.Index].Enabled }, null);

    public Task DeleteRuleAsync(RuleRow r) => EditRules(rules => rules.RemoveAt(r.Index), "Rule removed");

    public Task AddRuleAsync(AppRule rule) => EditRules(rules => rules.Add(rule), "Rule added");

    public Task AllowOnlyThisAsync(ConnectionRow c)
    {
        if (Selected is not { } a) return Task.CompletedTask;
        var p = PolicyFor(a);
        var rule = DestinationRule(c, RuleAction.Allow, withPort: true);
        var rules = p.Rules.ToList();
        rules.Add(rule);
        return SaveAsync(a, p with { AllowByDefault = false, Rules = rules }, $"{a.Name} may now only reach {c.Destination}:{c.Port}");
    }

    public Task BlockPortAsync(ConnectionRow c) =>
        EditRules(rules => rules.Add(new AppRule
        {
            Action = RuleAction.Block,
            Protocol = c.Info.Protocol == "UDP" ? TrafficProtocol.Udp : TrafficProtocol.Tcp,
            Ports = c.Port,
        }), $"Blocked port {c.Port}");

    public Task BlockDestinationAsync(ConnectionRow c) =>
        EditRules(rules => rules.Add(DestinationRule(c, RuleAction.Block, withPort: false)), $"Blocked {c.Destination}");

    public Task RemoveAllRulesAsync()
    {
        if (Selected is not { Policy: not null } a) return Task.CompletedTask;
        return SendAsync(ServiceClient.DeletePolicyAsync(a.Identity), $"Rules for {a.Name} removed");
    }

    private static AppRule DestinationRule(ConnectionRow c, RuleAction action, bool withPort)
    {
        bool hasDomain = c.Info.Host is not null && AppRuleLimits.TryNormalizeDomain(c.Info.Host, out _);
        string? domain = hasDomain ? RegistrableDomain(c.Info.Host!) : null;
        return new AppRule
        {
            Action = action,
            Protocol = withPort ? (c.Info.Protocol == "UDP" ? TrafficProtocol.Udp : TrafficProtocol.Tcp) : TrafficProtocol.Any,
            Ports = withPort ? c.Port : "Any",
            Destination = domain is not null ? DestinationKind.Domain : DestinationKind.Address,
            Value = domain ?? c.Info.RemoteAddress,
        };
    }

    /// <summary>"ads.tracker.example.com" → "example.com" (good enough without a public-suffix list; two-label suffixes kept whole).</summary>
    private static string RegistrableDomain(string host)
    {
        var labels = host.TrimEnd('.').ToLowerInvariant().Split('.');
        if (labels.Length <= 2) return string.Join('.', labels);
        bool twoPartSuffix = labels[^2] is "co" or "com" or "net" or "org" or "gov" or "ac" or "edu" && labels[^1].Length == 2;
        return string.Join('.', labels.Skip(labels.Length - (twoPartSuffix ? 3 : 2)));
    }

    private Task EditRules(Action<List<AppRule>> edit, string? done)
    {
        if (Selected is not { } a) return Task.CompletedTask;
        var p = PolicyFor(a);
        var rules = p.Rules.ToList();
        edit(rules);
        return SaveAsync(a, p with { Rules = rules }, done);
    }

    private Task SaveAsync(AppRow a, AppPolicy p, string? done)
    {
        if (AppRuleLimits.Validate(p) is { } error)
        {
            Message = "That rule isn't valid: " + error;
            return Task.CompletedTask;
        }
        // A policy that allows everything and has no rules is the same as no policy: remove it.
        if (p.AllowByDefault && p.Rules.Count == 0)
            return a.Policy is null ? Task.CompletedTask : SendAsync(ServiceClient.DeletePolicyAsync(a.Identity), done);
        return SendAsync(ServiceClient.PutPolicyAsync(p), done);
    }

    private async Task SendAsync(Task<DataReply<PolicySnapshot>> call, string? done)
    {
        var reply = await call.ConfigureAwait(true);
        if (reply.Value is not null)
        {
            _policyVersion++;
            _policies = reply.Value;
            Message = done;
            Rebuild();
            await RefreshConnectionsAsync().ConfigureAwait(true);
            return;
        }
        Message = reply.Error switch
        {
            ProtocolErrors.Denied => "An administrator needs to make this change",
            ProtocolErrors.Protected => "That app is protected and can't be blocked",
            ProtocolErrors.Invalid => "That rule isn't valid",
            ProtocolErrors.Limit => "Too many rules. Remove some first",
            "unreachable" => "Can't reach the protection service",
            "untrusted-server" => "Refused: the control channel is not the real service",
            _ => "The service couldn't apply that change",
        };
    }

    public void ClearMessage() => Message = null;

    public void ShowMessage(string message) => Message = message;

    // ---- PowerShell export ---------------------------------------------------------------

    /// <summary>
    /// PowerShell commands reproducing the selected app's rules. Every value is single-quoted with
    /// quotes doubled, and anything with control characters is refused, so an app's name or path
    /// can't change what the command does. Domain rules can't be expressed in Windows Firewall,
    /// so they're exported as the addresses Callosotomy currently knows for them (as a comment).
    /// </summary>
    public static string? PowerShellFor(AppRow a)
    {
        if (a.Policy is null) return null;
        var specs = AppRuleEngine.Compile(a.Policy);
        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"# Callosotomy rules for {Comment(a.Name)} (run in an administrator PowerShell)");
        if (a.Policy.Rules.Any(r => r.Enabled && r.Destination == DestinationKind.Domain))
            sb.AppendLine("# Note: domain rules can't be exported; they're omitted below.");
        foreach (var s in specs)
        {
            if (!Safe(s.Program) || !Safe(s.Service) || !Safe(s.PackageSid)) return null;
            sb.Append("New-NetFirewallRule -DisplayName ").Append(Q("Callosotomy export: " + a.Name))
              .Append(" -Group 'Callosotomy (exported)' -Action Block -Direction ")
              .Append(s.Direction == RuleDirection.Inbound ? "Inbound" : "Outbound")
              .Append(" -Protocol ").Append(s.Protocol switch
              {
                  RuleProtocol.Tcp => "TCP", RuleProtocol.Udp => "UDP", RuleProtocol.Icmp4 => "ICMPv4", RuleProtocol.Icmp6 => "ICMPv6", _ => "Any",
              });
            if (s.RemotePorts is not null) sb.Append(" -RemotePort ").Append(string.Join(',', s.RemotePorts.Split(',').Select(Q)));
            if (s.RemoteAddresses != "*") sb.Append(" -RemoteAddress ").Append(string.Join(',', s.RemoteAddresses.Split(',').Select(Q)));
            if (s.Program is not null) sb.Append(" -Program ").Append(Q(s.Program));
            if (s.Service is not null) sb.Append(" -Service ").Append(Q(s.Service));
            if (s.PackageSid is not null) sb.Append(" -Package ").Append(Q(s.PackageSid));
            sb.AppendLine();
        }
        return sb.ToString();

        static string Q(string v) => "'" + v.Replace("'", "''", StringComparison.Ordinal) + "'";
        static bool Safe(string? v) => v is null || !v.Any(char.IsControl);
        static string Comment(string v) => new string(v.Where(ch => !char.IsControl(ch)).ToArray());
    }

    private static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} GB",
    };

    private static string Trim(string name) =>
        new string(name.Where(c => !char.IsControl(c)).Take(AppRuleLimits.MaxDisplayName).ToArray());

    private void RaiseSelection()
    {
        Raise(nameof(Selected));
        // Rebuild the rule rows only when the rules actually changed, so a refresh never replaces
        // a switch while it's being clicked.
        var sel = Selected;
        var rules = sel?.Policy?.Rules ?? Array.Empty<AppRule>();
        bool editable = sel?.CanToggle == true;
        if (rules.Count != _rules.Count || _rules.Any(r => r.Editable != editable)
            || !rules.SequenceEqual(_rules.Select(r => r.Rule)))
        {
            _rules = rules.Select((r, i) => new RuleRow { Rule = r, Index = i, Editable = editable }).ToList();
            Raise(nameof(Rules));
        }
        Raise(nameof(SelectedConnections));
        Raise(nameof(HasSelection));
        Raise(nameof(CanEditSelected));
    }

    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
