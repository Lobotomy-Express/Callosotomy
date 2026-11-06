using System.Runtime.InteropServices;
using Callosotomy.Core;

namespace Callosotomy.Service;

/// <summary>
/// Thin wrapper over the Windows Firewall COM API (INetFwPolicy2). Block rules always win over
/// allow rules in Windows Firewall, so nothing another app allows can punch through ours.
/// Not thread-safe: callers serialise access.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Injected service; kept as an instance API so it can be substituted.")]
internal sealed class FirewallBackend
{
    private const int ActionBlock = 0;
    private const int AllProfiles = 0x7FFFFFFF;
    private static readonly int[] ProfileTypes = { 1, 2, 4 }; // Domain, Private, Public

    private static dynamic NewPolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;

    private static dynamic NewRule() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;

    /// <summary>
    /// Makes the firewall contain exactly <paramref name="specs"/> among our rules.
    /// New rules are added before stale ones are removed, so switching modes never opens a gap.
    /// </summary>
    public void Reconcile(IReadOnlyList<RuleSpec> specs)
    {
        dynamic policy = NewPolicy();
        dynamic rules = policy.Rules;
        var existing = OurRuleNames(rules);

        foreach (var spec in specs)
        {
            if (existing.Contains(spec.Name))
            {
                Configure(rules.Item(spec.Name), spec);
            }
            else
            {
                dynamic rule = NewRule();
                rule.Name = spec.Name;
                Configure(rule, spec);
                rules.Add(rule);
            }
        }

        var wanted = specs.Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        foreach (string name in existing)
        {
            if (!wanted.Contains(name)) RemoveAllNamed(rules, name);
        }
    }

    /// <summary>Removes every rule this tool created.</summary>
    public void RemoveAll()
    {
        dynamic rules = NewPolicy().Rules;
        foreach (string name in OurRuleNames(rules)) RemoveAllNamed(rules, name);
    }

    /// <summary>Returns a description of what is wrong, or null when every rule is intact and enforced.</summary>
    public string? Verify(IReadOnlyList<RuleSpec> specs)
    {
        if (specs.Count == 0) return null;
        dynamic policy = NewPolicy();

        int active = policy.CurrentProfileTypes;
        foreach (int p in ProfileTypes)
        {
            if ((active & p) != 0 && !(bool)policy.FirewallEnabled[p])
                return "Windows Firewall was turned off for the active network profile";
        }

        dynamic rules = policy.Rules;
        foreach (var spec in specs)
        {
            dynamic rule;
            try { rule = rules.Item(spec.Name); }
            catch (COMException) { return $"rule '{spec.Name}' was deleted"; }
            catch (FileNotFoundException) { return $"rule '{spec.Name}' was deleted"; }

            if (!(bool)rule.Enabled) return $"rule '{spec.Name}' was disabled";
            if ((int)rule.Action != ActionBlock) return $"rule '{spec.Name}' was changed to allow";
            if ((int)rule.Direction != (int)spec.Direction || (int)rule.Protocol != (int)spec.Protocol)
                return $"rule '{spec.Name}' was modified";
            if (spec.RemoteAddresses == "*" && (string)rule.RemoteAddresses != "*")
                return $"rule '{spec.Name}' was narrowed";
            if ((int)rule.Profiles != AllProfiles) return $"rule '{spec.Name}' profiles were changed";
        }
        return null;
    }

    /// <summary>Turns Windows Firewall back on for the active profiles. Our block rules do nothing while it is off.</summary>
    public void EnsureFirewallOn()
    {
        dynamic policy = NewPolicy();
        int active = policy.CurrentProfileTypes;
        foreach (int p in ProfileTypes)
        {
            if ((active & p) != 0 && !(bool)policy.FirewallEnabled[p]) policy.FirewallEnabled[p] = true;
        }
    }

    private static void Configure(dynamic rule, RuleSpec spec)
    {
        rule.Description = "Created by Callosotomy network isolation. Do not edit; the service restores it.";
        rule.Grouping = FirewallPlan.RuleGroup;
        rule.Direction = (int)spec.Direction;
        rule.Action = ActionBlock;
        rule.Protocol = (int)spec.Protocol; // must be set before ports
        rule.RemoteAddresses = spec.RemoteAddresses;
        if (spec.RemotePorts is not null) rule.RemotePorts = spec.RemotePorts;
        rule.Profiles = AllProfiles;
        rule.InterfaceTypes = "All";
        rule.Enabled = true;
    }

    private static HashSet<string> OurRuleNames(dynamic rules)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (dynamic rule in rules)
        {
            string? name = rule.Name;
            if (FirewallPlan.IsOurs(name)) names.Add(name!);
        }
        return names;
    }

    private static void RemoveAllNamed(dynamic rules, string name)
    {
        // Remove() deletes one match; loop in case a duplicate was planted to shadow ours.
        for (int i = 0; i < 64; i++)
        {
            try { rules.Item(name); }
            catch (COMException) { return; }
            catch (FileNotFoundException) { return; }
            rules.Remove(name);
        }
    }
}
