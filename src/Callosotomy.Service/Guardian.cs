using System.Net;
using System.Net.NetworkInformation;
using Callosotomy.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Callosotomy.Service;

/// <summary>
/// Owns everything the service enforces: the kill-switch mode and the per-app rules.
/// Applies them, re-checks them when Windows reports a firewall change (with a slow backstop),
/// repairs tampering and raises the alarm when traffic gets through.
/// </summary>
internal sealed class Guardian : BackgroundService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan BackstopInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DnsInterval = TimeSpan.FromSeconds(5);
    private const int ProbeEveryNthCycle = 4; // ~12 s

    private readonly FirewallBackend _firewall;
    private readonly FirewallWatcher _watcher;
    private readonly DnsMap _dns;
    private readonly ConnectionTable _connections;
    private readonly NetworkEvents _events;
    private readonly ILogger<Guardian> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private IsolationMode _mode;
    private BlockHealth _health;
    private long _checkedUnixMs;
    private IReadOnlyList<IPAddress> _infrastructure = Array.Empty<IPAddress>();
    private IReadOnlyList<RuleSpec> _specs = Array.Empty<RuleSpec>();
    private List<AppPolicy> _policies = new();
    private IReadOnlyList<RuleSpec> _appSpecs = Array.Empty<RuleSpec>();
    private DateTime _lastFullVerify;
    private volatile bool _networkChanged;
    private bool _needsApply, _needsApplyApps;

    public Guardian(FirewallBackend firewall, FirewallWatcher watcher, DnsMap dns, ConnectionTable connections, NetworkEvents events, ILogger<Guardian> log)
    {
        _events = events;
        _firewall = firewall;
        _watcher = watcher;
        _dns = dns;
        _connections = connections;
        _log = log;
    }

    public Protocol.Status Current => new(_mode, _health, Interlocked.Read(ref _checkedUnixMs));

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        // Fail closed: whatever was active before a reboot or crash is enforced again first thing.
        var restored = StateStore.Load();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _policies = AppPolicyStore.Load();
            try
            {
                ApplyLocked(restored);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Typically Windows Firewall isn't ready yet. Keep the mode and retry every cycle.
                Log.ApplyFailed(_log, restored, ex);
                _mode = restored;
                _health = restored == IsolationMode.None ? BlockHealth.Ok : BlockHealth.Bypassed;
                _needsApply = true;
            }
            try
            {
                _dns.Refresh(TimeSpan.Zero);
                ApplyAppsLocked();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.AppApplyFailed(_log, ex);
                _needsApplyApps = true;
            }
        }
        finally
        {
            _gate.Release();
        }

        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        _watcher.Start();
        Log.Started(_log, restored);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        // Rules are deliberately left in place: stopping the service must never lift a block.
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        _watcher.Stop();
        return base.StopAsync(cancellationToken);
    }

    public override void Dispose()
    {
        // The watcher and event stream are singletons owned and disposed by the host.
        _gate.Dispose();
        base.Dispose();
    }

    // ---- Kill switch -------------------------------------------------------------------

    public async Task<Protocol.Status> SetModeAsync(IsolationMode target, string user, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var from = _mode;
            ApplyLocked(target);
            StateStore.Save(target);
            Log.ModeChanged(_log, from, target, user);

            if (target != IsolationMode.None && ServicePolicy.Load().DropConnections)
            {
                int dropped = Network.DropConnections(target, _infrastructure);
                if (dropped > 0) Log.ConnectionsDropped(_log, dropped, target);
            }
            return Current;
        }
        finally
        {
            _gate.Release();
        }
    }

    // ---- App rules ---------------------------------------------------------------------

    public IReadOnlyList<IPAddress> Resolve(string pattern) => _dns.Resolve(pattern);

    public ConnectionSnapshot Connections()
    {
        _events.Touch();
        _dns.Refresh(TimeSpan.FromSeconds(3));
        return _connections.Snapshot(_events.Snapshot(), _events.Active);
    }

    public async Task<IReadOnlyList<AppPolicy>> PoliciesAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { return _policies.ToList(); }
        finally { _gate.Release(); }
    }

    /// <summary>Stores and enforces a policy (null removes it). Caller has already validated and authorized it.</summary>
    public async Task<IReadOnlyList<AppPolicy>> ReplacePolicyAsync(AppIdentity identity, AppPolicy? policy, string user, CancellationToken ct)
    {
        List<AppPolicy> result;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var next = _policies.Where(p => p.Identity.Key != identity.Key).ToList();
            if (policy is not null) next.Add(policy);

            int total = next.Sum(p => AppRuleEngine.Compile(p, _dns.Resolve).Count);
            if (total > AppRuleLimits.MaxFirewallRulesTotal)
                throw new InvalidOperationException("too many firewall rules");

            var previous = _policies;
            _policies = next;
            try
            {
                ApplyAppsLocked();
                AppPolicyStore.Save(_policies);
            }
            catch
            {
                _policies = previous;
                _needsApplyApps = true;
                throw;
            }
            Log.AppRulesChanged(_log, identity.Value, policy is null ? "removed" : Describe(policy), user);
            result = _policies.ToList();
        }
        finally
        {
            _gate.Release();
        }

        // Cut connections the new rules block, so switching an app off takes effect immediately.
        if (policy is not null && ServicePolicy.Load().DropConnections)
        {
            int dropped = _connections.DropBlocked(new[] { policy }, _dns.Resolve);
            if (dropped > 0) Log.AppConnectionsDropped(_log, dropped, identity.Value);
        }
        return result;
    }

    private static string Describe(AppPolicy p) =>
        $"{(p.AllowByDefault ? "allowed" : "blocked")} by default, {p.Rules.Count(r => r.Enabled)} active rule(s)";

    private bool UsesDomains => _policies.Any(p => p.Rules.Any(r => r.Enabled && r.Destination == DestinationKind.Domain));

    // ---- Watchdog ----------------------------------------------------------------------

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TickInterval);
        int cycle = 0;
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await TickAsync(++cycle % ProbeEveryNthCycle == 0, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.ApplyFailed(_log, _mode, ex);
            }
        }
    }

    private async Task TickAsync(bool probe, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        IsolationMode mode;
        IPEndPoint? target;
        try
        {
            mode = _mode;
            if (_needsApply)
            {
                ApplyLocked(mode);   // throws (and retries next cycle) until the firewall is ready
                Log.Repaired(_log, mode);
            }
            if (_needsApplyApps) ApplyAppsLocked();

            if (_networkChanged && mode == IsolationMode.Local)
            {
                _networkChanged = false;
                ApplyLocked(mode);
                Log.NetworkChanged(_log);
            }

            // Domain rules follow the addresses apps actually resolve.
            if (UsesDomains && _dns.Refresh(DnsInterval)) ApplyAppsLocked();

            var policy = ServicePolicy.Load();
            var active = mode == IsolationMode.None ? _appSpecs : _specs.Concat(_appSpecs).ToList();

            // Full check only when Windows reports a firewall change, after a problem, or every 30 s.
            bool due = _watcher.TakeChanged() || _health != BlockHealth.Ok || DateTime.UtcNow - _lastFullVerify > BackstopInterval;
            if (due && active.Count > 0)
            {
                _lastFullVerify = DateTime.UtcNow;
                string? problem = _firewall.Verify(active);
                if (problem is not null) Heal(mode, problem, policy.SelfHeal);
            }
            Stamp();

            if (!probe || policy.Probe is null) return;
            if (mode is not (IsolationMode.Internet or IsolationMode.All)) return;
            if (!FirewallPlan.ShouldDrop(mode, policy.Probe.Address)) return; // target must be one we block
            target = policy.Probe;
        }
        finally
        {
            _gate.Release();
        }

        // Probe outside the lock so a slow timeout never delays a change.
        if (await Network.ProbeLeaksAsync(target, ct).ConfigureAwait(false))
        {
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_mode == mode)
                {
                    _health = BlockHealth.Bypassed;
                    Log.ProbeLeaked(_log, mode, target);
                }
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    private void Heal(IsolationMode mode, string problem, bool selfHeal)
    {
        Log.TamperDetected(_log, mode, problem);
        if (!selfHeal)
        {
            _health = BlockHealth.Bypassed;
            Log.Bypassed(_log, mode, problem);
            return;
        }
        _firewall.EnsureFirewallOn();
        if (mode != IsolationMode.None) _firewall.Reconcile(_specs, FirewallPlan.IsKillSwitchRule);
        _firewall.Reconcile(_appSpecs, AppRuleEngine.IsAppRule);
        var active = mode == IsolationMode.None ? _appSpecs : _specs.Concat(_appSpecs).ToList();
        string? still = _firewall.Verify(active);
        if (still is null)
        {
            if (_health == BlockHealth.Ok) _health = BlockHealth.Repaired;
            Log.Repaired(_log, mode);
        }
        else
        {
            _health = BlockHealth.Bypassed;
            Log.Bypassed(_log, mode, still);
        }
    }

    private void ApplyLocked(IsolationMode mode)
    {
        _needsApply = true; // cleared only once the rules are fully in place
        _infrastructure = Network.Infrastructure();
        var specs = FirewallPlan.Build(mode, _infrastructure);
        if (mode != IsolationMode.None) _firewall.EnsureFirewallOn();
        _firewall.Reconcile(specs, FirewallPlan.IsKillSwitchRule);
        _specs = specs;
        _mode = mode;
        _health = BlockHealth.Ok;
        _needsApply = false;
        Stamp();
    }

    private void ApplyAppsLocked()
    {
        _needsApplyApps = true;
        var specs = _policies.SelectMany(p => AppRuleEngine.Compile(p, _dns.Resolve)).ToList();
        if (specs.Count > 0) _firewall.EnsureFirewallOn();
        _firewall.Reconcile(specs, AppRuleEngine.IsAppRule);
        _appSpecs = specs;
        _needsApplyApps = false;
    }

    private void Stamp() => Interlocked.Exchange(ref _checkedUnixMs, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    private void OnNetworkChanged(object? sender, EventArgs e) => _networkChanged = true;
}
