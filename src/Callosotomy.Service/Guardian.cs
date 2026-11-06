using System.Net;
using System.Net.NetworkInformation;
using Callosotomy.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Callosotomy.Service;

/// <summary>
/// Owns the isolation state. Applies modes, re-checks the block every few seconds,
/// repairs tampering and raises the alarm when traffic gets through.
/// </summary>
internal sealed class Guardian : BackgroundService
{
    private static readonly TimeSpan VerifyInterval = TimeSpan.FromSeconds(3);
    private const int ProbeEveryNthCycle = 4; // ~12 s

    private readonly FirewallBackend _firewall;
    private readonly ILogger<Guardian> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private IsolationMode _mode;
    private BlockHealth _health;
    private long _checkedUnixMs;
    private IReadOnlyList<IPAddress> _infrastructure = Array.Empty<IPAddress>();
    private IReadOnlyList<RuleSpec> _specs = Array.Empty<RuleSpec>();
    private volatile bool _networkChanged;

    public Guardian(FirewallBackend firewall, ILogger<Guardian> log)
    {
        _firewall = firewall;
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
            ApplyLocked(restored);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.ApplyFailed(_log, restored, ex);
            _mode = restored;
            _health = BlockHealth.Bypassed;
        }
        finally
        {
            _gate.Release();
        }

        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        Log.Started(_log, restored);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        // Rules are deliberately left in place: stopping the service must never lift a block.
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        return base.StopAsync(cancellationToken);
    }

    public override void Dispose()
    {
        _gate.Dispose();
        base.Dispose();
    }

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

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(VerifyInterval);
        int cycle = 0;
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await VerifyAsync(++cycle % ProbeEveryNthCycle == 0, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.ApplyFailed(_log, _mode, ex);
            }
        }
    }

    private async Task VerifyAsync(bool probe, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        IsolationMode mode;
        IPEndPoint? target;
        try
        {
            mode = _mode;
            if (mode == IsolationMode.None) { Stamp(); return; }

            if (_networkChanged && mode == IsolationMode.Local)
            {
                _networkChanged = false;
                ApplyLocked(mode);
                Log.NetworkChanged(_log);
            }

            var policy = ServicePolicy.Load();
            string? problem = _firewall.Verify(_specs);
            if (problem is not null)
            {
                Log.TamperDetected(_log, mode, problem);
                if (policy.SelfHeal)
                {
                    _firewall.EnsureFirewallOn();
                    _firewall.Reconcile(_specs);
                    string? still = _firewall.Verify(_specs);
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
                else
                {
                    _health = BlockHealth.Bypassed;
                    Log.Bypassed(_log, mode, problem);
                }
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

        // Probe outside the lock so a slow timeout never delays a mode change.
        if (await Network.ProbeLeaksAsync(target, ct).ConfigureAwait(false))
        {
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_mode == mode)
                {
                    _health = BlockHealth.Bypassed;
                    Log.Bypassed(_log, mode, $"a test connection to {target} succeeded");
                }
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    private void ApplyLocked(IsolationMode mode)
    {
        _infrastructure = Network.Infrastructure();
        var specs = FirewallPlan.Build(mode, _infrastructure);
        if (mode != IsolationMode.None) _firewall.EnsureFirewallOn();
        _firewall.Reconcile(specs);
        _specs = specs;
        _mode = mode;
        _health = BlockHealth.Ok;
        Stamp();
    }

    private void Stamp() => Interlocked.Exchange(ref _checkedUnixMs, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    private void OnNetworkChanged(object? sender, EventArgs e) => _networkChanged = true;
}
