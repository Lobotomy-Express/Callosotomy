namespace Callosotomy.Core;

/// <summary>What is currently cut off.</summary>
public enum IsolationMode
{
    /// <summary>Nothing blocked.</summary>
    None = 0,
    /// <summary>Internet blocked; local network still reachable.</summary>
    Internet = 1,
    /// <summary>Local network blocked; internet (via gateway) still reachable.</summary>
    Local = 2,
    /// <summary>Every remote address blocked in both directions.</summary>
    All = 3,
}

/// <summary>Health of an active block as seen by the service.</summary>
public enum BlockHealth
{
    /// <summary>Rules present, firewall on, probe (if any) failed as expected.</summary>
    Ok = 0,
    /// <summary>Rules or firewall were tampered with and have been restored.</summary>
    Repaired = 1,
    /// <summary>Traffic got through, or the block could not be restored.</summary>
    Bypassed = 2,
}

public static class IsolationModeExtensions
{
    /// <summary>
    /// True when <paramref name="target"/> blocks at least everything <paramref name="current"/> blocks.
    /// Moving to a mode that covers the current one only ever tightens protection.
    /// </summary>
    public static bool Covers(this IsolationMode target, IsolationMode current) =>
        target == current || target == IsolationMode.All || current == IsolationMode.None;
}
