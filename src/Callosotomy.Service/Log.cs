using Callosotomy.Core;
using Microsoft.Extensions.Logging;

namespace Callosotomy.Service;

/// <summary>
/// Every event the service writes to the Windows Application log. IDs are stable so SIEM rules can key on them.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Callosotomy protection service started. Restored mode: {Mode}.")]
    public static partial void Started(ILogger logger, IsolationMode mode);

    [LoggerMessage(EventId = 1100, Level = LogLevel.Warning, Message = "Isolation mode changed from {From} to {To} by {User}.")]
    public static partial void ModeChanged(ILogger logger, IsolationMode from, IsolationMode to, string user);

    [LoggerMessage(EventId = 1101, Level = LogLevel.Information, Message = "Dropped {Count} established connection(s) after switching to {Mode}.")]
    public static partial void ConnectionsDropped(ILogger logger, int count, IsolationMode mode);

    [LoggerMessage(EventId = 1102, Level = LogLevel.Information, Message = "Network configuration changed; local-mode rules recalculated.")]
    public static partial void NetworkChanged(ILogger logger);

    [LoggerMessage(EventId = 1200, Level = LogLevel.Error, Message = "TAMPERING DETECTED while in {Mode}: {Detail}.")]
    public static partial void TamperDetected(ILogger logger, IsolationMode mode, string detail);

    [LoggerMessage(EventId = 1201, Level = LogLevel.Warning, Message = "Block for {Mode} was restored after tampering.")]
    public static partial void Repaired(ILogger logger, IsolationMode mode);

    [LoggerMessage(EventId = 1300, Level = LogLevel.Critical, Message = "BLOCK BYPASSED in {Mode}: {Detail}. Disconnect this machine physically.")]
    public static partial void Bypassed(ILogger logger, IsolationMode mode, string detail);

    [LoggerMessage(EventId = 1400, Level = LogLevel.Warning, Message = "Denied request '{Request}' from {User}: {Reason}.")]
    public static partial void Denied(ILogger logger, string request, string user, string reason);

    [LoggerMessage(EventId = 1401, Level = LogLevel.Critical, Message = "Could not create the control pipe; another process may be impersonating the service.")]
    public static partial void PipeSquatted(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 1402, Level = LogLevel.Warning, Message = "Control client dropped: {Kind}: {Detail}")]
    public static partial void ClientDropped(ILogger logger, string kind, string detail);

    [LoggerMessage(EventId = 1403, Level = LogLevel.Error, Message = "Could not identify the control client; request refused.")]
    public static partial void IdentifyFailed(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 1500, Level = LogLevel.Error, Message = "Failed to apply {Mode}.")]
    public static partial void ApplyFailed(ILogger logger, IsolationMode mode, Exception ex);

    [LoggerMessage(EventId = 1501, Level = LogLevel.Error, Message = "Control request failed.")]
    public static partial void RequestFailed(ILogger logger, Exception ex);
}
