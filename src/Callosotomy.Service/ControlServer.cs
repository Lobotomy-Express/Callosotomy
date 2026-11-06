using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Callosotomy.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Callosotomy.Service;

/// <summary>
/// Local control channel. A named pipe that:
/// - refuses network clients outright (explicit deny for the NETWORK group),
/// - lets interactive users read/write but never create pipe instances (blocks squatting),
/// - accepts one short command per connection and drops slow or oversized clients.
/// </summary>
internal sealed class ControlServer : BackgroundService
{
    private const int Listeners = 2;
    private static readonly TimeSpan ClientTimeout = TimeSpan.FromSeconds(3);

    private readonly Guardian _guardian;
    private readonly ILogger<ControlServer> _log;
    private int _firstInstanceClaimed;

    public ControlServer(Guardian guardian, ILogger<ControlServer> log)
    {
        _guardian = guardian;
        _log = log;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.WhenAll(Enumerable.Range(0, Listeners).Select(_ => ListenAsync(stoppingToken)));

    private async Task ListenAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe();
            }
            catch (UnauthorizedAccessException ex)
            {
                Log.PipeSquatted(_log, ex);
                await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                continue;
            }
            catch (IOException ex)
            {
                Log.PipeSquatted(_log, ex);
                await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                continue;
            }

            await using (pipe.ConfigureAwait(false))
            {
                try
                {
                    await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(ClientTimeout);
                    await HandleAsync(pipe, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException)
                {
                    // Client vanished or timed out. Logged so a failure is never silent.
                    Log.ClientDropped(_log, ex.GetType().Name, ex.Message);
                }
                catch (Exception ex)
                {
                    Log.RequestFailed(_log, ex);
                }
            }
        }
    }

    private NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        // The very first instance must be ours: if another process already owns the name, fail loudly.
        var options = PipeOptions.Asynchronous | PipeOptions.WriteThrough;
        if (Interlocked.Exchange(ref _firstInstanceClaimed, 1) == 0) options |= PipeOptions.FirstPipeInstance;

        return NamedPipeServerStreamAcl.Create(
            Protocol.PipeName, PipeDirection.InOut, Listeners, PipeTransmissionMode.Byte, options,
            inBufferSize: Protocol.MaxLineBytes, outBufferSize: Protocol.MaxLineBytes, security);
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        string? line = await ReadLineAsync(pipe, ct).ConfigureAwait(false);

        // Identify the caller from the kernel, never from anything it sends.
        string user = "unknown";
        bool isAdmin = false;
        bool identified = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                using var id = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                user = id.Name;
                isAdmin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            });
            identified = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.IdentifyFailed(_log, ex);
        }

        string reply = identified
            ? await DecideAsync(line, user, isAdmin, ct).ConfigureAwait(false)
            : Protocol.FormatError(ProtocolErrors.Denied);
        byte[] bytes = Encoding.ASCII.GetBytes(reply + "\n");
        await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);
    }

    private async Task<string> DecideAsync(string? line, string user, bool isAdmin, CancellationToken ct)
    {
        if (!Protocol.TryParseRequest(line, out var request))
        {
            Log.Denied(_log, Sanitize(line), user, "malformed");
            return Protocol.FormatError(ProtocolErrors.BadRequest);
        }

        if (request.Verb == Protocol.Verb.Status) return Protocol.FormatOk(_guardian.Current);

        var policy = ServicePolicy.Load();
        var target = request.Mode;
        var current = _guardian.Current.Mode;

        if (!policy.IsAllowed(target))
        {
            Log.Denied(_log, line!, user, "mode disabled by policy");
            return Protocol.FormatError(ProtocolErrors.ModeDisabled);
        }

        bool tightening = target.Covers(current);
        bool permitted = isAdmin || (tightening ? policy.AllowUsersToIsolate : policy.AllowUserRestore);
        if (!permitted)
        {
            Log.Denied(_log, line!, user, tightening ? "users may not isolate" : "only administrators may lift a block");
            return Protocol.FormatError(ProtocolErrors.Denied);
        }

        try
        {
            return Protocol.FormatOk(await _guardian.SetModeAsync(target, user, ct).ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.ApplyFailed(_log, target, ex);
            return Protocol.FormatError(ProtocolErrors.Failed);
        }
    }

    /// <summary>Reads one ASCII line, at most <see cref="Protocol.MaxLineBytes"/> bytes. Returns null on anything odd.</summary>
    private static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        byte[] buffer = new byte[Protocol.MaxLineBytes + 1];
        int length = 0;
        while (length < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(length, 1), ct).ConfigureAwait(false);
            if (n == 0) break;
            if (buffer[length] == (byte)'\n') return Encoding.ASCII.GetString(buffer, 0, length).TrimEnd('\r');
            if (buffer[length] < 0x20 || buffer[length] > 0x7E) return null;
            length++;
        }
        return null;
    }

    private static string Sanitize(string? line) =>
        line is null ? "(none)" : new string(line.Take(40).Select(c => c is >= ' ' and <= '~' ? c : '?').ToArray());
}
