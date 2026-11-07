using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Callosotomy.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Callosotomy.Service;

/// <summary>
/// Local control channel, a named pipe hardened against the usual named-pipe attacks:
/// <list type="bullet">
/// <item>Squatting: the service only ever creates the pipe as its first instance, and always keeps
/// a waiting instance open, so the name can never be taken over and later "joined".</item>
/// <item>Remote use: the ACL denies the NETWORK group, and network-logon callers are refused
/// again in code unless they are administrators.</item>
/// <item>Hogging: a short read timeout and a per-process connection cap stop one program from
/// tying up every slot and jamming the kill switch.</item>
/// </list>
/// One short command per connection; anything malformed is rejected and logged.
/// </summary>
internal sealed partial class ControlServer : BackgroundService
{
    private const int MaxInstances = 16;
    private const int MaxPerProcess = 2;
    private static readonly TimeSpan ClientTimeout = TimeSpan.FromSeconds(2);
    private static readonly SecurityIdentifier NetworkSid = new(WellKnownSidType.NetworkSid, null);

    private readonly Guardian _guardian;
    private readonly ILogger<ControlServer> _log;
    private readonly Dictionary<uint, int> _perProcess = new();
    private readonly SemaphoreSlim _slots = new(MaxInstances - 1, MaxInstances - 1);

    public ControlServer(Guardian guardian, ILogger<ControlServer> log)
    {
        _guardian = guardian;
        _log = log;
    }

    public override void Dispose()
    {
        _slots.Dispose();
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Claim the name as the very first instance. If something else already holds it, keep
        // trying with FirstPipeInstance: never fall back to joining a pipe someone else created.
        NamedPipeServerStream? waiting = null;
        while (waiting is null && !stoppingToken.IsCancellationRequested)
        {
            try
            {
                waiting = CreateInstance(first: true);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                Log.PipeSquatted(_log, ex);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
            }
        }

        while (!stoppingToken.IsCancellationRequested && waiting is not null)
        {
            try
            {
                await waiting.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                Log.ClientDropped(_log, ex.GetType().Name, ex.Message);
                // Replace the broken instance, creating the new one first so the name stays ours.
                var broken = waiting;
                waiting = await NextInstanceAsync(stoppingToken).ConfigureAwait(false);
                await broken.DisposeAsync().ConfigureAwait(false);
                _slots.Release();
                continue;
            }

            var connected = waiting;
            // Open the next instance *before* handing this one off, so one of ours always exists.
            waiting = await NextInstanceAsync(stoppingToken).ConfigureAwait(false);
            _ = ServeAsync(connected, stoppingToken);
        }

        if (waiting is not null) await waiting.DisposeAsync().ConfigureAwait(false);
    }

    private async Task<NamedPipeServerStream?> NextInstanceAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _slots.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    return CreateInstance(first: false);
                }
                catch
                {
                    _slots.Release();
                    throw;
                }
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (IOException)
            {
                await Task.Delay(200, ct).ConfigureAwait(false);
            }
        }
        return null;
    }

    private static NamedPipeServerStream CreateInstance(bool first)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(NetworkSid, PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        var options = PipeOptions.Asynchronous | PipeOptions.WriteThrough;
        if (first) options |= PipeOptions.FirstPipeInstance;

        return NamedPipeServerStreamAcl.Create(
            Protocol.PipeName, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte, options,
            inBufferSize: Protocol.MaxLineBytes, outBufferSize: Protocol.MaxLineBytes, security);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        uint pid = 0;
        bool counted = false;
        try
        {
            await using (pipe.ConfigureAwait(false))
            {
                if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid)) pid = 0;
                lock (_perProcess)
                {
                    _perProcess.TryGetValue(pid, out int n);
                    if (pid != 0 && n >= MaxPerProcess)
                    {
                        Log.ClientDropped(_log, "Throttled", $"process {pid} already has {n} open connections");
                        return;
                    }
                    _perProcess[pid] = n + 1;
                    counted = true;
                }

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(ClientTimeout);
                await HandleAsync(pipe, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException)
        {
            Log.ClientDropped(_log, ex.GetType().Name, ex.Message);
        }
        catch (Exception ex)
        {
            Log.RequestFailed(_log, ex);
        }
        finally
        {
            if (counted)
            {
                lock (_perProcess)
                {
                    if (--_perProcess[pid] <= 0) _perProcess.Remove(pid);
                }
            }
            _slots.Release();
        }
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        string? line = await ReadLineAsync(pipe, ct).ConfigureAwait(false);

        // Identify the caller from the kernel, never from anything it sends.
        string user = "unknown";
        bool isAdmin = false, isNetwork = false, identified = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                using var id = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                user = id.Name;
                isAdmin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                isNetwork = id.Groups?.Contains(NetworkSid) == true;
            });
            identified = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.IdentifyFailed(_log, ex);
        }

        string reply;
        if (!identified)
        {
            reply = Protocol.FormatError(ProtocolErrors.Denied);
        }
        else if (isNetwork && !isAdmin)
        {
            // Defence in depth: the ACL already denies network logons.
            Log.Denied(_log, Sanitize(line), user, "network callers must be administrators");
            reply = Protocol.FormatError(ProtocolErrors.Denied);
        }
        else
        {
            reply = await DecideAsync(line, user, isAdmin, ct).ConfigureAwait(false);
        }

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

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint processId);
}
