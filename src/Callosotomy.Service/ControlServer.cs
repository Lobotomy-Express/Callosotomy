using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
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
    private static readonly TimeSpan ClientTimeout = TimeSpan.FromSeconds(4);
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
            inBufferSize: 4096, outBufferSize: 64 * 1024, security);
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
        byte[]? body = null;
        if (Protocol.TryParseRequest(line, out var parsed) && parsed.BodyLength > 0)
            body = await ReadExactlyAsync(pipe, parsed.BodyLength, ct).ConfigureAwait(false);

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
        byte[]? data = null;
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
        else if (parsed.Verb is Protocol.Verb.Connections or Protocol.Verb.Policies or Protocol.Verb.Put or Protocol.Verb.Delete
                 && Protocol.TryParseRequest(line, out _))
        {
            uint session = GetNamedPipeClientSessionId(pipe.SafePipeHandle, out uint sid) ? sid : uint.MaxValue;
            (reply, data) = await AppRequestAsync(parsed, body, user, isAdmin, session, ct).ConfigureAwait(false);
        }
        else
        {
            reply = await DecideAsync(line, user, isAdmin, ct).ConfigureAwait(false);
        }

        byte[] bytes = Encoding.ASCII.GetBytes(reply + "\n");
        await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
        if (data is not null) await pipe.WriteAsync(data, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);
    }

    // ---- App rules --------------------------------------------------------------------

    private async Task<(string Reply, byte[]? Data)> AppRequestAsync(Protocol.Request req, byte[]? body, string user, bool isAdmin, uint session, CancellationToken ct)
    {
        var policy = ServicePolicy.Load();
        bool canEdit = isAdmin || policy.AllowUserAppRules;
        bool canLoosen = isAdmin || (policy.AllowUserAppRules && policy.AllowUserRestore);

        switch (req.Verb)
        {
            case Protocol.Verb.Connections:
                var snapshot = _guardian.Connections();
                if (!isAdmin)
                {
                    // Standard users see their own session's apps plus Windows services (session 0),
                    // never other signed-in users' programs.
                    snapshot = snapshot with
                    {
                        Connections = snapshot.Connections
                            .Where(c => ProcessIdToSessionId((uint)c.Pid, out uint s) && (s == 0 || s == session))
                            .ToList(),
                    };
                }
                return Data(JsonSerializer.SerializeToUtf8Bytes(snapshot, CallosotomyJson.Default.ConnectionSnapshot));

            case Protocol.Verb.Policies:
                return Data(await PolicyDataAsync(canEdit, canLoosen, ct).ConfigureAwait(false));
        }

        if (body is null) return (Protocol.FormatError(ProtocolErrors.BadRequest), null);
        if (!canEdit)
        {
            Log.Denied(_log, "app rules", user, "users may not change app rules");
            return (Protocol.FormatError(ProtocolErrors.Denied), null);
        }

        AppIdentity identity;
        AppPolicy? next = null;
        try
        {
            if (req.Verb == Protocol.Verb.Put)
            {
                next = JsonSerializer.Deserialize(body, CallosotomyJson.Default.AppPolicy);
                if (next is null) return (Protocol.FormatError(ProtocolErrors.BadRequest), null);
                next = next with { DisplayName = next.DisplayName ?? "", Rules = next.Rules ?? Array.Empty<AppRule>() };
                identity = next.Identity;
            }
            else
            {
                identity = JsonSerializer.Deserialize(body, CallosotomyJson.Default.AppIdentity)
                           ?? throw new JsonException("empty");
            }
        }
        catch (JsonException)
        {
            Log.Denied(_log, "app rules", user, "malformed");
            return (Protocol.FormatError(ProtocolErrors.BadRequest), null);
        }

        string? invalid = next is not null ? AppRuleLimits.Validate(next) : AppRuleLimits.ValidateIdentity(identity);
        // No File.Exists check: as SYSTEM it would let users probe for files they can't see.
        // A rule for a path that doesn't exist is harmless.
        if (invalid is null && identity.Kind == AppKind.Service && !ServiceExists(identity.Value)) invalid = "service not found";
        if (invalid is not null)
        {
            Log.Denied(_log, "app rules", user, invalid);
            return (Protocol.FormatError(ProtocolErrors.Invalid), null);
        }
        if (ProtectedApps.IsProtected(identity))
        {
            Log.Denied(_log, "app rules for " + identity.Value, user, "protected app");
            return (Protocol.FormatError(ProtocolErrors.Protected), null);
        }

        var current = await _guardian.PoliciesAsync(ct).ConfigureAwait(false);
        var previous = current.FirstOrDefault(p => p.Identity.Key == identity.Key);
        if (previous is null && next is not null && current.Count >= AppRuleLimits.MaxPolicies)
            return (Protocol.FormatError(ProtocolErrors.Limit), null);

        var effective = next ?? new AppPolicy { Identity = identity };
        if (!canLoosen && AppRuleEngine.Loosens(previous, effective, _guardian.Resolve))
        {
            Log.Denied(_log, "app rules for " + identity.Value, user, "only administrators may loosen app rules");
            return (Protocol.FormatError(ProtocolErrors.Denied), null);
        }

        try
        {
            await _guardian.ReplacePolicyAsync(identity, next, user, ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            return (Protocol.FormatError(ProtocolErrors.Limit), null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.AppApplyFailed(_log, ex);
            return (Protocol.FormatError(ProtocolErrors.Failed), null);
        }
        return Data(await PolicyDataAsync(canEdit, canLoosen, ct).ConfigureAwait(false));
    }

    private async Task<byte[]> PolicyDataAsync(bool canEdit, bool canLoosen, CancellationToken ct)
    {
        var snapshot = new PolicySnapshot
        {
            Policies = await _guardian.PoliciesAsync(ct).ConfigureAwait(false),
            Protected = ProtectedApps.ListedKeys,
            CanEdit = canEdit,
            CanLoosen = canLoosen,
        };
        return JsonSerializer.SerializeToUtf8Bytes(snapshot, CallosotomyJson.Default.PolicySnapshot);
    }

    private static (string, byte[]?) Data(byte[] json) =>
        json.Length > Protocol.MaxResponseBody
            ? (Protocol.FormatError(ProtocolErrors.Limit), null)
            : (Protocol.FormatDataHeader(json.Length), json);

    private static bool ServiceExists(string name)
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name);
        return key is not null;
    }

    private static async Task<byte[]?> ReadExactlyAsync(Stream stream, int length, CancellationToken ct)
    {
        byte[] buffer = new byte[length];
        int read = 0;
        while (read < length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read), ct).ConfigureAwait(false);
            if (n == 0) return null;
            read += n;
        }
        return buffer;
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
    private static partial bool GetNamedPipeClientSessionId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint sessionId);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint pid, out uint sessionId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint processId);
}
