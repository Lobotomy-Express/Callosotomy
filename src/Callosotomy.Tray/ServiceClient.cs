using System;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using System.Threading.Tasks;
using Callosotomy.Core;

namespace Callosotomy.Tray;

internal readonly record struct ServiceReply(bool Reachable, bool Ok, Protocol.Status Status, string? Error);

/// <summary>A JSON reply from the service, or the reason there isn't one.</summary>
internal readonly record struct DataReply<T>(T? Value, string? Error) where T : class;

/// <summary>
/// Talks to the protection service. Before sending anything it checks that the process on the
/// other end of the pipe is the installed service executable, so a malicious process that grabbed
/// the pipe name cannot fake a "you're protected" status.
/// </summary>
internal static class ServiceClient
{
    public static Task<ServiceReply> StatusAsync(CancellationToken ct = default) =>
        SendAsync(Protocol.FormatStatusRequest(), ct);

    public static Task<ServiceReply> SetAsync(IsolationMode mode, CancellationToken ct = default) =>
        SendAsync(Protocol.FormatSetRequest(mode), ct);

    public static Task<DataReply<ConnectionSnapshot>> ConnectionsAsync(CancellationToken ct = default) =>
        SendDataAsync("CONNS", null, CallosotomyJson.Default.ConnectionSnapshot, ct);

    public static Task<DataReply<PolicySnapshot>> PoliciesAsync(CancellationToken ct = default) =>
        SendDataAsync("POLICIES", null, CallosotomyJson.Default.PolicySnapshot, ct);

    public static Task<DataReply<PolicySnapshot>> PutPolicyAsync(AppPolicy policy, CancellationToken ct = default)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(policy, CallosotomyJson.Default.AppPolicy);
        return SendDataAsync(Protocol.FormatBodyHeader(Protocol.Verb.Put, body.Length), body, CallosotomyJson.Default.PolicySnapshot, ct);
    }

    public static Task<DataReply<PolicySnapshot>> DeletePolicyAsync(AppIdentity identity, CancellationToken ct = default)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(identity, CallosotomyJson.Default.AppIdentity);
        return SendDataAsync(Protocol.FormatBodyHeader(Protocol.Verb.Delete, body.Length), body, CallosotomyJson.Default.PolicySnapshot, ct);
    }

    private static async Task<DataReply<T>> SendDataAsync<T>(string line, byte[]? body, JsonTypeInfo<T> type, CancellationToken ct) where T : class
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".", Protocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);
            await pipe.ConnectAsync(1000, ct).ConfigureAwait(false);
            VerifyServer(pipe);

            await pipe.WriteAsync(Encoding.ASCII.GetBytes(line + "\n"), ct).ConfigureAwait(false);
            if (body is not null) await pipe.WriteAsync(body, ct).ConfigureAwait(false);
            await pipe.FlushAsync(ct).ConfigureAwait(false);

            // Header line, read a byte at a time so nothing of the body is consumed.
            var header = new StringBuilder();
            byte[] one = new byte[1];
            while (header.Length <= Protocol.MaxLineBytes)
            {
                if (await pipe.ReadAsync(one, ct).ConfigureAwait(false) == 0) break;
                if (one[0] == (byte)'\n') break;
                header.Append((char)one[0]);
            }
            string h = header.ToString().TrimEnd('\r');
            if (h.StartsWith("ERR ", StringComparison.Ordinal)) return new(null, h[4..]);
            if (!Protocol.TryParseDataHeader(h, out int length)) return new(null, "malformed");

            byte[] data = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = await pipe.ReadAsync(data.AsMemory(read), ct).ConfigureAwait(false);
                if (n == 0) return new(null, "malformed");
                read += n;
            }
            return new(JsonSerializer.Deserialize(data, type), null);
        }
        catch (JsonException)
        {
            return new(null, "malformed");
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            return new(null, "unreachable");
        }
        catch (SecurityException)
        {
            return new(null, "untrusted-server");
        }
    }

    private static async Task<ServiceReply> SendAsync(string line, CancellationToken ct)
    {
        try
        {
            // Impersonation level lets the service read our token to decide what we're allowed to do.
            // Safe because nothing is written until VerifyServer has proven the other end is the
            // installed SYSTEM service, and a pipe server can only impersonate after reading from us.
            using var pipe = new NamedPipeClientStream(
                ".", Protocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);
            await pipe.ConnectAsync(1000, ct).ConfigureAwait(false);
            VerifyServer(pipe);

            byte[] request = Encoding.ASCII.GetBytes(line + "\n");
            await pipe.WriteAsync(request, ct).ConfigureAwait(false);
            await pipe.FlushAsync(ct).ConfigureAwait(false);

            byte[] buffer = new byte[Protocol.MaxLineBytes + 1];
            int length = 0;
            while (length < buffer.Length)
            {
                int n = await pipe.ReadAsync(buffer.AsMemory(length), ct).ConfigureAwait(false);
                if (n == 0) break;
                length += n;
                if (Array.IndexOf(buffer, (byte)'\n', 0, length) >= 0) break;
            }
            string reply = Encoding.ASCII.GetString(buffer, 0, length).TrimEnd('\r', '\n');
            return Protocol.TryParseResponse(reply, out var status, out string? error)
                ? new ServiceReply(true, true, status, null)
                : new ServiceReply(true, false, default, error);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            return new ServiceReply(false, false, default, "unreachable");
        }
        catch (SecurityException)
        {
            return new ServiceReply(false, false, default, "untrusted-server");
        }
    }

    /// <summary>
    /// The process holding the pipe must be the one Windows' Service Control Manager says is
    /// running the Callosotomy service. A standard user can't register or repoint that service,
    /// so a squatting process can never pass this check.
    /// </summary>
    private static void VerifyServer(NamedPipeClientStream pipe)
    {
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid))
            throw new SecurityException("Cannot identify pipe server.");

        uint servicePid = Native.ServiceProcessId("Callosotomy");
        if (servicePid == 0 || servicePid != serverPid)
            throw new SecurityException("Pipe server is not the running Callosotomy service.");
    }
}
