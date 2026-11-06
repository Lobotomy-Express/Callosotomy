using System;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Callosotomy.Core;
using Microsoft.Win32;

namespace Callosotomy.Tray;

internal readonly record struct ServiceReply(bool Reachable, bool Ok, Protocol.Status Status, string? Error);

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

    private static void VerifyServer(NamedPipeClientStream pipe)
    {
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pid))
            throw new SecurityException("Cannot identify pipe server.");

        string? actual = Native.ProcessImagePath(pid);
        string? expected = InstalledServicePath();
        if (actual is null || expected is null
            || !string.Equals(Path.GetFullPath(actual), Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("Pipe server is not the installed Callosotomy service.");
        }
    }

    /// <summary>The service executable as registered with Windows (admin-only key).</summary>
    private static string? InstalledServicePath()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Callosotomy");
        if (key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string raw) return null;
        raw = Environment.ExpandEnvironmentVariables(raw.Trim());
        if (raw.StartsWith('"'))
        {
            int end = raw.IndexOf('"', 1);
            return end > 1 ? raw[1..end] : null;
        }
        int exe = raw.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? raw[..(exe + 4)] : raw;
    }
}
