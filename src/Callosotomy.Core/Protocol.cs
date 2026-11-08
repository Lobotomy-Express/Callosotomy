using System.Globalization;

namespace Callosotomy.Core;

/// <summary>
/// The whole control protocol: one short ASCII line each way. Anything that does not parse
/// exactly is rejected, so there is nothing for a hostile client to exploit beyond the five commands.
/// </summary>
public static class Protocol
{
    public const string PipeName = "Callosotomy.Control.v1";
    public const int MaxLineBytes = 128;

    public enum Verb { Status, Set, Connections, Policies, Put, Delete }

    /// <summary>Largest JSON body a client may send (one policy).</summary>
    public const int MaxRequestBody = 64 * 1024;

    /// <summary>Largest JSON body the service sends (connection snapshot or policy list).</summary>
    public const int MaxResponseBody = 4 * 1024 * 1024;

    /// <summary>A request. Put and Delete are followed by <see cref="BodyLength"/> bytes of JSON.</summary>
    public readonly record struct Request(Verb Verb, IsolationMode Mode, int BodyLength = 0);

    public readonly record struct Status(IsolationMode Mode, BlockHealth Health, long CheckedUnixMs);

    public static string FormatStatusRequest() => "STATUS";

    public static string FormatSetRequest(IsolationMode mode) => "SET " + ModeName(mode);

    public static bool TryParseRequest(string? line, out Request request)
    {
        request = default;
        if (line is null || line.Length > MaxLineBytes) return false;
        if (line == "STATUS") { request = new(Verb.Status, IsolationMode.None); return true; }
        if (line == "CONNS") { request = new(Verb.Connections, IsolationMode.None); return true; }
        if (line == "POLICIES") { request = new(Verb.Policies, IsolationMode.None); return true; }
        foreach (var (prefix, verb) in new[] { ("PUT ", Verb.Put), ("DEL ", Verb.Delete) })
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal)
                && int.TryParse(line.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out int len)
                && len is > 0 and <= MaxRequestBody
                && line.Length == prefix.Length + len.ToString(CultureInfo.InvariantCulture).Length)
            {
                request = new(verb, IsolationMode.None, len);
                return true;
            }
        }
        if (line.StartsWith("SET ", StringComparison.Ordinal) && TryParseMode(line[4..], out var mode))
        {
            request = new(Verb.Set, mode);
            return true;
        }
        return false;
    }

    public static string FormatOk(Status s) =>
        string.Create(CultureInfo.InvariantCulture, $"OK {ModeName(s.Mode)} {HealthName(s.Health)} {s.CheckedUnixMs}");

    public static string FormatError(string code) => "ERR " + code;

    public static string FormatDataHeader(int length) =>
        "DATA " + length.ToString(CultureInfo.InvariantCulture);

    public static string FormatBodyHeader(Verb verb, int length) => verb switch
    {
        Verb.Put => "PUT " + length.ToString(CultureInfo.InvariantCulture),
        Verb.Delete => "DEL " + length.ToString(CultureInfo.InvariantCulture),
        _ => throw new ArgumentOutOfRangeException(nameof(verb)),
    };

    /// <summary>Parses "DATA n" (a JSON body of n bytes follows).</summary>
    public static bool TryParseDataHeader(string? line, out int length)
    {
        length = 0;
        return line is not null && line.StartsWith("DATA ", StringComparison.Ordinal)
            && int.TryParse(line.AsSpan(5), NumberStyles.None, CultureInfo.InvariantCulture, out length)
            && length is >= 0 and <= MaxResponseBody;
    }

    /// <summary>Parses a server reply. Errors come back as <c>false</c> with <paramref name="error"/> set.</summary>
    public static bool TryParseResponse(string? line, out Status status, out string? error)
    {
        status = default;
        error = null;
        if (line is null || line.Length > MaxLineBytes) { error = "malformed"; return false; }
        if (line.StartsWith("ERR ", StringComparison.Ordinal)) { error = line[4..]; return false; }

        var parts = line.Split(' ');
        if (parts.Length == 4 && parts[0] == "OK"
            && TryParseMode(parts[1], out var mode)
            && TryParseHealth(parts[2], out var health)
            && long.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out long ms))
        {
            status = new(mode, health, ms);
            return true;
        }
        error = "malformed";
        return false;
    }

    public static string ModeName(IsolationMode mode) => mode switch
    {
        IsolationMode.None => "NONE",
        IsolationMode.Internet => "INTERNET",
        IsolationMode.Local => "LOCAL",
        IsolationMode.All => "ALL",
        _ => throw new ArgumentOutOfRangeException(nameof(mode)),
    };

    public static bool TryParseMode(string text, out IsolationMode mode)
    {
        switch (text)
        {
            case "NONE": mode = IsolationMode.None; return true;
            case "INTERNET": mode = IsolationMode.Internet; return true;
            case "LOCAL": mode = IsolationMode.Local; return true;
            case "ALL": mode = IsolationMode.All; return true;
            default: mode = default; return false;
        }
    }

    private static string HealthName(BlockHealth h) => h switch
    {
        BlockHealth.Ok => "OK",
        BlockHealth.Repaired => "REPAIRED",
        BlockHealth.Bypassed => "BYPASSED",
        _ => throw new ArgumentOutOfRangeException(nameof(h)),
    };

    private static bool TryParseHealth(string text, out BlockHealth health)
    {
        switch (text)
        {
            case "OK": health = BlockHealth.Ok; return true;
            case "REPAIRED": health = BlockHealth.Repaired; return true;
            case "BYPASSED": health = BlockHealth.Bypassed; return true;
            default: health = default; return false;
        }
    }
}

/// <summary>Error codes the service can return.</summary>
public static class ProtocolErrors
{
    public const string BadRequest = "bad-request";
    public const string Denied = "denied";
    public const string ModeDisabled = "mode-disabled";
    public const string Failed = "failed";
    public const string Invalid = "invalid";
    public const string Protected = "protected";
    public const string Limit = "limit";
}
