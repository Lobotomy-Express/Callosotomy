using System.Text.Json;
using System.Text.Json.Serialization;

namespace Callosotomy.Core;

/// <summary>One live connection or listening socket, as the service reports it to the monitor.</summary>
public sealed record ConnectionInfo
{
    public int Pid { get; init; }
    public required AppIdentity App { get; init; }
    public string DisplayName { get; init; } = "";
    /// <summary>"TCP" or "UDP".</summary>
    public string Protocol { get; init; } = "TCP";
    public string LocalAddress { get; init; } = "";
    public int LocalPort { get; init; }
    public string RemoteAddress { get; init; } = "";
    public int RemotePort { get; init; }
    /// <summary>"Established", "Listening" or "Open" (UDP).</summary>
    public string State { get; init; } = "";
    /// <summary>True when someone else connected to this PC.</summary>
    public bool Inbound { get; init; }
    /// <summary>Host name from the DNS cache, if known. Untrusted text.</summary>
    public string? Host { get; init; }
    /// <summary>Bytes sent and received in the last two minutes (event stream only; 0 if unknown).</summary>
    public long BytesSent { get; init; }
    public long BytesReceived { get; init; }
    /// <summary>Seconds since the last packet, when known from the event stream.</summary>
    public int? SecondsAgo { get; init; }
}

/// <summary>Everything the monitor needs in one response.</summary>
public sealed record ConnectionSnapshot
{
    public IReadOnlyList<ConnectionInfo> Connections { get; init; } = Array.Empty<ConnectionInfo>();
    public bool Truncated { get; init; }
    /// <summary>True when the kernel event stream is running (UDP destinations and short connections included).</summary>
    public bool LiveEvents { get; init; }
}

/// <summary>Stored policies plus what the current user may do with them.</summary>
public sealed record PolicySnapshot
{
    public IReadOnlyList<AppPolicy> Policies { get; init; } = Array.Empty<AppPolicy>();
    /// <summary>Identity keys of apps that can't be blocked (security software, core networking).</summary>
    public IReadOnlyList<string> Protected { get; init; } = Array.Empty<string>();
    /// <summary>The caller may create or tighten rules.</summary>
    public bool CanEdit { get; init; }
    /// <summary>The caller may also loosen rules (allow something that was blocked).</summary>
    public bool CanLoosen { get; init; }
}

[JsonSourceGenerationOptions(
    UseStringEnumConverter = true,
    MaxDepth = 16,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ConnectionSnapshot))]
[JsonSerializable(typeof(PolicySnapshot))]
[JsonSerializable(typeof(AppPolicy))]
[JsonSerializable(typeof(AppIdentity))]
[JsonSerializable(typeof(List<AppPolicy>))]
public sealed partial class CallosotomyJson : JsonSerializerContext;
