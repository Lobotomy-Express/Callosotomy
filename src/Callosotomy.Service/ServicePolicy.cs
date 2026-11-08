using System.Globalization;
using System.Net;
using Callosotomy.Core;
using Microsoft.Win32;

namespace Callosotomy.Service;

/// <summary>
/// Settings read from HKLM. Group Policy (HKLM\SOFTWARE\Policies\Callosotomy) wins over
/// local settings (HKLM\SOFTWARE\Callosotomy). Both keys are writable only by administrators.
/// </summary>
internal sealed record ServicePolicy
{
    public const string PolicyKey = @"SOFTWARE\Policies\Callosotomy";
    public const string SettingsKey = @"SOFTWARE\Callosotomy";

    public bool AllowUsersToIsolate { get; init; } = true;
    public bool AllowUserRestore { get; init; } = true;
    public bool AllowUserAppRules { get; init; } = true;
    public bool AllowInternetMode { get; init; } = true;
    public bool AllowLocalMode { get; init; } = true;
    public bool AllowAllMode { get; init; } = true;
    public bool SelfHeal { get; init; } = true;
    public bool DropConnections { get; init; } = true;
    public IPEndPoint? Probe { get; init; } = new(IPAddress.Parse("1.1.1.1"), 443);

    public bool IsAllowed(IsolationMode mode) => mode switch
    {
        IsolationMode.None => true,
        IsolationMode.Internet => AllowInternetMode,
        IsolationMode.Local => AllowLocalMode,
        IsolationMode.All => AllowAllMode,
        _ => false,
    };

    public static ServicePolicy Load()
    {
        using var policy = Registry.LocalMachine.OpenSubKey(PolicyKey);
        using var local = Registry.LocalMachine.OpenSubKey(SettingsKey);
        var d = new ServicePolicy();

        bool Flag(string name, bool fallback)
        {
            object? v = policy?.GetValue(name) ?? local?.GetValue(name);
            return v is int i ? i != 0 : fallback;
        }

        IPEndPoint? probe = d.Probe;
        if (Flag("ProbeEnabled", true))
        {
            // Must be an IP literal: DNS is blocked while isolated, so a name could never resolve.
            if ((policy?.GetValue("ProbeTarget") ?? local?.GetValue("ProbeTarget")) is string s
                && IPEndPoint.TryParse(s, out var ep) && ep.Port != 0)
            {
                probe = ep;
            }
        }
        else
        {
            probe = null;
        }

        return d with
        {
            AllowUsersToIsolate = Flag("AllowUsersToIsolate", d.AllowUsersToIsolate),
            AllowUserRestore = Flag("AllowUserRestore", d.AllowUserRestore),
            AllowUserAppRules = Flag("AllowUserAppRules", d.AllowUserAppRules),
            AllowInternetMode = Flag("AllowInternetMode", d.AllowInternetMode),
            AllowLocalMode = Flag("AllowLocalMode", d.AllowLocalMode),
            AllowAllMode = Flag("AllowAllMode", d.AllowAllMode),
            SelfHeal = Flag("SelfHeal", d.SelfHeal),
            DropConnections = Flag("DropConnections", d.DropConnections),
            Probe = probe,
        };
    }
}

/// <summary>Remembers the active mode so a reboot or service restart re-applies it.</summary>
internal static class StateStore
{
    private const string Key = @"SOFTWARE\Callosotomy\State";

    public static IsolationMode Load()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Key);
        return key?.GetValue("Mode") is int i && Enum.IsDefined(typeof(IsolationMode), i)
            ? (IsolationMode)i
            : IsolationMode.None;
    }

    public static void Save(IsolationMode mode)
    {
        using var key = Registry.LocalMachine.CreateSubKey(Key, writable: true);
        key.SetValue("Mode", (int)mode, RegistryValueKind.DWord);
        key.SetValue("ChangedUtc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture), RegistryValueKind.String);
    }

    public static void Clear() =>
        Registry.LocalMachine.DeleteSubKeyTree(Key, throwOnMissingSubKey: false);
}
