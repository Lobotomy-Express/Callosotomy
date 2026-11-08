using System.Text.Json;
using Callosotomy.Core;
using Microsoft.Win32;

namespace Callosotomy.Service;

/// <summary>
/// App policies, stored as JSON in HKLM\SOFTWARE\Callosotomy\Rules, a key only administrators
/// and SYSTEM can write. Anything that fails validation on load is dropped rather than applied.
/// </summary>
internal static class AppPolicyStore
{
    private const string Key = @"SOFTWARE\Callosotomy\Rules";

    public static List<AppPolicy> Load()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Key);
        if (key?.GetValue("Policies") is not string json || json.Length == 0) return new();
        try
        {
            var list = JsonSerializer.Deserialize(json, CallosotomyJson.Default.ListAppPolicy) ?? new();
            return list
                .Where(p => AppRuleLimits.Validate(p) is null && !ProtectedApps.IsProtected(p.Identity))
                .GroupBy(p => p.Identity.Key).Select(g => g.Last())
                .Take(AppRuleLimits.MaxPolicies)
                .ToList();
        }
        catch (JsonException)
        {
            return new();
        }
    }

    public static void Save(IReadOnlyCollection<AppPolicy> policies)
    {
        string json = JsonSerializer.Serialize(policies.ToList(), CallosotomyJson.Default.ListAppPolicy);
        using var key = Registry.LocalMachine.CreateSubKey(Key, writable: true);
        key.SetValue("Policies", json, RegistryValueKind.String);
    }
}

/// <summary>
/// Apps that can never be given rules: Callosotomy itself, Microsoft Defender, Windows Update and
/// core networking. Stops malware running as the user from using app rules to blind the PC.
/// </summary>
internal static class ProtectedApps
{
    private static readonly HashSet<string> Services = new(StringComparer.OrdinalIgnoreCase)
    {
        "Callosotomy", "WinDefend", "WdNisSvc", "Sense", "SecurityHealthService", "MpsSvc", "BFE",
        "Dnscache", "Dhcp", "NlaSvc", "nsi", "netprofm", "Netman", "wuauserv", "UsoSvc", "WaaSMedicSvc",
        "CryptSvc", "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "EventLog", "Winmgmt", "W32Time",
    };

    private static readonly HashSet<string> SystemPrograms = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "smss.exe", "csrss.exe", "winlogon.exe",
        "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe", "MpDefenderCoreService.exe", "SecurityHealthService.exe",
    };

    private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string Self = AppContext.BaseDirectory.TrimEnd('\\');

    private static readonly string[] ProtectedFolders =
    {
        Self,
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender"),
    };

    /// <summary>Identity keys shown as locked in the monitor (programs are matched by rule, not listed).</summary>
    public static IReadOnlyList<string> ListedKeys { get; } =
        Services.Select(s => new AppIdentity(AppKind.Service, s).Key).Append("p:SYSTEM").ToList();

    public static bool IsProtected(AppIdentity id)
    {
        ArgumentNullException.ThrowIfNull(id);
        switch (id.Kind)
        {
            case AppKind.Service:
                return Services.Contains(id.Value);
            case AppKind.Program:
                string path = id.Value;
                if (path.Equals("System", StringComparison.OrdinalIgnoreCase)) return true;
                string? dir = Path.GetDirectoryName(path);
                string file = Path.GetFileName(path);
                if (dir is not null && dir.StartsWith(Windows, StringComparison.OrdinalIgnoreCase) && SystemPrograms.Contains(file))
                    return true;
                if (SystemPrograms.Contains(file) && file.StartsWith("Mp", StringComparison.OrdinalIgnoreCase)) return true;
                return ProtectedFolders.Any(f => path.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase));
            default:
                return false;
        }
    }
}
