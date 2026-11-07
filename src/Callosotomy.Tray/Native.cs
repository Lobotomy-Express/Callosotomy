using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Callosotomy.Tray;

internal static partial class Native
{
    // DWM
    public const int DwmwaUseImmersiveDarkMode = 20;
    public const int DwmwaWindowCornerPreference = 33;
    public const int DwmwaSystemBackdropType = 38;
    public const int DwmwcpRound = 2;
    public const int DwmsbtTransientWindow = 3; // acrylic

    [LibraryImport("dwmapi.dll")]
    public static partial int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public static bool SetDwm(IntPtr hwnd, int attribute, int value) =>
        DwmSetWindowAttribute(hwnd, attribute, ref value, sizeof(int)) == 0;

    // Capture exclusion, so the frosted orb never blurs itself.
    public const uint WdaExcludeFromCapture = 0x11;

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);

    // Global hotkey
    public const int WmHotkey = 0x0312;
    public const uint ModAlt = 0x1, ModControl = 0x2, ModNoRepeat = 0x4000;

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool RegisterHotKey(IntPtr hwnd, int id, uint modifiers, uint vk);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool UnregisterHotKey(IntPtr hwnd, int id);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DestroyIcon(IntPtr icon);

    // Pipe server identity check
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    // Service Control Manager: ask Windows which process is running the registered service.
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenSCManager(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenService(IntPtr scm, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryServiceStatusEx(IntPtr service, int infoLevel, byte* buffer, uint size, out uint needed);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);

    /// <summary>
    /// Process ID of a running service, straight from the Service Control Manager, or 0.
    /// Works for standard users (they hold SERVICE_QUERY_STATUS by default) and only an
    /// administrator can change which executable the service runs.
    /// </summary>
    public static unsafe uint ServiceProcessId(string serviceName)
    {
        IntPtr scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return 0;
        try
        {
            IntPtr svc = OpenService(scm, serviceName, ServiceQueryStatus);
            if (svc == IntPtr.Zero) return 0;
            try
            {
                // SERVICE_STATUS_PROCESS: 9 DWORDs; dwProcessId is the 8th (offset 28).
                byte* buffer = stackalloc byte[36];
                return QueryServiceStatusEx(svc, ScStatusProcessInfo, buffer, 36, out _)
                    ? *(uint*)(buffer + 28)
                    : 0;
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    // Console attach for the command-line interface of a WinExe.
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool AttachConsole(int processId);
}
