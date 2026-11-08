using System;
using System.Globalization;
using System.IO;

namespace Callosotomy.Tray;

/// <summary>
/// Writes unexpected errors to %LOCALAPPDATA%\Callosotomy\error.log (kept under 256 KB),
/// so problems can be diagnosed instead of disappearing silently. Contains only exception
/// details, never network data.
/// </summary>
internal static class ErrorLog
{
    public static string PathName { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Callosotomy", "error.log");

    public static void Write(Exception ex)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PathName)!);
            var info = new FileInfo(PathName);
            if (info.Exists && info.Length > 256 * 1024) info.Delete();
            File.AppendAllText(PathName, string.Create(CultureInfo.InvariantCulture,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] v{typeof(ErrorLog).Assembly.GetName().Version}\n{ex}\n\n"));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
