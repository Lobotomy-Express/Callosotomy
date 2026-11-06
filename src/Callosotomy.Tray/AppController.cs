using System;
using System.Threading.Tasks;
using System.Windows.Interop;
using System.Windows.Threading;
using Callosotomy.Core;
using Microsoft.Win32;

namespace Callosotomy.Tray;

/// <summary>Wires the tray icon, pane, orb, hotkey and the service together.</summary>
internal sealed class AppController : IDisposable
{
    private const int HotkeyId = 0xCA11;
    private const uint VkK = 0x4B;

    private readonly DispatcherTimer _poll;
    private readonly TrayIcon _tray;
    private readonly HwndSource _messageWindow;
    private PaneWindow? _pane;
    private OrbWindow? _orb;
    private bool _polling;

    public StatusViewModel Status { get; } = new();

    public AppController()
    {
        var (forced, value) = OrbPolicy();
        Status.OrbLocked = forced;
        Status.ShowOrb = forced ? value : UserWantsOrb();

        _tray = new TrayIcon(this);

        // Invisible message-only window to receive the global hotkey.
        _messageWindow = new HwndSource(new HwndSourceParameters("CallosotomyHotkey") { ParentWindow = new IntPtr(-3) });
        _messageWindow.AddHook(WndProc);
        Native.RegisterHotKey(_messageWindow.Handle, HotkeyId, Native.ModControl | Native.ModAlt | Native.ModNoRepeat, VkK);

        _poll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _poll.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
        _poll.Start();

        if (Status.ShowOrb) ShowOrb();
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        if (_polling) return;
        _polling = true;
        try
        {
            Status.Update(await ServiceClient.StatusAsync().ConfigureAwait(true));
            _tray.Update(Status);
        }
        finally
        {
            _polling = false;
        }
    }

    public async Task SetModeAsync(IsolationMode mode)
    {
        Status.Flash(null);
        var reply = await ServiceClient.SetAsync(mode).ConfigureAwait(true);
        if (reply.Ok)
        {
            Status.Update(reply);
            _tray.Update(Status);
            return;
        }

        Status.Flash(reply.Error switch
        {
            ProtocolErrors.Denied => "Only an administrator can lift this block",
            ProtocolErrors.ModeDisabled => "That mode is turned off by your organisation",
            "untrusted-server" => "Refused: the control channel is not the real service",
            "unreachable" => "Can't reach the protection service",
            _ => "The service could not apply that change",
        });
        await RefreshAsync().ConfigureAwait(true);
    }

    public void ShowPane()
    {
        _pane ??= new PaneWindow(this);
        if (_pane.IsVisible) { _pane.Hide(); return; }
        if (DateTime.UtcNow - _pane.LastHiddenUtc < TimeSpan.FromMilliseconds(300)) return; // click on the tray icon closed it
        _pane.ShowNearTray();
        _ = RefreshAsync();
    }

    public void SetOrbVisible(bool visible)
    {
        if (Status.OrbLocked) return;
        Status.ShowOrb = visible;
        using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Callosotomy"))
        {
            key.SetValue("ShowFloatingButton", visible ? 1 : 0, RegistryValueKind.DWord);
        }
        if (visible) ShowOrb(); else _orb?.Hide();
        _tray.Update(Status);
    }

    private void ShowOrb()
    {
        _orb ??= new OrbWindow(this);
        _orb.Show();
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == Native.WmHotkey && wParam.ToInt32() == HotkeyId)
        {
            handled = true;
            _ = SetModeAsync(IsolationMode.All);
        }
        return IntPtr.Zero;
    }

    /// <summary>Group Policy can force the floating button on (1) or off (0).</summary>
    private static (bool Forced, bool Value) OrbPolicy()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Callosotomy");
        return key?.GetValue("ShowFloatingButton") is int v ? (true, v != 0) : (false, false);
    }

    private static bool UserWantsOrb()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Callosotomy");
        return key?.GetValue("ShowFloatingButton") is int v && v != 0;
    }

    public void Dispose()
    {
        _poll.Stop();
        Native.UnregisterHotKey(_messageWindow.Handle, HotkeyId);
        _messageWindow.Dispose();
        _orb?.Close();
        _pane?.Close();
        _tray.Dispose();
    }
}
