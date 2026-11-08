using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>
/// The notification-area icon: the neon brain, whole and green while connected, with the left
/// hemisphere red when the internet is cut, the right red when the local network is cut, both
/// red when everything is cut, amber when bypassed and grey when the service is offline.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly Dictionary<string, Icon> _icons = new(StringComparer.Ordinal);
    private readonly ToolStripMenuItem _orbItem;
    private string? _current;

    public TrayIcon(AppController controller)
    {
        int size = Math.Max(16, SystemInformation.SmallIconSize.Width);
        foreach (string state in new[] { "green", "internet", "local", "all", "amber", "grey" })
        {
            using var bmp = BrainArtwork.TrayBitmap(state, size);
            _icons[state] = Icon.FromHandle(bmp.GetHicon());
        }

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Callosotomy", null, (_, _) => controller.ShowPane());
        menu.Items.Add("Network monitor", null, (_, _) => controller.ShowMonitor());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Sever everything", null, async (_, _) => await controller.SetModeAsync(IsolationMode.All).ConfigureAwait(true));
        menu.Items.Add("Restore all connections", null, async (_, _) => await controller.SetModeAsync(IsolationMode.None).ConfigureAwait(true));
        menu.Items.Add(new ToolStripSeparator());
        _orbItem = new ToolStripMenuItem("Show floating button", null, (_, _) => controller.SetOrbVisible(!controller.Status.ShowOrb));
        menu.Items.Add(_orbItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit tray app (protection keeps running)", null, (_, _) => System.Windows.Application.Current.Shutdown());

        _icon = new NotifyIcon { Icon = _icons["grey"], Text = "Callosotomy", ContextMenuStrip = menu, Visible = true };
        _icon.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) controller.ShowPane(); };
    }

    public void Update(StatusViewModel s)
    {
        string state = BrainArtwork.TrayState(s);
        if (state != _current) { _icon.Icon = _icons[state]; _current = state; }
        string text = s.TrayText;
        _icon.Text = text.Length > 63 ? text[..63] : text;
        _orbItem.Checked = s.ShowOrb;
        _orbItem.Enabled = !s.OrbLocked;
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        foreach (var i in _icons.Values)
        {
            Native.DestroyIcon(i.Handle);
            i.Dispose();
        }
    }
}
