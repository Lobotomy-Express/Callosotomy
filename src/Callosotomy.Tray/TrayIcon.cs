using System;
using System.Drawing;
using System.Windows.Forms;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>
/// The notification-area icon: a green joined brain while connected, a glowing red split brain
/// when severed, amber when bypassed and grey when the service is offline.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly Icon _live, _severed, _bypassed, _offline;
    private readonly ToolStripMenuItem _orbItem;
    private Icon? _current;

    public TrayIcon(AppController controller)
    {
        int size = SystemInformation.SmallIconSize.Width * 2; // crisp at 200% and downsampled cleanly at 100%
        _live = BrainShape.RenderIcon(size, ToDrawing(StatusViewModel.Green), split: false);
        _severed = BrainShape.RenderIcon(size, ToDrawing(StatusViewModel.Red), split: true);
        _bypassed = BrainShape.RenderIcon(size, ToDrawing(StatusViewModel.Amber), split: true);
        _offline = BrainShape.RenderIcon(size, ToDrawing(StatusViewModel.Grey), split: false);

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Callosotomy", null, (_, _) => controller.ShowPane());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Sever everything", null, async (_, _) => await controller.SetModeAsync(IsolationMode.All).ConfigureAwait(true));
        menu.Items.Add("Restore all connections", null, async (_, _) => await controller.SetModeAsync(IsolationMode.None).ConfigureAwait(true));
        menu.Items.Add(new ToolStripSeparator());
        _orbItem = new ToolStripMenuItem("Show floating button", null, (_, _) => controller.SetOrbVisible(!controller.Status.ShowOrb));
        menu.Items.Add(_orbItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit tray app (protection keeps running)", null, (_, _) => System.Windows.Application.Current.Shutdown());

        _icon = new NotifyIcon { Icon = _offline, Text = "Callosotomy", ContextMenuStrip = menu, Visible = true };
        _icon.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) controller.ShowPane(); };
    }

    public void Update(StatusViewModel s)
    {
        var next = !s.Reachable ? _offline : s.Bypassed ? _bypassed : s.Blocked ? _severed : _live;
        if (!ReferenceEquals(next, _current)) { _icon.Icon = next; _current = next; }
        string text = s.TrayText;
        _icon.Text = text.Length > 63 ? text[..63] : text;
        _orbItem.Checked = s.ShowOrb;
        _orbItem.Enabled = !s.OrbLocked;
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        foreach (var i in new[] { _live, _severed, _bypassed, _offline })
        {
            Native.DestroyIcon(i.Handle);
            i.Dispose();
        }
    }

    private static Color ToDrawing(System.Windows.Media.Color c) => Color.FromArgb(c.A, c.R, c.G, c.B);
}
