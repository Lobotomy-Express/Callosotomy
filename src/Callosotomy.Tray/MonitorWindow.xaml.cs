using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>
/// The network monitor. Polls the service only while it is visible: connections every
/// 1.5 seconds, rules every 10 seconds and after every change. Closing it stops all polling.
/// </summary>
internal sealed partial class MonitorWindow : Window
{
    private readonly MonitorViewModel _vm = new();
    private readonly DispatcherTimer _poll;
    private int _ticks;
    private bool _busy;
    private int _acting;
    private bool _exiting;

    /// <summary>Really closes the window (used when the tray app exits).</summary>
    public void ForceClose()
    {
        _exiting = true;
        Close();
    }

    public MonitorWindow()
    {
        DataContext = _vm;
        InitializeComponent();
        _poll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
        _poll.Tick += async (_, _) => await PollAsync().ConfigureAwait(true);
        SourceInitialized += (_, _) => ApplyBackdrop();
        IsVisibleChanged += async (_, _) =>
        {
            if (IsVisible)
            {
                _ticks = 0;
                await _vm.RefreshPoliciesAsync().ConfigureAwait(true);
                await _vm.RefreshConnectionsAsync().ConfigureAwait(true);
                _poll.Start();
            }
            else
            {
                _poll.Stop();
            }
        };
        // Keep the window for next time; polling stops while hidden.
        Closing += (_, e) => { if (!_exiting) { e.Cancel = true; Hide(); } };
        Closed += (_, _) => _poll.Stop();
    }

    private async Task PollAsync()
    {
        if (_busy || _acting > 0) return;
        _busy = true;
        try
        {
            if (++_ticks % 7 == 0) await _vm.RefreshPoliciesAsync().ConfigureAwait(true);
            await _vm.RefreshConnectionsAsync().ConfigureAwait(true);
        }
        finally
        {
            _busy = false;
        }
    }

    private void ApplyBackdrop()
    {
        IntPtr hwnd = new WindowInteropHelper(this).Handle;
        if (HwndSource.FromHwnd(hwnd) is { } source) source.CompositionTarget.BackgroundColor = Colors.Transparent;
        Native.SetDwm(hwnd, Native.DwmwaUseImmersiveDarkMode, 1);
        Native.SetDwm(hwnd, Native.DwmwaWindowCornerPreference, Native.DwmwcpRound);
        // Mica-style backdrop for a main window; fall back to solid dark glass on Windows 10.
        if (!Native.SetDwm(hwnd, Native.DwmwaSystemBackdropType, 2))
            Root.Background = new SolidColorBrush(Color.FromArgb(0xF2, 0x1C, 0x1C, 0x22));
    }

    // ---- Apps -------------------------------------------------------------------------

    private void OnAppClicked(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject d && FindParent<Button>(d) is not null) return; // the switch handles itself
        if (sender is FrameworkElement { Tag: string key }) _vm.Select(key);
    }

    private async void OnAppSwitch(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: AppRow row })
        {
            _vm.Select(row.Key);
            await Run(() => _vm.ToggleAppAsync(row)).ConfigureAwait(true);
        }
    }

    private async void OnSelectedSwitch(object sender, RoutedEventArgs e)
    {
        if (_vm.Selected is { } row) await Run(() => _vm.ToggleAppAsync(row)).ConfigureAwait(true);
    }

    private void OnMore(object sender, RoutedEventArgs e)
    {
        if (sender is Button { ContextMenu: { } menu } b)
        {
            menu.PlacementTarget = b;
            menu.IsOpen = true;
        }
    }

    private void OnCopyPowerShell(object sender, RoutedEventArgs e)
    {
        if (_vm.Selected is not { } row) return;
        string? text = MonitorViewModel.PowerShellFor(row);
        if (text is null) { Show("This app has no rules to copy"); return; }
        try
        {
            Clipboard.SetText(text);
            Show("Copied. Paste into an administrator PowerShell to recreate these rules elsewhere.");
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            Show("The clipboard is busy. Try again.");
        }
    }

    private async void OnRemoveAll(object sender, RoutedEventArgs e) => await Run(_vm.RemoveAllRulesAsync).ConfigureAwait(true);

    // ---- Rules ------------------------------------------------------------------------

    private async void OnToggleRule(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: RuleRow r }) await Run(() => _vm.ToggleRuleAsync(r)).ConfigureAwait(true);
    }

    private async void OnDeleteRule(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: RuleRow r }) await Run(() => _vm.DeleteRuleAsync(r)).ConfigureAwait(true);
    }

    private async void OnAllowOnly(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ConnectionRow c }) await Run(() => _vm.AllowOnlyThisAsync(c)).ConfigureAwait(true);
    }

    private async void OnBlockPort(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ConnectionRow c }) await Run(() => _vm.BlockPortAsync(c)).ConfigureAwait(true);
    }

    private async void OnBlockSite(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ConnectionRow c }) await Run(() => _vm.BlockDestinationAsync(c)).ConfigureAwait(true);
    }

    private async void OnAddRule(object sender, RoutedEventArgs e)
    {
        FError.Visibility = Visibility.Collapsed;
        var dest = FAnywhere.IsChecked == true ? DestinationKind.Anywhere
            : FInternet.IsChecked == true ? DestinationKind.Internet
            : FLocal.IsChecked == true ? DestinationKind.LocalNetwork
            : FDomain.IsChecked == true ? DestinationKind.Domain
            : DestinationKind.Address;
        var proto = FTcp.IsChecked == true ? TrafficProtocol.Tcp : FUdp.IsChecked == true ? TrafficProtocol.Udp : TrafficProtocol.Any;
        string ports = string.IsNullOrWhiteSpace(FPorts.Text) ? "Any" : FPorts.Text.Trim();
        string value = FValue.Text.Trim();

        string? error = null;
        if (dest == DestinationKind.Domain && !AppRuleLimits.TryNormalizeDomain(value, out value)) error = "Enter a domain like example.com or *.example.com";
        else if (dest == DestinationKind.Address && !AppRuleLimits.TryParseAddresses(value, out _)) error = "Enter an address like 1.2.3.4, 10.0.0.0/8 or 1.2.3.4-1.2.3.9";
        else if (!AppRuleLimits.TryParsePorts(ports, out _)) error = "Enter ports like 443, 80,443 or 8000-8100";
        else if (proto == TrafficProtocol.Any && !AppRuleLimits.IsAnyPort(ports)) error = "Pick TCP or UDP to use specific ports";
        if (error is not null)
        {
            FError.Text = error;
            FError.Visibility = Visibility.Visible;
            return;
        }

        var rule = new AppRule
        {
            Action = FAllow.IsChecked == true ? RuleAction.Allow : RuleAction.Block,
            Direction = FOut.IsChecked == true ? TrafficDirection.Outbound : FIn.IsChecked == true ? TrafficDirection.Inbound : TrafficDirection.Both,
            Protocol = proto,
            Ports = ports,
            Destination = dest,
            Value = dest is DestinationKind.Domain or DestinationKind.Address ? value : null,
        };
        await Run(() => _vm.AddRuleAsync(rule)).ConfigureAwait(true);
        FValue.Text = "";
        FPorts.Text = "";
    }

    // ---- Helpers ----------------------------------------------------------------------

    private async Task Run(Func<Task> action)
    {
        IsEnabled = false;
        _acting++;
        try { await action().ConfigureAwait(true); }
        finally { _acting--; IsEnabled = true; }
    }

    private void Show(string message) => _vm.ShowMessage(message);

    private static T? FindParent<T>(DependencyObject d) where T : DependencyObject
    {
        for (var cur = d; cur is not null; cur = VisualTreeHelper.GetParent(cur))
            if (cur is T t) return t;
        return null;
    }
}
