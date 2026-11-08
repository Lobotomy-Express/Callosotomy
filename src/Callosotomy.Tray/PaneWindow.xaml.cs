using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>The Control-Center-style pane that opens from the tray icon.</summary>
internal sealed partial class PaneWindow : Window
{
    private readonly AppController _controller;

    public PaneWindow(AppController controller)
    {
        _controller = controller;
        DataContext = controller.Status;
        InitializeComponent();
        SourceInitialized += (_, _) => ApplyBackdrop();
        Deactivated += (_, _) => { Hide(); LastHiddenUtc = DateTime.UtcNow; };
        PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape) Hide(); };
    }

    /// <summary>When the pane last closed by losing focus; a tray click that caused it must not reopen it.</summary>
    public DateTime LastHiddenUtc { get; private set; }

    /// <summary>Slides the pane up from the tray corner.</summary>
    public void ShowNearTray()
    {
        Show();
        UpdateLayout();
        var area = SystemParameters.WorkArea;
        Left = area.Right - ActualWidth - 12;
        Top = area.Bottom - ActualHeight - 12;
        Activate();

        var duration = new Duration(TimeSpan.FromMilliseconds(220));
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        SlideIn.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty, new DoubleAnimation(14, 0, duration) { EasingFunction = ease });
        Root.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, duration) { EasingFunction = ease });
    }

    private void ApplyBackdrop()
    {
        IntPtr hwnd = new WindowInteropHelper(this).Handle;
        if (HwndSource.FromHwnd(hwnd) is { } source) source.CompositionTarget.BackgroundColor = Colors.Transparent;

        Native.SetDwm(hwnd, Native.DwmwaUseImmersiveDarkMode, 1);
        Native.SetDwm(hwnd, Native.DwmwaWindowCornerPreference, Native.DwmwcpRound);
        bool acrylic = Native.SetDwm(hwnd, Native.DwmwaSystemBackdropType, Native.DwmsbtTransientWindow);
        if (!acrylic)
        {
            // Windows 10: no system acrylic, fall back to a near-opaque dark glass.
            Root.Background = new SolidColorBrush(Color.FromArgb(0xF2, 0x1C, 0x1C, 0x22));
        }
    }

    private async void OnInternet(object sender, RoutedEventArgs e) =>
        await _controller.SetModeAsync(AppController.Combine(!_controller.Status.InternetOn, _controller.Status.LocalOn)).ConfigureAwait(true);

    private async void OnLocal(object sender, RoutedEventArgs e) =>
        await _controller.SetModeAsync(AppController.Combine(_controller.Status.InternetOn, !_controller.Status.LocalOn)).ConfigureAwait(true);

    private async void OnAll(object sender, RoutedEventArgs e) =>
        await _controller.SetModeAsync(_controller.Status.AllOn ? IsolationMode.None : IsolationMode.All).ConfigureAwait(true);

    private async void OnRestore(object sender, RoutedEventArgs e) =>
        await _controller.SetModeAsync(IsolationMode.None).ConfigureAwait(true);

    private void OnMonitor(object sender, RoutedEventArgs e) => _controller.ShowMonitor();

    private void OnToggleOrb(object sender, RoutedEventArgs e) => _controller.SetOrbVisible(!_controller.Status.ShowOrb);
}
