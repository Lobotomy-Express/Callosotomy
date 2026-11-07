using System;
using System.ComponentModel;
using GdiPixelFormat = System.Drawing.Imaging.PixelFormat;
using ImageLockMode = System.Drawing.Imaging.ImageLockMode;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Callosotomy.Core;
using Microsoft.Win32;

namespace Callosotomy.Tray;

/// <summary>
/// Optional floating panic button. Real frosted glass: the strip of screen behind the orb is
/// captured a few times a second and blurred. The window excludes itself from capture so it
/// never blurs its own reflection.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Bitmap is disposed in the Closed handler, the window lifetime hook.")]
internal sealed partial class OrbWindow : Window
{
    private const string PositionKey = @"Software\Callosotomy";
    private const int CaptureDip = 188;
    private const int CaptureOffsetDip = 16; // (220 - 188) / 2

    private readonly AppController _controller;
    private readonly DispatcherTimer _frost;
    private System.Drawing.Bitmap? _grab;
    private WriteableBitmap? _frame;
    private bool _frostSupported;
    private bool _breathingFast;

    public OrbWindow(AppController controller)
    {
        _controller = controller;
        DataContext = controller.Status;
        InitializeComponent();

        _frost = new DispatcherTimer(DispatcherPriority.Render) { Interval = TimeSpan.FromMilliseconds(150) };
        _frost.Tick += (_, _) => Capture();

        SourceInitialized += OnSourceInitialized;
        IsVisibleChanged += (_, _) => { if (IsVisible && _frostSupported) _frost.Start(); else _frost.Stop(); };
        Closed += (_, _) => { _frost.Stop(); _grab?.Dispose(); };
        Disc.MouseLeftButtonDown += OnPress;
        Disc.MouseMove += OnMove;
        Disc.MouseLeftButtonUp += OnRelease;
        Disc.MouseEnter += (_, _) => Scale(1.04);
        Disc.MouseLeave += (_, _) => { Scale(1.0); ShowHover(null); };
        controller.Status.PropertyChanged += OnStatusChanged;

        RestorePosition();
        Breathe(fast: false);
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        IntPtr hwnd = new WindowInteropHelper(this).Handle;
        _frostSupported = Native.SetWindowDisplayAffinity(hwnd, Native.WdaExcludeFromCapture);
        if (_frostSupported && IsVisible) _frost.Start();
    }

    private void OnStatusChanged(object? sender, PropertyChangedEventArgs e)
    {
        bool fast = _controller.Status.Blocked;
        if (fast != _breathingFast) Breathe(fast);
    }

    private void Breathe(bool fast)
    {
        _breathingFast = fast;
        Halo.BeginAnimation(OpacityProperty, new DoubleAnimation(0.25, 0.65, new Duration(TimeSpan.FromMilliseconds(fast ? 1300 : 3200)))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        });
    }

    private void Scale(double s)
    {
        var a = new DoubleAnimation(s, new Duration(TimeSpan.FromMilliseconds(160))) { EasingFunction = new CubicEase() };
        DiscScale.BeginAnimation(ScaleTransform.ScaleXProperty, a);
        DiscScale.BeginAnimation(ScaleTransform.ScaleYProperty, a);
    }

    // ---- Interaction --------------------------------------------------------------
    // Click the left hemisphere: toggle Internet. Click the right: toggle Local network.
    // Press and hold anywhere for one second: sever everything (or restore, if anything is cut).
    // Drag: move the button.

    private enum Side { Left, Right }

    private static readonly TimeSpan HoldTime = TimeSpan.FromSeconds(1);
    private DispatcherTimer? _holdTimer;
    private Point _pressPoint;
    private Side _pressSide;
    private bool _pressed, _holdFired;

    private Side SideAt(Point p) => p.X < Disc.ActualWidth / 2 ? Side.Left : Side.Right;

    private void OnPress(object sender, MouseButtonEventArgs e)
    {
        _pressed = true;
        _holdFired = false;
        _pressPoint = e.GetPosition(this);
        _pressSide = SideAt(e.GetPosition(Disc));
        Disc.CaptureMouse();
        Scale(0.96);

        HoldRing.BeginAnimation(OpacityProperty, new DoubleAnimation(0.9, new Duration(TimeSpan.FromMilliseconds(120))));
        HoldRing.BeginAnimation(System.Windows.Shapes.Shape.StrokeDashOffsetProperty, new DoubleAnimation(151, 0, new Duration(HoldTime)));
        _holdTimer = new DispatcherTimer { Interval = HoldTime };
        _holdTimer.Tick += async (_, _) =>
        {
            StopHold();
            _holdFired = true;
            var target = _controller.Status.Mode == IsolationMode.None ? IsolationMode.All : IsolationMode.None;
            await _controller.SetModeAsync(target).ConfigureAwait(true);
        };
        _holdTimer.Start();
    }

    private void OnMove(object sender, MouseEventArgs e)
    {
        if (_pressed)
        {
            var p = e.GetPosition(this);
            if (!_holdFired && (Math.Abs(p.X - _pressPoint.X) > 4 || Math.Abs(p.Y - _pressPoint.Y) > 4)
                && e.LeftButton == MouseButtonState.Pressed)
            {
                // Became a drag: cancel the click/hold and move the window instead.
                _pressed = false;
                StopHold();
                Disc.ReleaseMouseCapture();
                try { DragMove(); } catch (InvalidOperationException) { }
                Scale(1.04);
                SavePosition();
            }
            return;
        }
        ShowHover(SideAt(e.GetPosition(Disc)));
    }

    private async void OnRelease(object sender, MouseButtonEventArgs e)
    {
        if (!_pressed) return;
        _pressed = false;
        StopHold();
        Disc.ReleaseMouseCapture();
        Scale(1.04);
        if (_holdFired || !_controller.Status.Reachable) return;

        var s = _controller.Status;
        var target = _pressSide == Side.Left
            ? AppController.Combine(!s.InternetOn, s.LocalOn)
            : AppController.Combine(s.InternetOn, !s.LocalOn);
        await _controller.SetModeAsync(target).ConfigureAwait(true);
        ShowHover(_pressSide);
    }

    private void StopHold()
    {
        _holdTimer?.Stop();
        _holdTimer = null;
        HoldRing.BeginAnimation(OpacityProperty, new DoubleAnimation(0, new Duration(TimeSpan.FromMilliseconds(160))));
    }

    private void ShowHover(Side? side)
    {
        HoverLeft.Opacity = side == Side.Left ? 0.07 : 0;
        HoverRight.Opacity = side == Side.Right ? 0.07 : 0;
        var s = _controller.Status;
        Disc.ToolTip = side switch
        {
            Side.Left => s.InternetOn ? "Internet: click to restore" : "Internet: click to sever",
            Side.Right => s.LocalOn ? "Local network: click to restore" : "Local network: click to sever",
            _ => null,
        } + (side is null ? "" : "\nHold for one second to sever or restore everything. Drag to move.");
    }

    private void OnOpenPane(object sender, RoutedEventArgs e) => _controller.ShowPane();

    private void OnHide(object sender, RoutedEventArgs e) => _controller.SetOrbVisible(false);

    private void Capture()
    {
        if (PresentationSource.FromVisual(this) is not { CompositionTarget: { } target }) return;
        double scale = target.TransformToDevice.M11;
        int px = Math.Max(1, (int)Math.Round(CaptureDip * scale));
        var origin = PointToScreen(new Point(CaptureOffsetDip, CaptureOffsetDip));

        if (_grab is null || _grab.Width != px)
        {
            _grab?.Dispose();
            _grab = new System.Drawing.Bitmap(px, px, GdiPixelFormat.Format32bppArgb);
            _frame = new WriteableBitmap(px, px, 96, 96, PixelFormats.Bgra32, null);
            Backdrop.Source = _frame;
        }

        try
        {
            using (var g = System.Drawing.Graphics.FromImage(_grab))
            {
                g.CopyFromScreen((int)origin.X, (int)origin.Y, 0, 0, _grab.Size);
            }
            var data = _grab.LockBits(new System.Drawing.Rectangle(0, 0, px, px), ImageLockMode.ReadOnly, GdiPixelFormat.Format32bppArgb);
            try
            {
                _frame!.WritePixels(new Int32Rect(0, 0, px, px), data.Scan0, data.Stride * px, data.Stride);
            }
            finally
            {
                _grab.UnlockBits(data);
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Secure desktop (UAC prompt, lock screen) can't be captured. Keep the last frame.
        }
    }

    private void RestorePosition()
    {
        var area = SystemParameters.WorkArea;
        Left = area.Right - Width - 24;
        Top = area.Top + 24;
        using var key = Registry.CurrentUser.OpenSubKey(PositionKey);
        if (key?.GetValue("OrbPosition") is string s)
        {
            var parts = s.Split(',');
            if (parts.Length == 2
                && double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out double l)
                && double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out double t)
                && l > SystemParameters.VirtualScreenLeft - Width / 2 && l < SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - Width / 2
                && t > SystemParameters.VirtualScreenTop - Height / 2 && t < SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - Height / 2)
            {
                Left = l;
                Top = t;
            }
        }
    }

    private void SavePosition()
    {
        using var key = Registry.CurrentUser.CreateSubKey(PositionKey);
        key.SetValue("OrbPosition", string.Create(CultureInfo.InvariantCulture, $"{Left},{Top}"));
    }
}
