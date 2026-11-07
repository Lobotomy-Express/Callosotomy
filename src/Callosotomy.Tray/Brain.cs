using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>Loads the brain artwork embedded under Art/ once and shares it.</summary>
internal static class BrainArtwork
{
    private static readonly Dictionary<string, BitmapImage> Cache = new(StringComparer.Ordinal);

    public static BitmapImage Get(string name)
    {
        if (Cache.TryGetValue(name, out var image)) return image;
        image = new BitmapImage();
        image.BeginInit();
        image.UriSource = new Uri($"pack://application:,,,/Art/{name}.png", UriKind.Absolute);
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.EndInit();
        image.Freeze();
        Cache[name] = image;
        return image;
    }

    /// <summary>Tray artwork as a GDI bitmap, for building notification-area icons.</summary>
    public static System.Drawing.Bitmap TrayBitmap(string state, int size)
    {
        var info = Application.GetResourceStream(new Uri($"pack://application:,,,/Art/tray-{state}.png", UriKind.Absolute))
                   ?? throw new FileNotFoundException("Missing tray artwork", state);
        using var stream = info.Stream;
        using var source = new System.Drawing.Bitmap(stream);
        var scaled = new System.Drawing.Bitmap(size, size);
        using var g = System.Drawing.Graphics.FromImage(scaled);
        g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
        g.DrawImage(source, 0, 0, size, size);
        return scaled;
    }

    /// <summary>Which tray artwork matches a status.</summary>
    public static string TrayState(StatusViewModel s) =>
        !s.Reachable ? "grey"
        : s.Bypassed ? "amber"
        : s.Mode switch
        {
            IsolationMode.Internet => "internet",
            IsolationMode.Local => "local",
            IsolationMode.All => "all",
            _ => "green",
        };
}

/// <summary>
/// The neon brain. Whole and green while connected; once anything is severed it becomes two
/// hemispheres that change colour independently (left = Internet, right = Local network) and
/// drift apart. Amber when a block was bypassed, grey when the service is unreachable.
/// </summary>
internal sealed class BrainArt : Grid
{
    public static readonly DependencyProperty ModeProperty = DependencyProperty.Register(
        nameof(Mode), typeof(IsolationMode), typeof(BrainArt), new PropertyMetadata(IsolationMode.None, Changed));
    public static readonly DependencyProperty ReachableProperty = DependencyProperty.Register(
        nameof(Reachable), typeof(bool), typeof(BrainArt), new PropertyMetadata(true, Changed));
    public static readonly DependencyProperty BypassedProperty = DependencyProperty.Register(
        nameof(Bypassed), typeof(bool), typeof(BrainArt), new PropertyMetadata(false, Changed));

    private static readonly Duration Fade = new(TimeSpan.FromMilliseconds(320));
    private static readonly IEasingFunction Ease = new CubicEase { EasingMode = EasingMode.EaseInOut };
    private static readonly IEasingFunction Spring = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.35 };

    private readonly Image _wholeGreen, _wholeGrey;
    private readonly Image _leftGreen, _leftRed, _leftAmber, _rightGreen, _rightRed, _rightAmber;
    private readonly TranslateTransform _leftShift = new(), _rightShift = new();

    public IsolationMode Mode { get => (IsolationMode)GetValue(ModeProperty); set => SetValue(ModeProperty, value); }
    public bool Reachable { get => (bool)GetValue(ReachableProperty); set => SetValue(ReachableProperty, value); }
    public bool Bypassed { get => (bool)GetValue(BypassedProperty); set => SetValue(BypassedProperty, value); }

    public BrainArt()
    {
        IsHitTestVisible = false;
        _leftGreen = Layer("brain-left-green", _leftShift);
        _leftRed = Layer("brain-left-red", _leftShift);
        _leftAmber = Layer("brain-left-amber", _leftShift);
        // The right hemisphere is nearer the viewer, so it is drawn on top.
        _rightGreen = Layer("brain-right-green", _rightShift);
        _rightRed = Layer("brain-right-red", _rightShift);
        _rightAmber = Layer("brain-right-amber", _rightShift);
        _wholeGreen = Layer("brain-all-green", null);
        _wholeGrey = Layer("brain-all-grey", null);
        Loaded += (_, _) => Apply(animate: false);
        SizeChanged += (_, _) => Apply(animate: false);
    }

    private Image Layer(string art, Transform? shift)
    {
        var img = new Image
        {
            Source = BrainArtwork.Get(art),
            Stretch = Stretch.Uniform,
            Opacity = 0,
            RenderTransform = shift ?? Transform.Identity,
        };
        RenderOptions.SetBitmapScalingMode(img, BitmapScalingMode.HighQuality);
        Children.Add(img);
        return img;
    }

    private static void Changed(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((BrainArt)d).Apply(animate: true);

    private void Apply(bool animate)
    {
        bool offline = !Reachable;
        bool whole = offline || Mode == IsolationMode.None;
        bool leftCut = !offline && Mode is IsolationMode.Internet or IsolationMode.All;
        bool rightCut = !offline && Mode is IsolationMode.Local or IsolationMode.All;
        bool amber = !offline && !whole && Bypassed;

        Show(_wholeGrey, offline, animate);
        Show(_wholeGreen, !offline && whole, animate);
        Show(_leftAmber, !whole && amber, animate);
        Show(_leftRed, !whole && !amber && leftCut, animate);
        Show(_leftGreen, !whole && !amber && !leftCut, animate);
        Show(_rightAmber, !whole && amber, animate);
        Show(_rightRed, !whole && !amber && rightCut, animate);
        Show(_rightGreen, !whole && !amber && !rightCut, animate);

        // A severed hemisphere drifts outward; the other stays close to the midline.
        double unit = Math.Max(ActualWidth, 1) * 0.045;
        Slide(_leftShift, whole ? 0 : -(leftCut ? unit : unit * 0.2), animate);
        Slide(_rightShift, whole ? 0 : (rightCut ? unit : unit * 0.2), animate);
    }

    private static void Show(UIElement e, bool visible, bool animate)
    {
        double to = visible ? 1 : 0;
        if (!animate) { e.BeginAnimation(OpacityProperty, null); e.Opacity = to; return; }
        e.BeginAnimation(OpacityProperty, new DoubleAnimation(to, Fade) { EasingFunction = Ease });
    }

    private static void Slide(TranslateTransform t, double x, bool animate)
    {
        if (!animate) { t.BeginAnimation(TranslateTransform.XProperty, null); t.X = x; return; }
        t.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(x, new Duration(TimeSpan.FromMilliseconds(520))) { EasingFunction = Spring });
    }
}
