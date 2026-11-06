using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using WpfBrush = System.Windows.Media.Brush;
using WpfColor = System.Windows.Media.Color;
using WpfPath = System.Windows.Shapes.Path;

namespace Callosotomy.Tray;

/// <summary>
/// The Callosotomy mark: two brain hemispheres joined by a bridge (connected) that slide apart
/// when the network is severed. Drawn on a 24×24 grid, mirrored about x = 12.
/// </summary>
internal static class BrainShape
{
    public const string LeftOutline = "M11,4.5 C7,4 3.5,6 3.5,10 C2.5,11.5 2.5,14 4,15.5 C4.5,18.5 7.5,20 11,19.5 Z";
    public const string LeftFolds = "M11,9 C9,8.5 7.5,9.5 6.5,8.5 M11,14 C9,13.5 7,15 5.5,13.5";
    public const string RightOutline = "M13,4.5 C17,4 20.5,6 20.5,10 C21.5,11.5 21.5,14 20,15.5 C19.5,18.5 16.5,20 13,19.5 Z";
    public const string RightFolds = "M13,9 C15,8.5 16.5,9.5 17.5,8.5 M13,14 C15,13.5 17,15 18.5,13.5";
    public const string Bridge = "M11,12 L13,12";

    /// <summary>Renders the mark as a tray icon. Caller owns the returned icon handle via <see cref="Native.DestroyIcon"/>.</summary>
    public static Icon RenderIcon(int size, System.Drawing.Color color, bool split)
    {
        using var bmp = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(System.Drawing.Color.Transparent);
            float s = size / 24f;
            float shift = split ? 1.6f : 0f;

            using var left = Hemisphere(s, -shift, mirror: false);
            using var right = Hemisphere(s, shift, mirror: true);

            if (split)
            {
                // Soft glow: a few widening translucent strokes under the outline.
                for (int i = 3; i >= 1; i--)
                {
                    using var glow = new System.Drawing.Pen(System.Drawing.Color.FromArgb(38, color), (1.6f + i * 1.4f) * s)
                    { LineJoin = LineJoin.Round };
                    g.DrawPath(glow, left);
                    g.DrawPath(glow, right);
                }
            }

            using var fill = new SolidBrush(System.Drawing.Color.FromArgb(split ? 70 : 90, color));
            g.FillPath(fill, left);
            g.FillPath(fill, right);

            using var pen = new System.Drawing.Pen(color, 1.7f * s) { LineJoin = LineJoin.Round, StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawPath(pen, left);
            g.DrawPath(pen, right);
            DrawFolds(g, pen, s, -shift, mirror: false);
            DrawFolds(g, pen, s, shift, mirror: true);
            if (!split) g.DrawLine(pen, 11 * s, 12 * s, 13 * s, 12 * s);
        }
        IntPtr h = bmp.GetHicon();
        return Icon.FromHandle(h);
    }

    private static GraphicsPath Hemisphere(float s, float dx, bool mirror)
    {
        PointF P(float x, float y) => new(((mirror ? 24 - x : x) + dx) * s, y * s);
        var path = new GraphicsPath();
        path.AddBezier(P(11, 4.5f), P(7, 4), P(3.5f, 6), P(3.5f, 10));
        path.AddBezier(P(3.5f, 10), P(2.5f, 11.5f), P(2.5f, 14), P(4, 15.5f));
        path.AddBezier(P(4, 15.5f), P(4.5f, 18.5f), P(7.5f, 20), P(11, 19.5f));
        path.CloseFigure();
        return path;
    }

    private static void DrawFolds(Graphics g, System.Drawing.Pen pen, float s, float dx, bool mirror)
    {
        PointF P(float x, float y) => new(((mirror ? 24 - x : x) + dx) * s, y * s);
        g.DrawBezier(pen, P(11, 9), P(9, 8.5f), P(7.5f, 9.5f), P(6.5f, 8.5f));
        g.DrawBezier(pen, P(11, 14), P(9, 13.5f), P(7, 15), P(5.5f, 13.5f));
    }
}

/// <summary>WPF version of the mark with an animated split.</summary>
internal sealed class BrainGlyph : Grid
{
    public static readonly DependencyProperty SplitProperty = DependencyProperty.Register(
        nameof(Split), typeof(bool), typeof(BrainGlyph), new PropertyMetadata(false, (d, _) => ((BrainGlyph)d).Animate()));

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(WpfBrush), typeof(BrainGlyph), new PropertyMetadata(System.Windows.Media.Brushes.White));

    public static readonly DependencyProperty GlowColorProperty = DependencyProperty.Register(
        nameof(GlowColor), typeof(WpfColor), typeof(BrainGlyph), new PropertyMetadata(Colors.Transparent, (d, e) => ((BrainGlyph)d)._glow.Color = (WpfColor)e.NewValue));

    private readonly TranslateTransform _leftShift = new();
    private readonly TranslateTransform _rightShift = new();
    private readonly WpfPath _bridge;
    private readonly DropShadowEffect _glow = new() { ShadowDepth = 0, BlurRadius = 10, Opacity = 0.9, Color = Colors.Transparent };

    public bool Split { get => (bool)GetValue(SplitProperty); set => SetValue(SplitProperty, value); }
    public WpfBrush Stroke { get => (WpfBrush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    public WpfColor GlowColor { get => (WpfColor)GetValue(GlowColorProperty); set => SetValue(GlowColorProperty, value); }

    public BrainGlyph()
    {
        var canvas = new Viewbox { Child = BuildCanvas(out _bridge) };
        Children.Add(canvas);
        Effect = _glow;
    }

    private Canvas BuildCanvas(out WpfPath bridge)
    {
        var c = new Canvas { Width = 24, Height = 24 };
        var left = new Canvas { RenderTransform = _leftShift };
        var right = new Canvas { RenderTransform = _rightShift };
        left.Children.Add(Stroked(BrainShape.LeftOutline + " " + BrainShape.LeftFolds));
        right.Children.Add(Stroked(BrainShape.RightOutline + " " + BrainShape.RightFolds));
        bridge = Stroked(BrainShape.Bridge);
        c.Children.Add(left);
        c.Children.Add(right);
        c.Children.Add(bridge);
        return c;
    }

    private WpfPath Stroked(string data)
    {
        var p = new WpfPath
        {
            Data = Geometry.Parse(data),
            StrokeThickness = 1.6,
            StrokeLineJoin = PenLineJoin.Round,
            StrokeStartLineCap = PenLineCap.Round,
            StrokeEndLineCap = PenLineCap.Round,
        };
        p.SetBinding(WpfPath.StrokeProperty, new System.Windows.Data.Binding(nameof(Stroke)) { Source = this });
        return p;
    }

    private void Animate()
    {
        var duration = new Duration(TimeSpan.FromMilliseconds(420));
        var ease = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.4 };
        double d = Split ? 1.8 : 0;
        _leftShift.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(-d, duration) { EasingFunction = ease });
        _rightShift.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(d, duration) { EasingFunction = ease });
        _bridge.BeginAnimation(OpacityProperty, new DoubleAnimation(Split ? 0 : 1, new Duration(TimeSpan.FromMilliseconds(200))));
    }
}
