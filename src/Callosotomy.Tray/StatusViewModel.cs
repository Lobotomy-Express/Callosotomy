using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using Callosotomy.Core;

namespace Callosotomy.Tray;

/// <summary>Everything the pane, orb and tray icon display, derived from one service status.</summary>
internal sealed class StatusViewModel : INotifyPropertyChanged
{
    public static readonly Color Green = Color.FromRgb(0x30, 0xD1, 0x58);
    public static readonly Color Red = Color.FromRgb(0xFF, 0x45, 0x3A);
    public static readonly Color Amber = Color.FromRgb(0xFF, 0xB3, 0x40);
    public static readonly Color Grey = Color.FromRgb(0x8E, 0x8E, 0x93);

    private bool _reachable;
    private Protocol.Status _status;
    private string? _flash;
    private bool _showOrb;
    private bool _orbLocked;

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool Reachable => _reachable;
    public IsolationMode Mode => _status.Mode;
    public bool Blocked => _reachable && _status.Mode != IsolationMode.None;
    public bool Bypassed => _reachable && _status.Health == BlockHealth.Bypassed;

    /// <summary>State colour: green open, red severed, amber bypassed, grey when the service is unreachable.</summary>
    public Color AccentColor => !_reachable ? Grey : Bypassed ? Amber : Blocked ? Red : Green;
    public SolidColorBrush Accent => Frozen(AccentColor);
    public SolidColorBrush AccentTint => Frozen(Color.FromArgb(0x2E, AccentColor.R, AccentColor.G, AccentColor.B));
    public SolidColorBrush AccentSoft => Frozen(Mix(AccentColor, Colors.White, 0.72));

    public string Title => !_reachable ? "Protection service offline"
        : Bypassed ? "Block was bypassed"
        : _status.Mode switch
        {
            IsolationMode.Internet => "Internet severed",
            IsolationMode.Local => "Local network severed",
            IsolationMode.All => "Everything severed",
            _ => "All connections open",
        };

    public string Subtitle => _flash ?? (!_reachable ? "Start the Callosotomy service to enable controls"
        : Bypassed ? "Unplug the network cable now"
        : _status.Mode switch
        {
            IsolationMode.Internet => "Local devices still reachable",
            IsolationMode.Local => "Internet still reachable",
            IsolationMode.All => "This PC is fully isolated",
            _ => "Watching for tampering",
        });

    public string OrbText => !_reachable ? "OFFLINE" : Bypassed ? "BYPASSED" : _status.Mode switch
    {
        IsolationMode.Internet => "NO INTERNET",
        IsolationMode.Local => "NO LAN",
        IsolationMode.All => "SEVERED",
        _ => "CONNECTED",
    };

    public string TrayText => "Callosotomy: " + Title.ToLowerInvariant();

    public bool InternetOn => _reachable && _status.Mode is IsolationMode.Internet or IsolationMode.All;
    public bool LocalOn => _reachable && _status.Mode is IsolationMode.Local or IsolationMode.All;
    public bool AllOn => _reachable && _status.Mode == IsolationMode.All;

    public string TamperText => !_reachable ? "Unavailable"
        : _status.Health switch
        {
            BlockHealth.Bypassed => "Traffic got through",
            BlockHealth.Repaired => "Tampering repaired",
            _ => Blocked ? $"Verified {AgeText()}" : "Standing by",
        };

    public SolidColorBrush TamperBrush => Frozen(!_reachable ? Grey
        : _status.Health switch { BlockHealth.Bypassed => Amber, BlockHealth.Repaired => Amber, _ => Green });

    public string ServiceText => _reachable ? "Running as SYSTEM" : "Not running";
    public SolidColorBrush ServiceBrush => Frozen(_reachable ? Green : Grey);

    public bool ShowOrb { get => _showOrb; set { if (_showOrb != value) { _showOrb = value; Raise(); } } }

    /// <summary>True when Group Policy forces the floating button on or off.</summary>
    public bool OrbLocked { get => _orbLocked; set { _orbLocked = value; Raise(); Raise(nameof(OrbToggleEnabled)); } }
    public bool OrbToggleEnabled => !_orbLocked;

    public void Update(ServiceReply reply)
    {
        _reachable = reply.Reachable;
        if (reply.Ok) _status = reply.Status;
        RaiseAll();
    }

    /// <summary>Shows a one-off message under the title (e.g. "denied") until cleared.</summary>
    public void Flash(string? message)
    {
        _flash = message;
        Raise(nameof(Subtitle));
    }

    private string AgeText()
    {
        long age = Math.Max(0, (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - _status.CheckedUnixMs) / 1000);
        return age < 2 ? "just now" : $"{age} s ago";
    }

    private void RaiseAll() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));

    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static SolidColorBrush Frozen(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    private static Color Mix(Color a, Color b, double t) => Color.FromRgb(
        (byte)(a.R + ((b.R - a.R) * t)), (byte)(a.G + ((b.G - a.G) * t)), (byte)(a.B + ((b.B - a.B) * t)));
}
