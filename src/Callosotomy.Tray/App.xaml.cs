using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Callosotomy.Core;

namespace Callosotomy.Tray;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Disposed in OnExit, the WPF application lifetime hook.")]
internal sealed partial class App : Application
{
    private Mutex? _single;
    private AppController? _controller;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Length > 0)
        {
            int code = RunCommandLine(e.Args).GetAwaiter().GetResult();
            Shutdown(code);
            return;
        }

        _single = new Mutex(initiallyOwned: true, @"Local\Callosotomy.Tray", out bool created);
        if (!created)
        {
            Shutdown(0);
            return;
        }
        _controller = new AppController();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _controller?.Dispose();
        _single?.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// Scriptable interface for IT and remote tooling:
    ///   Callosotomy.exe --status
    ///   Callosotomy.exe --sever internet|local|all
    ///   Callosotomy.exe --restore
    /// Exit codes: 0 ok, 1 usage, 2 denied/failed, 3 service unreachable.
    /// </summary>
    private static async Task<int> RunCommandLine(string[] args)
    {
        Native.AttachConsole(-1);
        IsolationMode? target = args switch
        {
            ["--status"] => null,
            ["--restore"] => IsolationMode.None,
            ["--sever", var m] when Protocol.TryParseMode(m.ToUpperInvariant(), out var mode) && mode != IsolationMode.None => mode,
            _ => (IsolationMode?)(-1),
        };
        if (target == (IsolationMode)(-1))
        {
            Console.Error.WriteLine("Usage: Callosotomy --status | --sever internet|local|all | --restore");
            return 1;
        }

        var reply = target is { } t
            ? await ServiceClient.SetAsync(t).ConfigureAwait(false)
            : await ServiceClient.StatusAsync().ConfigureAwait(false);

        if (!reply.Reachable)
        {
            Console.Error.WriteLine("Callosotomy service unreachable (" + reply.Error + ").");
            return 3;
        }
        if (!reply.Ok)
        {
            Console.Error.WriteLine("Refused: " + reply.Error);
            return 2;
        }
        Console.WriteLine($"mode={Protocol.ModeName(reply.Status.Mode).ToLowerInvariant()} health={reply.Status.Health.ToString().ToLowerInvariant()}");
        return reply.Status.Health == BlockHealth.Bypassed ? 2 : 0;
    }
}
