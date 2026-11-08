using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Callosotomy.Service;

/// <summary>
/// Tells the guardian when Windows Firewall's configuration changes, so it can verify rules
/// right away instead of re-reading every rule every few seconds. Watches the registry keys
/// where Windows stores firewall rules, profiles and Group Policy firewall settings.
/// If watching fails, <see cref="TakeChanged"/> simply returns true and the guardian falls
/// back to checking every cycle.
/// </summary>
internal sealed partial class FirewallWatcher : IDisposable
{
    private static readonly string[] Keys =
    {
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        @"SOFTWARE\Policies\Microsoft\WindowsFirewall",
    };

    private readonly ManualResetEvent _stop = new(false);
    private Thread? _thread;
    private volatile bool _broken;
    private int _changedFlag = 1;

    public void Start()
    {
        _thread = new Thread(Run) { IsBackground = true, Name = "Callosotomy firewall watcher" };
        _thread.Start();
    }

    private int _disposed;

    public void Stop()
    {
        if (Volatile.Read(ref _disposed) == 0) _stop.Set();
    }

    /// <summary>True if anything changed since the last call (or watching isn't possible).</summary>
    public bool TakeChanged() => _broken || Interlocked.Exchange(ref _changedFlag, 0) != 0;

    private void Run()
    {
        // Registry change notifications are tied to the thread that asked for them,
        // so this thread lives as long as the service.
        var keys = new List<RegistryKey>();
        var events = new List<AutoResetEvent>();
        try
        {
            foreach (string path in Keys)
            {
                var key = Registry.LocalMachine.OpenSubKey(path);
                if (key is null) continue; // the policy key usually doesn't exist; that's fine
                var ev = new AutoResetEvent(false);
                keys.Add(key);
                events.Add(ev);
                Arm(key, ev);
            }
            if (keys.Count == 0) { _broken = true; return; }

            var handles = events.Cast<WaitHandle>().Append(_stop).ToArray();
            while (true)
            {
                int i = WaitHandle.WaitAny(handles);
                if (i == handles.Length - 1) return;
                Interlocked.Exchange(ref _changedFlag, 1);
                Arm(keys[i], events[i]);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _broken = true;
        }
        finally
        {
            foreach (var k in keys) k.Dispose();
            foreach (var e in events) e.Dispose();
        }
    }

    private static void Arm(RegistryKey key, AutoResetEvent ev)
    {
        const uint Filter = 0x1 | 0x4; // REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
        int rc = RegNotifyChangeKeyValue(key.Handle, true, Filter, ev.SafeWaitHandle, true);
        if (rc != 0) throw new IOException($"RegNotifyChangeKeyValue failed: {rc}");
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Set();
        if (_thread is null || _thread.Join(TimeSpan.FromSeconds(2))) _stop.Dispose();
    }

    [LibraryImport("advapi32.dll")]
    private static partial int RegNotifyChangeKeyValue(SafeRegistryHandle key, [MarshalAs(UnmanagedType.Bool)] bool subtree,
        uint filter, SafeWaitHandle ev, [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
}
