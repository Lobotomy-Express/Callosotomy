using Callosotomy.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;

// Maintenance switch used by the uninstaller: lift every block and forget the saved mode.
if (args.Length == 1 && args[0] == "--remove-rules")
{
    new FirewallBackend().RemoveAll();
    StateStore.Clear();
    return 0;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "Callosotomy");

builder.Logging.ClearProviders();
builder.Logging.AddEventLog(new EventLogSettings { SourceName = "Callosotomy", LogName = "Application" });
builder.Logging.AddFilter<EventLogLoggerProvider>("Callosotomy", LogLevel.Information);
builder.Logging.AddFilter<EventLogLoggerProvider>("Microsoft", LogLevel.Warning);

builder.Services.AddSingleton<FirewallBackend>();
builder.Services.AddSingleton<Guardian>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Guardian>());
builder.Services.AddHostedService<ControlServer>();

await builder.Build().RunAsync().ConfigureAwait(false);
return 0;
