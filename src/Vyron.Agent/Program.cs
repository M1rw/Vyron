using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Vyron.Core.Services;
using Vyron.Monitoring.Services;
using Vyron.Detection.Services;

namespace Vyron.Agent;

class Program
{
    static async Task Main(string[] args)
    {
        // Configure Serilog
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .WriteTo.File(
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Vyron", "Logs", "vyron-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30)
            .CreateLogger();

        try
        {
            Log.Information("Starting Vyron Advanced Malware Detection Agent");

            // Check if running in console mode
            bool consoleMode = args.Contains("--console") || args.Contains("-c");

            var builder = Host.CreateApplicationBuilder(args);

            // Configure to run as Windows Service unless in console mode
            if (!consoleMode)
            {
                builder.Services.AddWindowsService(options =>
                {
                    options.ServiceName = "VyronAgent";
                });
            }

            // Add Serilog
            builder.Services.AddSerilog();

            // Register core services
            builder.Services.AddSingleton<ConfigurationService>();
            
            // Register monitoring services
            builder.Services.AddSingleton<ProcessMonitorService>();
            builder.Services.AddSingleton<FileMonitorService>();
            
            // Register detection services
            builder.Services.AddSingleton<DetectionEngine>();
            builder.Services.AddSingleton<SignatureScanner>();
            builder.Services.AddSingleton<BehavioralAnalyzer>();
            builder.Services.AddSingleton<ReputationService>();
            
            // Register response services
            builder.Services.AddSingleton<QuarantineService>();
            builder.Services.AddSingleton<ResponseOrchestrator>();
            
            // Register the main worker service
            builder.Services.AddHostedService<VyronWorkerService>();

            var host = builder.Build();

            // Initialize configuration
            var configService = host.Services.GetRequiredService<ConfigurationService>();
            await configService.LoadAsync();

            Log.Information("Vyron Agent initialized successfully");
            Log.Information("Running in {Mode} mode", consoleMode ? "Console" : "Service");

            await host.RunAsync();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Vyron Agent terminated unexpectedly");
            throw;
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }
}
