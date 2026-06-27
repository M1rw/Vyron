using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Vyron.Core.Services;
using Vyron.Monitoring.Services;
using Vyron.Detection.Services;

namespace Vyron.Agent;

/// <summary>
/// Main worker service that orchestrates all Vyron components
/// </summary>
public class VyronWorkerService : BackgroundService
{
    private readonly ILogger<VyronWorkerService> _logger;
    private readonly ConfigurationService _configService;
    private readonly ProcessMonitorService _processMonitor;
    private readonly FileMonitorService _fileMonitor;
    private readonly DetectionEngine _detectionEngine;
    private readonly ResponseOrchestrator _responseOrchestrator;

    public VyronWorkerService(
        ILogger<VyronWorkerService> logger,
        ConfigurationService configService,
        ProcessMonitorService processMonitor,
        FileMonitorService fileMonitor,
        DetectionEngine detectionEngine,
        ResponseOrchestrator responseOrchestrator)
    {
        _logger = logger;
        _configService = configService;
        _processMonitor = processMonitor;
        _fileMonitor = fileMonitor;
        _detectionEngine = detectionEngine;
        _responseOrchestrator = responseOrchestrator;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Vyron Worker Service starting at: {Time}", DateTimeOffset.Now);

        try
        {
            // Load configuration
            await _configService.LoadAsync();
            var config = _configService.GetConfig();

            _logger.LogInformation("Starting detection engine...");
            await _detectionEngine.InitializeAsync(stoppingToken);

            // Start monitors based on configuration
            if (config.Monitoring.EnableProcessMonitoring)
            {
                _logger.LogInformation("Starting process monitoring...");
                _ = Task.Run(() => _processMonitor.StartAsync(stoppingToken), stoppingToken);
            }

            if (config.Monitoring.EnableFileMonitoring)
            {
                _logger.LogInformation("Starting file system monitoring...");
                _ = Task.Run(() => _fileMonitor.StartAsync(stoppingToken), stoppingToken);
            }

            // Subscribe to threat detections
            _detectionEngine.ThreatDetected += async (sender, threat) =>
            {
                _logger.LogWarning("Threat detected: {Type} - {Severity} - {Process} (Confidence: {Score:P0})",
                    threat.Type, threat.Severity, threat.ProcessName, threat.ConfidenceScore);
                
                await _responseOrchestrator.HandleThreatAsync(threat, stoppingToken);
            };

            _logger.LogInformation("Vyron Agent is now actively protecting the system");

            // Keep service running
            while (!stoppingToken.IsCancellationRequested)
            {
                // Perform periodic health checks and maintenance
                await PerformMaintenanceAsync(stoppingToken);
                
                // Wait before next cycle
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Vyron Worker Service is stopping due to cancellation");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Vyron Worker Service encountered a critical error");
            throw;
        }
    }

    private async Task PerformMaintenanceAsync(CancellationToken cancellationToken)
    {
        try
        {
            var config = _configService.GetConfig();
            
            // Log current status
            _logger.LogDebug("Performing maintenance cycle");
            
            // Check for signature updates
            if (config.Updates.AutoUpdate)
            {
                // TODO: Implement signature update check
            }
            
            // Clean old logs
            await CleanOldLogsAsync(config.Storage.LogPath, config.Storage.LogRetentionDays);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during maintenance cycle");
        }
    }

    private async Task CleanOldLogsAsync(string logPath, int retentionDays)
    {
        try
        {
            if (!Directory.Exists(logPath))
                return;

            var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
            var oldLogs = Directory.GetFiles(logPath, "*.log")
                .Where(f => File.GetCreationTimeUtc(f) < cutoffDate);

            foreach (var log in oldLogs)
            {
                try
                {
                    File.Delete(log);
                    _logger.LogDebug("Deleted old log file: {File}", log);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to delete log file: {File}", log);
                }
            }

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning old logs");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Vyron Worker Service is stopping at: {Time}", DateTimeOffset.Now);
        
        // Gracefully stop all monitors
        await _processMonitor.StopAsync(cancellationToken);
        await _fileMonitor.StopAsync(cancellationToken);
        
        await base.StopAsync(cancellationToken);
    }
}
