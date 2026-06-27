using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using Vyron.Core.Models;
using Vyron.Core.Services;

namespace Vyron.Detection.Services;

/// <summary>
/// Orchestrates response actions to detected threats
/// </summary>
public class ResponseOrchestrator
{
    private readonly ILogger<ResponseOrchestrator> _logger;
    private readonly ConfigurationService _configService;
    private readonly QuarantineService _quarantineService;

    public ResponseOrchestrator(
        ILogger<ResponseOrchestrator> logger,
        ConfigurationService configService,
        QuarantineService quarantineService)
    {
        _logger = logger;
        _configService = configService;
        _quarantineService = quarantineService;
    }

    public async Task HandleThreatAsync(ThreatEvent threat, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogWarning("Handling threat: {Type} - {Severity} - Confidence: {Score:P0}",
                threat.Type, threat.Severity, threat.ConfidenceScore);

            var config = _configService.GetConfig();
            var actions = DetermineActions(threat, config);

            foreach (var action in actions)
            {
                await ExecuteActionAsync(action, threat, cancellationToken);
            }

            // Log to Windows Event Log
            if (config.Response.EnableEventLog)
            {
                LogToEventLog(threat);
            }

            // Store threat event for learning
            if (config.Learning.StoreTrainingData)
            {
                await StoreThreatEventAsync(threat);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling threat: {Threat}", threat.Id);
        }
    }

    private List<ResponseAction> DetermineActions(ThreatEvent threat, Core.Configuration.VyronConfig config)
    {
        var actions = new List<ResponseAction> { ResponseAction.Alert };

        // Check if auto-response is enabled and severity threshold is met
        var minSeverity = Enum.Parse<ThreatSeverity>(config.Response.MinimumSeverityForAutoResponse);
        
        if (threat.Severity < minSeverity)
        {
            return actions; // Only alert for low severity
        }

        // Terminate malicious processes
        if (config.Response.AutoTerminateProcess && threat.ProcessId > 0)
        {
            actions.Add(ResponseAction.TerminateProcess);
        }

        // Quarantine malicious files
        if (config.Response.AutoQuarantine && !string.IsNullOrEmpty(threat.FilePath))
        {
            actions.Add(ResponseAction.Quarantine);
        }

        return actions;
    }

    private async Task ExecuteActionAsync(ResponseAction action, ThreatEvent threat, CancellationToken cancellationToken)
    {
        try
        {
            switch (action)
            {
                case ResponseAction.Alert:
                    await SendAlertAsync(threat);
                    break;

                case ResponseAction.TerminateProcess:
                    await TerminateProcessAsync(threat);
                    break;

                case ResponseAction.Quarantine:
                    await QuarantineFileAsync(threat);
                    break;

                case ResponseAction.Block:
                    // Future: Block network connections, registry access, etc.
                    _logger.LogInformation("Block action not yet implemented");
                    break;

                case ResponseAction.IsolateHost:
                    // Future: Network isolation
                    _logger.LogInformation("Host isolation not yet implemented");
                    break;
            }

            threat.ActionTaken = action;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute action {Action} for threat {Id}", action, threat.Id);
        }
    }

    private Task SendAlertAsync(ThreatEvent threat)
    {
        // In production, send alerts via:
        // - Email
        // - SMS
        // - SIEM integration
        // - Management console
        // - Windows notifications

        _logger.LogWarning(
            "ALERT: {Type} detected - {Process} (PID: {Pid}) - Severity: {Severity} - Confidence: {Score:P0}",
            threat.Type, threat.ProcessName, threat.ProcessId, threat.Severity, threat.ConfidenceScore);

        return Task.CompletedTask;
    }

    private async Task TerminateProcessAsync(ThreatEvent threat)
    {
        try
        {
            if (threat.ProcessId <= 0)
            {
                _logger.LogWarning("Cannot terminate process - invalid PID: {Pid}", threat.ProcessId);
                return;
            }

            // Don't terminate critical system processes
            if (IsCriticalProcess(threat.ProcessName))
            {
                _logger.LogWarning("Cannot terminate critical system process: {Process}", threat.ProcessName);
                return;
            }

            var process = Process.GetProcessById(threat.ProcessId);
            process.Kill(entireProcessTree: true);
            
            _logger.LogWarning("Terminated malicious process: {Process} (PID: {Pid})", 
                threat.ProcessName, threat.ProcessId);

            await Task.CompletedTask;
        }
        catch (ArgumentException)
        {
            _logger.LogWarning("Process no longer exists: {Pid}", threat.ProcessId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to terminate process: {Pid}", threat.ProcessId);
        }
    }

    private async Task QuarantineFileAsync(ThreatEvent threat)
    {
        if (string.IsNullOrEmpty(threat.FilePath))
        {
            _logger.LogWarning("Cannot quarantine - no file path specified");
            return;
        }

        var success = await _quarantineService.QuarantineFileAsync(threat.FilePath, threat);
        
        if (success)
        {
            _logger.LogWarning("File quarantined: {Path}", threat.FilePath);
        }
        else
        {
            _logger.LogError("Failed to quarantine file: {Path}", threat.FilePath);
        }
    }

    private bool IsCriticalProcess(string processName)
    {
        var criticalProcesses = new[]
        {
            "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe"
        };

        return criticalProcesses.Any(p => 
            processName.Equals(p, StringComparison.OrdinalIgnoreCase));
    }

    private void LogToEventLog(ThreatEvent threat)
    {
        try
        {
            const string source = "Vyron";
            const string logName = "Application";

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, logName);
            }

            var message = $"Threat Detected\n" +
                         $"Type: {threat.Type}\n" +
                         $"Severity: {threat.Severity}\n" +
                         $"Process: {threat.ProcessName} (PID: {threat.ProcessId})\n" +
                         $"File: {threat.FilePath}\n" +
                         $"Confidence: {threat.ConfidenceScore:P0}\n" +
                         $"Detection Method: {threat.DetectionMethod}\n" +
                         $"Action Taken: {threat.ActionTaken}";

            var eventType = threat.Severity >= ThreatSeverity.High 
                ? EventLogEntryType.Error 
                : EventLogEntryType.Warning;

            EventLog.WriteEntry(source, message, eventType, (int)threat.Severity);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write to Event Log");
        }
    }

    private async Task StoreThreatEventAsync(ThreatEvent threat)
    {
        try
        {
            var dataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Vyron", "Data", "threats");

            if (!Directory.Exists(dataPath))
            {
                Directory.CreateDirectory(dataPath);
            }

            var fileName = $"{DateTime.UtcNow:yyyyMMdd}_{threat.Id}.json";
            var filePath = Path.Combine(dataPath, fileName);

            var json = System.Text.Json.JsonSerializer.Serialize(threat, 
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            
            await File.WriteAllTextAsync(filePath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to store threat event");
        }
    }
}
