using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using Vyron.Core.Models;

namespace Vyron.Monitoring.Services;

/// <summary>
/// Monitors process creation and termination using ETW
/// </summary>
public class ProcessMonitorService
{
    private readonly ILogger<ProcessMonitorService> _logger;
    private TraceEventSession? _session;
    private CancellationTokenSource? _cts;
    
    public event EventHandler<ProcessEvent>? ProcessEventDetected;

    public ProcessMonitorService(ILogger<ProcessMonitorService> logger)
    {
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Starting process monitoring with ETW...");

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            // Run ETW monitoring in background
            await Task.Run(() => StartEtwMonitoring(_cts.Token), cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start process monitoring");
            throw;
        }
    }

    private void StartEtwMonitoring(CancellationToken cancellationToken)
    {
        try
        {
            // Create a new ETW session for process monitoring
            var sessionName = "VyronProcessMonitor";
            
            // Clean up any existing session
            TraceEventSession.GetActiveSessionNames()
                .Where(s => s.Equals(sessionName, StringComparison.OrdinalIgnoreCase))
                .ToList()
                .ForEach(s => {
                    try { TraceEventSession.GetActiveSession(s)?.Dispose(); }
                    catch { }
                });

            _session = new TraceEventSession(sessionName);
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | 
                                         KernelTraceEventParser.Keywords.ImageLoad);

            // Subscribe to process start events
            _session.Source.Kernel.ProcessStart += (data) =>
            {
                try
                {
                    var processEvent = new ProcessEvent
                    {
                        EventType = ProcessEventType.Created,
                        ProcessId = data.ProcessID,
                        ProcessName = data.ProcessName ?? "Unknown",
                        ExecutablePath = data.ImageFileName ?? string.Empty,
                        CommandLine = data.CommandLine ?? string.Empty,
                        ParentProcessId = data.ParentID,
                        Timestamp = data.TimeStamp,
                        UserName = Environment.UserName,
                        SessionId = data.SessionID.ToString()
                    };

                    ProcessEventDetected?.Invoke(this, processEvent);
                    
                    _logger.LogDebug("Process started: {Process} (PID: {Pid})", 
                        processEvent.ProcessName, processEvent.ProcessId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing process start event");
                }
            };

            // Subscribe to process stop events
            _session.Source.Kernel.ProcessStop += (data) =>
            {
                try
                {
                    var processEvent = new ProcessEvent
                    {
                        EventType = ProcessEventType.Terminated,
                        ProcessId = data.ProcessID,
                        ProcessName = data.ProcessName ?? "Unknown",
                        Timestamp = data.TimeStamp
                    };

                    ProcessEventDetected?.Invoke(this, processEvent);
                    
                    _logger.LogDebug("Process terminated: {Process} (PID: {Pid})", 
                        processEvent.ProcessName, processEvent.ProcessId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing process stop event");
                }
            };

            _logger.LogInformation("ETW process monitoring session started");

            // Process events (blocking call)
            _session.Source.Process();
        }
        catch (UnauthorizedAccessException)
        {
            _logger.LogError("Insufficient privileges for ETW monitoring. Service must run with Administrator rights.");
            // Fall back to WMI monitoring
            FallbackToWmiMonitoring(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ETW monitoring failed");
            // Fall back to WMI monitoring
            FallbackToWmiMonitoring(cancellationToken);
        }
    }

    private void FallbackToWmiMonitoring(CancellationToken cancellationToken)
    {
        _logger.LogWarning("Falling back to WMI-based process monitoring (higher latency)");
        
        try
        {
            // Use WMI to monitor process creation
            var processStartWatcher = new System.Management.ManagementEventWatcher(
                new System.Management.EventQuery("SELECT * FROM Win32_ProcessStartTrace"));

            processStartWatcher.EventArrived += (sender, e) =>
            {
                try
                {
                    var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                    var processName = e.NewEvent.Properties["ProcessName"].Value?.ToString() ?? "Unknown";

                    var processEvent = new ProcessEvent
                    {
                        EventType = ProcessEventType.Created,
                        ProcessId = processId,
                        ProcessName = processName,
                        Timestamp = DateTime.UtcNow
                    };

                    ProcessEventDetected?.Invoke(this, processEvent);
                    
                    _logger.LogDebug("Process started (WMI): {Process} (PID: {Pid})", 
                        processName, processId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing WMI process start event");
                }
            };

            processStartWatcher.Start();
            
            _logger.LogInformation("WMI process monitoring started");

            // Keep monitoring active
            cancellationToken.WaitHandle.WaitOne();
            
            processStartWatcher.Stop();
            processStartWatcher.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WMI monitoring also failed");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping process monitoring...");
        
        _cts?.Cancel();
        _session?.Dispose();
        
        return Task.CompletedTask;
    }
}
