using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using Vyron.Core.Models;
using Vyron.Core.Services;

namespace Vyron.Monitoring.Services;

/// <summary>
/// Monitors file system changes using FileSystemWatcher with enhanced filtering
/// </summary>
public class FileMonitorService
{
    private readonly ILogger<FileMonitorService> _logger;
    private readonly ConfigurationService _configService;
    private readonly List<FileSystemWatcher> _watchers = new();
    
    public event EventHandler<FileEvent>? FileEventDetected;

    public FileMonitorService(
        ILogger<FileMonitorService> logger,
        ConfigurationService configService)
    {
        _logger = logger;
        _configService = configService;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Starting file system monitoring...");

            var config = _configService.GetConfig();
            var monitoredPaths = config.Monitoring.MonitoredPaths;

            foreach (var path in monitoredPaths)
            {
                if (!Directory.Exists(path))
                {
                    _logger.LogWarning("Monitored path does not exist: {Path}", path);
                    continue;
                }

                try
                {
                    var watcher = new FileSystemWatcher(path)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName |
                                     NotifyFilters.DirectoryName |
                                     NotifyFilters.Size |
                                     NotifyFilters.LastWrite |
                                     NotifyFilters.CreationTime
                    };

                    // Subscribe to events
                    watcher.Created += OnFileCreated;
                    watcher.Changed += OnFileChanged;
                    watcher.Deleted += OnFileDeleted;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Error += OnError;

                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);

                    _logger.LogInformation("Monitoring file system path: {Path}", path);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to start monitoring path: {Path}", path);
                }
            }

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start file system monitoring");
            throw;
        }
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        ProcessFileEvent(e.FullPath, FileEventType.Created);
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        ProcessFileEvent(e.FullPath, FileEventType.Modified);
    }

    private void OnFileDeleted(object sender, FileSystemEventArgs e)
    {
        ProcessFileEvent(e.FullPath, FileEventType.Deleted);
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        ProcessFileEvent(e.FullPath, FileEventType.Renamed, e.OldFullPath);
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        _logger.LogError(e.GetException(), "File system watcher error");
    }

    private void ProcessFileEvent(string filePath, FileEventType eventType, string? oldPath = null)
    {
        try
        {
            var config = _configService.GetConfig();

            // Check if path should be excluded
            if (config.Monitoring.ExcludedPaths.Any(excluded => 
                filePath.StartsWith(excluded, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists && eventType != FileEventType.Deleted)
            {
                return;
            }

            // Filter by priority extensions
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            bool isHighPriority = config.Monitoring.HighPriorityExtensions.Contains(extension);
            bool isExecutable = extension == ".exe" || extension == ".dll" || extension == ".sys";

            // Only process high-priority files or executables
            if (!isHighPriority && !isExecutable)
            {
                return;
            }

            var fileEvent = new FileEvent
            {
                EventType = eventType,
                FilePath = filePath,
                FileExtension = extension,
                FileSize = fileInfo.Exists ? fileInfo.Length : 0,
                Timestamp = DateTime.UtcNow,
                IsExecutable = isExecutable,
                IsSystemFile = IsSystemFile(filePath)
            };

            // Calculate file hash for created/modified files
            if ((eventType == FileEventType.Created || eventType == FileEventType.Modified) && 
                fileInfo.Exists && fileInfo.Length < 100 * 1024 * 1024) // Max 100MB for hashing
            {
                try
                {
                    fileEvent.FileHash = CalculateFileHash(filePath);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Could not calculate hash for: {Path}", filePath);
                }
            }

            // Get process information (if available)
            try
            {
                var process = System.Diagnostics.Process.GetCurrentProcess();
                fileEvent.ProcessName = process.ProcessName;
                fileEvent.ProcessId = process.Id;
                fileEvent.UserName = Environment.UserName;
            }
            catch { }

            FileEventDetected?.Invoke(this, fileEvent);
            
            _logger.LogDebug("File event: {Type} - {Path}", eventType, filePath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing file event for: {Path}", filePath);
        }
    }

    private bool IsSystemFile(string filePath)
    {
        try
        {
            var systemPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            return systemPaths.Any(sysPath => 
                filePath.StartsWith(sysPath, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    private string CalculateFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping file system monitoring...");
        
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
        
        _watchers.Clear();
        
        return Task.CompletedTask;
    }
}
