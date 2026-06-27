using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Text.Json;
using Vyron.Core.Models;

namespace Vyron.Detection.Services;

/// <summary>
/// Securely quarantines suspicious files
/// </summary>
public class QuarantineService
{
    private readonly ILogger<QuarantineService> _logger;
    private readonly string _quarantinePath;
    private readonly string _metadataPath;

    public QuarantineService(ILogger<QuarantineService> logger)
    {
        _logger = logger;
        _quarantinePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Vyron", "Quarantine");
        _metadataPath = Path.Combine(_quarantinePath, "metadata.json");
        
        EnsureQuarantineDirectory();
    }

    private void EnsureQuarantineDirectory()
    {
        if (!Directory.Exists(_quarantinePath))
        {
            Directory.CreateDirectory(_quarantinePath);
            
            // Set restrictive permissions
            try
            {
                var dirInfo = new DirectoryInfo(_quarantinePath);
                var security = dirInfo.GetAccessControl();
                // In production, lock down permissions to SYSTEM and Administrators only
                _logger.LogInformation("Quarantine directory created: {Path}", _quarantinePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set quarantine directory permissions");
            }
        }
    }

    public async Task<bool> QuarantineFileAsync(string filePath, ThreatEvent threat)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                _logger.LogWarning("Cannot quarantine - file not found: {Path}", filePath);
                return false;
            }

            var quarantineId = Guid.NewGuid().ToString();
            var quarantinedFileName = $"{quarantineId}.quarantine";
            var quarantinedPath = Path.Combine(_quarantinePath, quarantinedFileName);

            // Move file to quarantine
            File.Move(filePath, quarantinedPath, true);

            // Save metadata
            var metadata = new QuarantineMetadata
            {
                Id = quarantineId,
                OriginalPath = filePath,
                QuarantinedPath = quarantinedPath,
                QuarantineDate = DateTime.UtcNow,
                ThreatType = threat.Type.ToString(),
                Severity = threat.Severity.ToString(),
                FileHash = threat.FileHash,
                Reason = threat.Metadata.GetValueOrDefault("DetectionReasons", "Unknown"),
                CanRestore = true
            };

            await SaveQuarantineMetadataAsync(metadata);

            _logger.LogWarning("File quarantined: {Original} -> {Quarantine}", filePath, quarantinedPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to quarantine file: {Path}", filePath);
            return false;
        }
    }

    public async Task<bool> RestoreFileAsync(string quarantineId)
    {
        try
        {
            var metadata = await LoadQuarantineMetadataAsync(quarantineId);
            if (metadata == null)
            {
                _logger.LogWarning("Quarantine metadata not found: {Id}", quarantineId);
                return false;
            }

            if (!metadata.CanRestore)
            {
                _logger.LogWarning("File cannot be restored: {Id}", quarantineId);
                return false;
            }

            if (!File.Exists(metadata.QuarantinedPath))
            {
                _logger.LogWarning("Quarantined file not found: {Path}", metadata.QuarantinedPath);
                return false;
            }

            // Restore file to original location
            var directory = Path.GetDirectoryName(metadata.OriginalPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.Move(metadata.QuarantinedPath, metadata.OriginalPath, true);

            // Remove metadata
            await RemoveQuarantineMetadataAsync(quarantineId);

            _logger.LogInformation("File restored from quarantine: {Path}", metadata.OriginalPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore file from quarantine: {Id}", quarantineId);
            return false;
        }
    }

    public async Task<bool> DeleteQuarantinedFileAsync(string quarantineId)
    {
        try
        {
            var metadata = await LoadQuarantineMetadataAsync(quarantineId);
            if (metadata == null)
                return false;

            if (File.Exists(metadata.QuarantinedPath))
            {
                File.Delete(metadata.QuarantinedPath);
            }

            await RemoveQuarantineMetadataAsync(quarantineId);

            _logger.LogInformation("Quarantined file permanently deleted: {Id}", quarantineId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete quarantined file: {Id}", quarantineId);
            return false;
        }
    }

    private async Task SaveQuarantineMetadataAsync(QuarantineMetadata metadata)
    {
        var allMetadata = await LoadAllMetadataAsync();
        allMetadata[metadata.Id] = metadata;
        
        var json = JsonSerializer.Serialize(allMetadata, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_metadataPath, json);
    }

    private async Task<QuarantineMetadata?> LoadQuarantineMetadataAsync(string quarantineId)
    {
        var allMetadata = await LoadAllMetadataAsync();
        return allMetadata.GetValueOrDefault(quarantineId);
    }

    private async Task RemoveQuarantineMetadataAsync(string quarantineId)
    {
        var allMetadata = await LoadAllMetadataAsync();
        allMetadata.Remove(quarantineId);
        
        var json = JsonSerializer.Serialize(allMetadata, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_metadataPath, json);
    }

    private async Task<Dictionary<string, QuarantineMetadata>> LoadAllMetadataAsync()
    {
        if (!File.Exists(_metadataPath))
            return new Dictionary<string, QuarantineMetadata>();

        try
        {
            var json = await File.ReadAllTextAsync(_metadataPath);
            return JsonSerializer.Deserialize<Dictionary<string, QuarantineMetadata>>(json) 
                   ?? new Dictionary<string, QuarantineMetadata>();
        }
        catch
        {
            return new Dictionary<string, QuarantineMetadata>();
        }
    }
}

public class QuarantineMetadata
{
    public string Id { get; set; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinedPath { get; set; } = string.Empty;
    public DateTime QuarantineDate { get; set; }
    public string ThreatType { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string FileHash { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public bool CanRestore { get; set; }
}
