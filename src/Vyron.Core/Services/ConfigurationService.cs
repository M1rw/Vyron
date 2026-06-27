using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using Vyron.Core.Configuration;

namespace Vyron.Core.Services;

/// <summary>
/// Manages configuration loading and persistence
/// </summary>
public class ConfigurationService
{
    private readonly ILogger<ConfigurationService> _logger;
    private readonly string _configPath;
    private VyronConfig _config;

    public ConfigurationService(ILogger<ConfigurationService> logger)
    {
        _logger = logger;
        _configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Vyron",
            "config.json"
        );
        _config = new VyronConfig();
    }

    public VyronConfig GetConfig() => _config;

    public async Task LoadAsync()
    {
        try
        {
            if (!File.Exists(_configPath))
            {
                _logger.LogWarning("Configuration file not found at {Path}. Creating default configuration.", _configPath);
                await CreateDefaultConfigAsync();
                return;
            }

            var json = await File.ReadAllTextAsync(_configPath);
            _config = JsonSerializer.Deserialize<VyronConfig>(json) ?? new VyronConfig();
            
            _logger.LogInformation("Configuration loaded successfully from {Path}", _configPath);
            ValidateConfiguration();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load configuration. Using defaults.");
            _config = new VyronConfig();
        }
    }

    public async Task SaveAsync()
    {
        try
        {
            var directory = Path.GetDirectoryName(_configPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            var json = JsonSerializer.Serialize(_config, options);
            await File.WriteAllTextAsync(_configPath, json);
            
            _logger.LogInformation("Configuration saved to {Path}", _configPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save configuration");
            throw;
        }
    }

    private async Task CreateDefaultConfigAsync()
    {
        _config = new VyronConfig();
        await SaveAsync();
    }

    private void ValidateConfiguration()
    {
        // Ensure critical directories exist
        EnsureDirectoryExists(_config.Detection.YaraRulesPath);
        EnsureDirectoryExists(_config.Response.QuarantinePath);
        EnsureDirectoryExists(_config.Storage.DataPath);
        EnsureDirectoryExists(_config.Storage.LogPath);

        // Validate thresholds
        if (_config.Detection.MinimumConfidenceThreshold < 0 || _config.Detection.MinimumConfidenceThreshold > 1)
        {
            _logger.LogWarning("Invalid confidence threshold. Resetting to 0.7");
            _config.Detection.MinimumConfidenceThreshold = 0.7;
        }
    }

    private void EnsureDirectoryExists(string path)
    {
        if (!Directory.Exists(path))
        {
            try
            {
                Directory.CreateDirectory(path);
                _logger.LogInformation("Created directory: {Path}", path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create directory: {Path}", path);
            }
        }
    }
}
