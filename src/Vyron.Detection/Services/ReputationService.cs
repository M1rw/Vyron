using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace Vyron.Detection.Services;

/// <summary>
/// Checks file and process reputation using local database and external sources
/// </summary>
public class ReputationService
{
    private readonly ILogger<ReputationService> _logger;
    private readonly HashSet<string> _knownGoodHashes = new();
    private readonly HashSet<string> _knownBadHashes = new();
    private readonly Dictionary<string, double> _reputationCache = new();

    public ReputationService(ILogger<ReputationService> logger)
    {
        _logger = logger;
    }

    public async Task InitializeAsync()
    {
        _logger.LogInformation("Initializing reputation service...");

        // Load known good hashes (system files, trusted apps)
        await LoadKnownGoodHashesAsync();
        
        // Load known bad hashes (malware database)
        await LoadKnownBadHashesAsync();

        _logger.LogInformation("Reputation service initialized. Good: {Good}, Bad: {Bad}",
            _knownGoodHashes.Count, _knownBadHashes.Count);
    }

    public async Task<double> CheckReputationAsync(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return 0.5; // Unknown

            var hash = await CalculateFileHashAsync(filePath);
            return await CheckFileHashReputationAsync(hash);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking reputation for: {File}", filePath);
            return 0.5; // Unknown
        }
    }

    public Task<double> CheckFileHashReputationAsync(string hash)
    {
        if (string.IsNullOrEmpty(hash))
            return Task.FromResult(0.5);

        // Check cache first
        if (_reputationCache.TryGetValue(hash, out var cachedScore))
            return Task.FromResult(cachedScore);

        double reputation;

        // Known malware
        if (_knownBadHashes.Contains(hash))
        {
            reputation = 0.0;
        }
        // Known good
        else if (_knownGoodHashes.Contains(hash))
        {
            reputation = 1.0;
        }
        // Unknown - neutral score
        else
        {
            reputation = 0.5;
            
            // In a production system, query external reputation services here:
            // - VirusTotal API
            // - Microsoft Defender Intelligence
            // - Community threat feeds
        }

        // Cache the result
        _reputationCache[hash] = reputation;

        return Task.FromResult(reputation);
    }

    private async Task LoadKnownGoodHashesAsync()
    {
        try
        {
            // In production, load from a curated database of known-good hashes
            // For now, we'll add common system files
            var systemPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            };

            // Add a few critical system files
            var criticalFiles = new[]
            {
                Path.Combine(systemPaths[0], "kernel32.dll"),
                Path.Combine(systemPaths[0], "ntdll.dll"),
                Path.Combine(systemPaths[0], "user32.dll"),
                Path.Combine(systemPaths[1], "explorer.exe")
            };

            foreach (var file in criticalFiles)
            {
                if (File.Exists(file))
                {
                    try
                    {
                        var hash = await CalculateFileHashAsync(file);
                        _knownGoodHashes.Add(hash);
                    }
                    catch { }
                }
            }

            _logger.LogDebug("Loaded {Count} known good hashes", _knownGoodHashes.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading known good hashes");
        }
    }

    private async Task LoadKnownBadHashesAsync()
    {
        try
        {
            // In production, load from threat intelligence feeds
            // This would include hashes from:
            // - Known malware samples
            // - Threat intelligence platforms
            // - Security vendor feeds
            
            var badHashesFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Vyron", "Data", "bad_hashes.txt");

            if (File.Exists(badHashesFile))
            {
                var lines = await File.ReadAllLinesAsync(badHashesFile);
                foreach (var line in lines)
                {
                    var hash = line.Trim();
                    if (!string.IsNullOrEmpty(hash) && hash.Length == 64) // SHA256 length
                    {
                        _knownBadHashes.Add(hash.ToLowerInvariant());
                    }
                }
            }

            _logger.LogDebug("Loaded {Count} known bad hashes", _knownBadHashes.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading known bad hashes");
        }
    }

    private async Task<string> CalculateFileHashAsync(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = await sha256.ComputeHashAsync(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    public void AddBadHash(string hash)
    {
        if (!string.IsNullOrEmpty(hash))
        {
            _knownBadHashes.Add(hash.ToLowerInvariant());
            _reputationCache[hash] = 0.0;
        }
    }

    public void AddGoodHash(string hash)
    {
        if (!string.IsNullOrEmpty(hash))
        {
            _knownGoodHashes.Add(hash.ToLowerInvariant());
            _reputationCache[hash] = 1.0;
        }
    }
}
