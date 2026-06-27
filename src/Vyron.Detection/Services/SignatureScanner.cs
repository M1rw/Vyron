using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

namespace Vyron.Detection.Services;

/// <summary>
/// Signature-based malware scanner (YARA-like rules)
/// </summary>
public class SignatureScanner
{
    private readonly ILogger<SignatureScanner> _logger;
    private readonly List<MalwareSignature> _signatures = new();

    public SignatureScanner(ILogger<SignatureScanner> logger)
    {
        _logger = logger;
    }

    public async Task LoadRulesAsync(string rulesPath)
    {
        try
        {
            if (!Directory.Exists(rulesPath))
            {
                _logger.LogWarning("Signature rules directory not found: {Path}. Creating with default rules.", rulesPath);
                Directory.CreateDirectory(rulesPath);
                await CreateDefaultRulesAsync(rulesPath);
            }

            var ruleFiles = Directory.GetFiles(rulesPath, "*.rule");
            
            foreach (var ruleFile in ruleFiles)
            {
                await LoadRuleFileAsync(ruleFile);
            }

            _logger.LogInformation("Loaded {Count} signature rules", _signatures.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load signature rules");
        }
    }

    private async Task LoadRuleFileAsync(string filePath)
    {
        try
        {
            var content = await File.ReadAllTextAsync(filePath);
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("#") || string.IsNullOrWhiteSpace(trimmed))
                    continue;

                // Simple format: RuleName|Pattern|Type
                var parts = trimmed.Split('|');
                if (parts.Length >= 3)
                {
                    _signatures.Add(new MalwareSignature
                    {
                        Name = parts[0],
                        Pattern = parts[1],
                        Type = parts[2]
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load rule file: {File}", filePath);
        }
    }

    private async Task CreateDefaultRulesAsync(string rulesPath)
    {
        var defaultRules = @"# Default Vyron Malware Signatures
# Format: RuleName|Pattern|Type

# Ransomware indicators
Ransomware_ShadowDelete|vssadmin.*delete.*shadows|Ransomware
Ransomware_BackupDelete|wbadmin.*delete.*catalog|Ransomware
Ransomware_RecoveryDisable|bcdedit.*recoveryenabled.*no|Ransomware
Ransomware_FileEncryption|\.encrypted$|\.locked$|\.crypto$|Ransomware

# Persistence mechanisms
Persistence_Registry|reg.*add.*run|PersistenceMechanism
Persistence_Startup|\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup|PersistenceMechanism
Persistence_ScheduledTask|schtasks.*create.*run|PersistenceMechanism

# Command and Control
C2_PowershellDownload|powershell.*downloadstring|CommandAndControl
C2_BitsTransfer|Start-BitsTransfer.*http|CommandAndControl

# Credential theft
CredTheft_Mimikatz|mimikatz|sekurlsa|CredentialTheft
CredTheft_LSASS|lsass\.exe.*dump|CredentialTheft

# Suspicious behavior
Suspicious_NoWindow|CreateNoWindow.*true|SuspiciousBehavior
Suspicious_EncodedCommand|powershell.*-enc.*-nop|SuspiciousBehavior
Suspicious_Base64|[A-Za-z0-9+/]{200,}={0,2}|SuspiciousBehavior

# Known malware families
Malware_WannaCry|wannacry|wcry|Ransomware
Malware_Emotet|emotet|Trojan
Malware_TrickBot|trickbot|Trojan
";

        var rulesFile = Path.Combine(rulesPath, "default.rule");
        await File.WriteAllTextAsync(rulesFile, defaultRules);
        _logger.LogInformation("Created default signature rules at: {Path}", rulesFile);
    }

    public async Task<SignatureScanResult> ScanFileAsync(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return new SignatureScanResult { IsMatch = false };
            }

            // Read file content for pattern matching
            var content = await File.ReadAllTextAsync(filePath);
            
            // Also check file name and path
            var combinedText = $"{filePath} {Path.GetFileName(filePath)} {content}";

            foreach (var signature in _signatures)
            {
                try
                {
                    if (Regex.IsMatch(combinedText, signature.Pattern, RegexOptions.IgnoreCase))
                    {
                        _logger.LogWarning("Signature match: {Rule} in {File}", signature.Name, filePath);
                        
                        return new SignatureScanResult
                        {
                            IsMatch = true,
                            RuleName = signature.Name,
                            ThreatType = signature.Type
                        };
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error matching pattern for rule: {Rule}", signature.Name);
                }
            }

            return new SignatureScanResult { IsMatch = false };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning file: {File}", filePath);
            return new SignatureScanResult { IsMatch = false };
        }
    }
}

public class MalwareSignature
{
    public string Name { get; set; } = string.Empty;
    public string Pattern { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
}

public class SignatureScanResult
{
    public bool IsMatch { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public string ThreatType { get; set; } = string.Empty;
}
