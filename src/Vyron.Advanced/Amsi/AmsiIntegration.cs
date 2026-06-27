using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;
using System.Text;

namespace Vyron.Advanced.Amsi;

/// <summary>
/// Anti-Malware Scan Interface (AMSI) integration
/// Scans PowerShell, VBScript, JScript, and other dynamic content for malicious code
/// Provides real-time scanning of script execution before it runs
/// </summary>
public class AmsiIntegration : IDisposable
{
    private readonly ILogger<AmsiIntegration> _logger;
    private IntPtr _amsiContext = IntPtr.Zero;
    private bool _isInitialized;

    private readonly HashSet<string> _knownMaliciousPatterns = new()
    {
        "Invoke-Mimikatz", "Invoke-ReflectivePEInjection", "Invoke-Shellcode",
        "Invoke-DllInjection", "Invoke-WMICommand", "Get-GPPPassword",
        "Invoke-TokenManipulation", "PowerUp", "PowerSploit", "Empire",
        "Invoke-Obfuscation", "Out-EncryptedScript", "Invoke-CradleCrafter",
        "amsi.dll", "AmsiScanBuffer", "[Ref].Assembly.GetType",
        "System.Management.Automation.AmsiUtils", "-encodedcommand",
        "FromBase64String", "-enc", "-e ", "IEX", "Invoke-Expression",
        "DownloadString", "DownloadFile", "Net.WebClient", "Start-Process -WindowStyle Hidden",
        "Add-MpPreference -ExclusionPath", "Set-MpPreference -DisableRealtimeMonitoring"
    };

    public AmsiIntegration(ILogger<AmsiIntegration> logger)
    {
        _logger = logger;
    }

    public bool Initialize()
    {
        try
        {
            var result = AmsiInitialize("Vyron Advanced EDR", out _amsiContext);
            
            if (result != 0)
            {
                _logger.LogError("Failed to initialize AMSI: 0x{Result:X8}", result);
                return false;
            }

            _isInitialized = true;
            _logger.LogInformation("AMSI integration initialized successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error initializing AMSI");
            return false;
        }
    }

    public async Task<AmsiScanResult> ScanContentAsync(string content, string contentName, string contentType = "script")
    {
        if (!_isInitialized)
        {
            _logger.LogWarning("AMSI not initialized, cannot scan content");
            return new AmsiScanResult { IsClean = true, Result = AmsiResult.NotDetected };
        }

        var result = new AmsiScanResult
        {
            ContentName = contentName,
            ContentType = contentType,
            ContentLength = content.Length
        };

        try
        {
            // Pre-scan with pattern matching (faster than AMSI for known patterns)
            var patternMatch = await DetectKnownPatternsAsync(content);
            if (patternMatch.IsMatch)
            {
                result.IsClean = false;
                result.Result = AmsiResult.Detected;
                result.ThreatName = patternMatch.PatternName;
                result.Confidence = 0.95;
                result.MatchedPatterns = patternMatch.Patterns;
                
                _logger.LogWarning(
                    "Malicious pattern detected in {Name}: {Pattern}",
                    contentName, patternMatch.PatternName);
                
                return result;
            }

            // Scan with AMSI
            var contentBytes = Encoding.Unicode.GetBytes(content);
            AmsiResult amsiResult;

            var scanResult = AmsiScanBuffer(
                _amsiContext,
                contentBytes,
                (uint)contentBytes.Length,
                contentName,
                IntPtr.Zero,
                out amsiResult);

            if (scanResult != 0)
            {
                _logger.LogError("AMSI scan failed: 0x{Result:X8}", scanResult);
                result.IsClean = true; // Fail open
                result.Result = AmsiResult.NotDetected;
                return result;
            }

            result.Result = amsiResult;
            result.IsClean = amsiResult == AmsiResult.NotDetected || amsiResult == AmsiResult.Clean;
            result.Confidence = amsiResult == AmsiResult.Detected ? 0.90 : 0.0;

            if (!result.IsClean)
            {
                // Analyze what triggered detection
                result.MatchedPatterns = await AnalyzeDetectionAsync(content);
                result.ThreatName = DetermineThreatName(result.MatchedPatterns);

                _logger.LogWarning(
                    "AMSI detected malicious content in {Name}: {Result}, Threat: {Threat}",
                    contentName, amsiResult, result.ThreatName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning content with AMSI");
            result.IsClean = true; // Fail open
            result.Result = AmsiResult.NotDetected;
        }

        await Task.CompletedTask;
        return result;
    }

    public async Task<AmsiScanResult> ScanScriptFileAsync(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                _logger.LogWarning("Script file not found: {Path}", filePath);
                return new AmsiScanResult { IsClean = true, Result = AmsiResult.NotDetected };
            }

            var content = await File.ReadAllTextAsync(filePath);
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            
            var contentType = extension switch
            {
                ".ps1" => "PowerShell",
                ".vbs" => "VBScript",
                ".js" => "JavaScript",
                ".wsf" => "Windows Script File",
                ".hta" => "HTML Application",
                ".bat" => "Batch Script",
                ".cmd" => "Command Script",
                _ => "Unknown Script"
            };

            return await ScanContentAsync(content, Path.GetFileName(filePath), contentType);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning script file: {Path}", filePath);
            return new AmsiScanResult { IsClean = true, Result = AmsiResult.NotDetected };
        }
    }

    private async Task<PatternMatchResult> DetectKnownPatternsAsync(string content)
    {
        var result = new PatternMatchResult();
        var lowerContent = content.ToLowerInvariant();

        foreach (var pattern in _knownMaliciousPatterns)
        {
            if (lowerContent.Contains(pattern.ToLowerInvariant()))
            {
                result.IsMatch = true;
                result.Patterns.Add(pattern);
            }
        }

        if (result.IsMatch)
        {
            result.PatternName = DetermineThreatName(result.Patterns);
        }

        // Additional heuristics
        if (DetectObfuscation(content))
        {
            result.IsMatch = true;
            result.Patterns.Add("Obfuscated Code");
        }

        if (DetectBase64Execution(content))
        {
            result.IsMatch = true;
            result.Patterns.Add("Base64 Execution");
        }

        if (DetectAmsiBypass(content))
        {
            result.IsMatch = true;
            result.Patterns.Add("AMSI Bypass Attempt");
            result.PatternName = "AMSI Bypass";
        }

        await Task.CompletedTask;
        return result;
    }

    private bool DetectObfuscation(string content)
    {
        // Detect common PowerShell obfuscation techniques
        var obfuscationIndicators = new[]
        {
            "{0}{1}{2}", // Format string obfuscation
            "-join", // Character joining
            "[char]", // Character conversion
            "```", // Backtick obfuscation
            "$_", // Pipeline variable abuse
            ".invoke(", // Reflection invoke
            "::Create", // Static method abuse
        };

        var matchCount = obfuscationIndicators.Count(indicator => 
            content.Contains(indicator, StringComparison.OrdinalIgnoreCase));

        // If 3+ obfuscation techniques used, likely malicious
        return matchCount >= 3;
    }

    private bool DetectBase64Execution(string content)
    {
        // Detect base64 + execution pattern
        return (content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("[Convert]::FromBase64", StringComparison.OrdinalIgnoreCase)) &&
               (content.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("IEX", StringComparison.OrdinalIgnoreCase));
    }

    private bool DetectAmsiBypass(string content)
    {
        var amsiBypassIndicators = new[]
        {
            "AmsiUtils",
            "amsiInitFailed",
            "[Ref].Assembly.GetType",
            "Management.Automation.AmsiUtils",
            "amsi.dll",
            "AmsiScanBuffer"
        };

        return amsiBypassIndicators.Any(indicator =>
            content.Contains(indicator, StringComparison.OrdinalIgnoreCase));
    }

    private async Task<List<string>> AnalyzeDetectionAsync(string content)
    {
        var patterns = new List<string>();

        // Break content into chunks and scan each to identify trigger
        var chunkSize = Math.Max(100, content.Length / 10);
        
        for (int i = 0; i < content.Length; i += chunkSize)
        {
            var chunk = content.Substring(i, Math.Min(chunkSize, content.Length - i));
            
            foreach (var pattern in _knownMaliciousPatterns)
            {
                if (chunk.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    patterns.Add(pattern);
                }
            }
        }

        await Task.CompletedTask;
        return patterns.Distinct().ToList();
    }

    private string DetermineThreatName(List<string> patterns)
    {
        if (patterns.Count == 0)
            return "Unknown Threat";

        // Categorize based on patterns
        if (patterns.Any(p => p.Contains("Mimikatz", StringComparison.OrdinalIgnoreCase)))
            return "Credential Theft (Mimikatz)";
        
        if (patterns.Any(p => p.Contains("Shellcode", StringComparison.OrdinalIgnoreCase)))
            return "Code Injection (Shellcode)";
        
        if (patterns.Any(p => p.Contains("Empire", StringComparison.OrdinalIgnoreCase)))
            return "PowerShell Empire Framework";
        
        if (patterns.Any(p => p.Contains("Obfuscation", StringComparison.OrdinalIgnoreCase)))
            return "Obfuscated Malicious Script";
        
        if (patterns.Any(p => p.Contains("AMSI", StringComparison.OrdinalIgnoreCase)))
            return "AMSI Bypass Attempt";

        if (patterns.Any(p => p.Contains("GPPPassword", StringComparison.OrdinalIgnoreCase)))
            return "Credential Harvesting (GPP)";

        if (patterns.Any(p => p.Contains("Token", StringComparison.OrdinalIgnoreCase)))
            return "Privilege Escalation (Token Manipulation)";

        return $"Malicious Script ({patterns.First()})";
    }

    public void Dispose()
    {
        if (_amsiContext != IntPtr.Zero)
        {
            AmsiUninitialize(_amsiContext);
            _amsiContext = IntPtr.Zero;
        }

        _isInitialized = false;
    }

    #region Windows API

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll")]
    private static extern int AmsiScanBuffer(
        IntPtr amsiContext,
        byte[] buffer,
        uint length,
        string contentName,
        IntPtr session,
        out AmsiResult result);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr amsiContext);

    #endregion
}

public enum AmsiResult
{
    Clean = 0,
    NotDetected = 1,
    BlockedByAdminStart = 0x4000,
    BlockedByAdminEnd = 0x4fff,
    Detected = 32768
}

public class AmsiScanResult
{
    public string ContentName { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public int ContentLength { get; set; }
    public bool IsClean { get; set; }
    public AmsiResult Result { get; set; }
    public string ThreatName { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public List<string> MatchedPatterns { get; set; } = new();
}

public class PatternMatchResult
{
    public bool IsMatch { get; set; }
    public string PatternName { get; set; } = string.Empty;
    public List<string> Patterns { get; set; } = new();
}
