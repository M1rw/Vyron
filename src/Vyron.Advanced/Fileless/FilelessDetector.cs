using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Vyron.Advanced.Fileless;

/// <summary>
/// Advanced Fileless & Living-off-the-Land Binaries (LOLBin) Detector
/// Detects abuse of legitimate Windows binaries for malicious purposes
/// Covers PowerShell, WMI, CertUtil, BITSAdmin, Registry-only malware, etc.
/// </summary>
public class FilelessDetector
{
    private readonly ILogger<FilelessDetector> _logger;

    // LOLBin database with abuse patterns
    private readonly Dictionary<string, List<LolbinPattern>> _lolbinPatterns = new()
    {
        ["powershell.exe"] = new()
        {
            new() { Pattern = @"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", Description = "Encoded command execution", Severity = "High" },
            new() { Pattern = @"DownloadString|DownloadFile|WebClient|Invoke-WebRequest.*IEX|Invoke-Expression", Description = "Remote script download and execution", Severity = "Critical" },
            new() { Pattern = @"-w(indowstyle)?\s+h(idden)?", Description = "Hidden window execution", Severity = "Medium" },
            new() { Pattern = @"Bypass.*ExecutionPolicy", Description = "Execution policy bypass", Severity = "High" },
            new() { Pattern = @"Reflection\.Assembly.*Load", Description = "Reflective assembly loading", Severity = "Critical" },
            new() { Pattern = @"Add-MpPreference\s+-Exclusion", Description = "Defender exclusion addition", Severity = "Critical" },
        },
        ["cmd.exe"] = new()
        {
            new() { Pattern = @"/c\s+echo.*>\s*\\\\", Description = "UNC path command execution", Severity = "Medium" },
            new() { Pattern = @"^for.*%.*in.*do", Description = "Obfuscated loop execution", Severity = "Medium" },
            new() { Pattern = @"copy.*\\\\.*\.exe", Description = "Remote binary copy via UNC", Severity = "High" },
        },
        ["certutil.exe"] = new()
        {
            new() { Pattern = @"-decode\s+.*\.(exe|dll|bat|ps1)", Description = "Binary decoding to executable", Severity = "Critical" },
            new() { Pattern = @"-urlcache.*http", Description = "Remote file download", Severity = "High" },
            new() { Pattern = @"-verifyctl.*http", Description = "Download via certificate verification", Severity = "High" },
        },
        ["bitsadmin.exe"] = new()
        {
            new() { Pattern = @"/transfer.*http", Description = "Background file transfer", Severity = "High" },
            new() { Pattern = @"/create.*\.(exe|dll|bat|ps1)", Description = "Executable download job", Severity = "Critical" },
        },
        ["wmic.exe"] = new()
        {
            new() { Pattern = @"process\s+call\s+create", Description = "Remote process creation", Severity = "Critical" },
            new() { Pattern = @".*shadowcopy\s+delete", Description = "Shadow copy deletion (ransomware)", Severity = "Critical" },
            new() { Pattern = @"/node:.*process", Description = "Remote WMI execution", Severity = "Critical" },
        },
        ["mshta.exe"] = new()
        {
            new() { Pattern = @"http.*\.hta", Description = "Remote HTA execution", Severity = "Critical" },
            new() { Pattern = @"javascript:|vbscript:", Description = "Inline script execution", Severity = "High" },
        },
        ["rundll32.exe"] = new()
        {
            new() { Pattern = @"javascript:|vbscript:|about:", Description = "Script protocol abuse", Severity = "Critical" },
            new() { Pattern = @"\\\\.*\.(dll|dat)", Description = "Remote DLL loading via UNC", Severity = "High" },
            new() { Pattern = @"url\.dll.*OpenURL.*http", Description = "URL invocation", Severity = "High" },
        },
        ["regsvr32.exe"] = new()
        {
            new() { Pattern = @"/s\s+/n\s+/u\s+/i:http", Description = "Squiblydoo technique", Severity = "Critical" },
            new() { Pattern = @"/i:.*\\.scrobj", Description = "Remote scriptlet execution", Severity = "Critical" },
        },
        ["msbuild.exe"] = new()
        {
            new() { Pattern = @"\.csproj.*<Code>.*<!\[CDATA\[", Description = "Inline C# execution", Severity = "Critical" },
            new() { Pattern = @"\.xml.*Task.*Assembly", Description = "Malicious build task", Severity = "High" },
        },
        ["installutil.exe"] = new()
        {
            new() { Pattern = @"/logfile=\s*/LogToConsole=false.*\.exe", Description = "Uninstall method abuse", Severity = "High" },
        },
        ["regasm.exe"] = new()
        {
            new() { Pattern = @"/U.*\.dll", Description = "Unregister method abuse", Severity = "High" },
        },
        ["cscript.exe"] = new()
        {
            new() { Pattern = @"\.vbs.*DownloadFile|\.js.*WScript\.Shell", Description = "Script-based download", Severity = "High" },
        },
        ["wscript.exe"] = new()
        {
            new() { Pattern = @"\.vbs.*CreateObject.*Shell|\.js.*ActiveXObject", Description = "ActiveX abuse", Severity = "High" },
        }
    };

    // Registry-only malware patterns
    private readonly List<RegistryMalwarePattern> _registryPatterns = new()
    {
        new() { Path = @"HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command", Description = "Fodhelper UAC bypass", Severity = "Critical" },
        new() { Path = @"HKCU\\Software\\Classes\\mscfile\\shell\\open\\command", Description = "EventVwr UAC bypass", Severity = "Critical" },
        new() { Path = @"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", Description = "Debugger persistence", Severity = "High" },
        new() { Path = @"HKCU\\Environment\\UserInitMprLogonScript", Description = "Logon script persistence", Severity = "High" },
        new() { Path = @".*\\CurrentVersion\\Windows\\Load", Description = "Load key persistence", Severity = "High" },
    };

    // WMI persistence patterns
    private readonly List<string> _wmiPersistenceClasses = new()
    {
        "__EventFilter", "__EventConsumer", "__FilterToConsumerBinding",
        "ActiveScriptEventConsumer", "CommandLineEventConsumer"
    };

    public FilelessDetector(ILogger<FilelessDetector> logger)
    {
        _logger = logger;
    }

    public async Task<FilelessDetectionResult> AnalyzeProcessAsync(Process process)
    {
        var result = new FilelessDetectionResult
        {
            ProcessId = process.Id,
            ProcessName = process.ProcessName.ToLowerInvariant(),
            CommandLine = GetProcessCommandLine(process.Id)
        };

        try
        {
            // Check if this is a known LOLBin
            var lolbinKey = $"{result.ProcessName}.exe";
            if (_lolbinPatterns.ContainsKey(lolbinKey))
            {
                result.IsLolbin = true;
                result.LolbinMatches = await AnalyzeLolbinCommandLineAsync(lolbinKey, result.CommandLine);
            }

            // Check for suspicious parent-child relationships
            result.SuspiciousParentChild = await AnalyzeProcessChainAsync(process);

            // Check for registry-only payload
            if (result.ProcessName == "reg" || result.ProcessName == "regedit")
            {
                result.RegistryOnlyPayload = await DetectRegistryPayloadAsync(result.CommandLine);
            }

            // Check for WMI-based execution
            if (result.ProcessName == "wmic" || result.ProcessName == "wmiprvse")
            {
                result.WmiExecution = await DetectWmiAbuseAsync(process);
            }

            // Check for scheduled task abuse
            if (result.ProcessName == "schtasks" || result.ProcessName == "at")
            {
                result.ScheduledTaskAbuse = await DetectScheduledTaskAbuseAsync(result.CommandLine);
            }

            // Calculate risk score
            result.RiskScore = CalculateFilelessRiskScore(result);
            result.IsSuspicious = result.RiskScore > 0.6;

            if (result.IsSuspicious)
            {
                _logger.LogWarning(
                    "Fileless/LOLBin activity detected: {Process} (PID: {Pid}), Score: {Score:F2}, Matches: {Matches}",
                    process.ProcessName, process.Id, result.RiskScore, result.LolbinMatches.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing fileless activity for PID {Pid}", process.Id);
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<List<LolbinMatch>> AnalyzeLolbinCommandLineAsync(string lolbin, string commandLine)
    {
        var matches = new List<LolbinMatch>();

        if (string.IsNullOrEmpty(commandLine))
            return matches;

        var patterns = _lolbinPatterns[lolbin];
        foreach (var pattern in patterns)
        {
            try
            {
                var regex = new Regex(pattern.Pattern, RegexOptions.IgnoreCase);
                var match = regex.Match(commandLine);

                if (match.Success)
                {
                    matches.Add(new LolbinMatch
                    {
                        Pattern = pattern.Pattern,
                        Description = pattern.Description,
                        Severity = pattern.Severity,
                        MatchedText = match.Value.Length > 100 ? match.Value.Substring(0, 100) + "..." : match.Value
                    });

                    _logger.LogWarning(
                        "LOLBin pattern matched: {Binary} - {Description}",
                        lolbin, pattern.Description);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error matching pattern: {Pattern}", pattern.Pattern);
            }
        }

        await Task.CompletedTask;
        return matches;
    }

    private async Task<bool> AnalyzeProcessChainAsync(Process process)
    {
        try
        {
            // Get parent process
            var parentId = GetParentProcessId(process.Id);
            if (parentId == 0)
                return false;

            var parent = Process.GetProcessById(parentId);
            var parentName = parent.ProcessName.ToLowerInvariant();
            var childName = process.ProcessName.ToLowerInvariant();

            // Suspicious parent-child combinations
            var suspiciousPairs = new Dictionary<string, List<string>>
            {
                ["winword"] = new() { "powershell", "cmd", "wscript", "cscript", "mshta" },
                ["excel"] = new() { "powershell", "cmd", "wscript", "cscript", "mshta" },
                ["outlook"] = new() { "powershell", "cmd", "wscript", "cscript", "mshta" },
                ["acrobat"] = new() { "powershell", "cmd", "wscript", "cscript" },
                ["acrord32"] = new() { "powershell", "cmd", "wscript", "cscript" },
                ["wmiprvse"] = new() { "powershell", "cmd", "rundll32", "regsvr32" },
                ["svchost"] = new() { "powershell", "cmd" } // Legitimate svchost shouldn't spawn shells
            };

            foreach (var pair in suspiciousPairs)
            {
                if (parentName.Contains(pair.Key) && pair.Value.Any(child => childName.Contains(child)))
                {
                    _logger.LogWarning(
                        "Suspicious process chain: {Parent} -> {Child}",
                        parentName, childName);
                    await Task.CompletedTask;
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error analyzing process chain");
        }

        await Task.CompletedTask;
        return false;
    }

    private async Task<bool> DetectRegistryPayloadAsync(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
            return false;

        // Check for registry key writes to known persistence locations
        foreach (var pattern in _registryPatterns)
        {
            try
            {
                var regex = new Regex(pattern.Path, RegexOptions.IgnoreCase);
                if (regex.IsMatch(commandLine))
                {
                    _logger.LogWarning(
                        "Registry-only payload detected: {Description} - {Path}",
                        pattern.Description, pattern.Path);
                    await Task.CompletedTask;
                    return true;
                }
            }
            catch { }
        }

        // Check for large binary data in registry (possible embedded payload)
        if (Regex.IsMatch(commandLine, @"/d\s+[0-9a-fA-F]{100,}", RegexOptions.IgnoreCase))
        {
            _logger.LogWarning("Large binary data in registry command detected");
            await Task.CompletedTask;
            return true;
        }

        await Task.CompletedTask;
        return false;
    }

    private async Task<bool> DetectWmiAbuseAsync(Process process)
    {
        try
        {
            // Check for WMI persistence via event subscriptions
            var wmiQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'";
            
            // In production: Query WMI namespace for suspicious event filters/consumers
            // For now, check command line
            var cmdLine = GetProcessCommandLine(process.Id);
            
            foreach (var wmiClass in _wmiPersistenceClasses)
            {
                if (cmdLine.Contains(wmiClass, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("WMI persistence mechanism detected: {Class}", wmiClass);
                    await Task.CompletedTask;
                    return true;
                }
            }

            // Check for WMI process creation
            if (cmdLine.Contains("process call create", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("WMI process creation detected");
                await Task.CompletedTask;
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error detecting WMI abuse");
        }

        await Task.CompletedTask;
        return false;
    }

    private async Task<bool> DetectScheduledTaskAbuseAsync(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
            return false;

        // Check for suspicious scheduled task creation
        var suspiciousPatterns = new[]
        {
            @"/create.*SYSTEM.*powershell",  // Task running as SYSTEM with PowerShell
            @"/create.*\\AppData\\",          // Task executing from AppData
            @"/create.*\.vbs|\.js|\.hta",    // Task executing scripts
            @"/create.*HIGHEST",              // Highest privilege task
            @"/create.*-enc"                  // Encoded command in task
        };

        foreach (var pattern in suspiciousPatterns)
        {
            try
            {
                if (Regex.IsMatch(commandLine, pattern, RegexOptions.IgnoreCase))
                {
                    _logger.LogWarning("Suspicious scheduled task: {Pattern}", pattern);
                    await Task.CompletedTask;
                    return true;
                }
            }
            catch { }
        }

        await Task.CompletedTask;
        return false;
    }

    public async Task<RegistryMalwareResult> ScanRegistryForMalwareAsync()
    {
        var result = new RegistryMalwareResult();

        try
        {
            _logger.LogDebug("Scanning registry for fileless malware...");

            // Scan persistence locations
            foreach (var pattern in _registryPatterns)
            {
                try
                {
                    var matches = await ScanRegistryKeyAsync(pattern.Path);
                    if (matches.Count > 0)
                    {
                        result.Detections.AddRange(matches.Select(m => new RegistryDetection
                        {
                            Path = m,
                            Description = pattern.Description,
                            Severity = pattern.Severity
                        }));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error scanning registry key: {Path}", pattern.Path);
                }
            }

            // Scan for COM hijacking
            result.ComHijackingDetected = await DetectComHijackingAsync();

            // Scan for AppInit_DLLs abuse
            result.AppInitDllsAbuse = await DetectAppInitDllsAbuseAsync();

            result.IsMalwareDetected = result.Detections.Count > 0 || 
                                      result.ComHijackingDetected || 
                                      result.AppInitDllsAbuse;

            if (result.IsMalwareDetected)
            {
                _logger.LogCritical(
                    "Registry-based malware detected: {Count} detections, COM hijacking: {Com}, AppInit: {AppInit}",
                    result.Detections.Count, result.ComHijackingDetected, result.AppInitDllsAbuse);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning registry for malware");
        }

        return result;
    }

    private async Task<List<string>> ScanRegistryKeyAsync(string keyPattern)
    {
        var matches = new List<string>();

        try
        {
            // Parse registry path
            var parts = keyPattern.Split('\\');
            if (parts.Length < 2)
                return matches;

            var hiveStr = parts[0];
            var subKeyPath = string.Join("\\", parts.Skip(1));

            Microsoft.Win32.RegistryKey? hive = hiveStr switch
            {
                "HKLM" => Microsoft.Win32.Registry.LocalMachine,
                "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                "HKCR" => Microsoft.Win32.Registry.ClassesRoot,
                _ => null
            };

            if (hive == null)
                return matches;

            // Open and scan key
            using var key = hive.OpenSubKey(subKeyPath);
            if (key != null)
            {
                // Check values for suspicious content
                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName);
                    if (value != null && IsSuspiciousRegistryValue(value.ToString() ?? ""))
                    {
                        matches.Add($"{keyPattern}\\{valueName}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning registry key: {Key}", keyPattern);
        }

        await Task.CompletedTask;
        return matches;
    }

    private bool IsSuspiciousRegistryValue(string value)
    {
        // Check for common malicious patterns
        var suspiciousPatterns = new[]
        {
            @"powershell.*-enc",
            @"cmd.*&&",
            @"\\AppData\\Local\\Temp",
            @"mshta.*javascript:",
            @"rundll32.*javascript:",
            @"base64",
            @"IEX|Invoke-Expression"
        };

        return suspiciousPatterns.Any(pattern => 
            Regex.IsMatch(value, pattern, RegexOptions.IgnoreCase));
    }

    private async Task<bool> DetectComHijackingAsync()
    {
        try
        {
            // Check HKCU\Software\Classes\CLSID for suspicious entries
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID");
            if (key != null)
            {
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var clsidKey = key.OpenSubKey(subKeyName);
                    if (clsidKey != null)
                    {
                        // Check for InprocServer32 pointing to suspicious locations
                        using var serverKey = clsidKey.OpenSubKey("InprocServer32");
                        if (serverKey != null)
                        {
                            var serverPath = serverKey.GetValue("")?.ToString() ?? "";
                            if (serverPath.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ||
                                serverPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogWarning("Possible COM hijacking detected: {Clsid} -> {Path}", 
                                    subKeyName, serverPath);
                                await Task.CompletedTask;
                                return true;
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error detecting COM hijacking");
        }

        await Task.CompletedTask;
        return false;
    }

    private async Task<bool> DetectAppInitDllsAbuseAsync()
    {
        try
        {
            // Check HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
            
            if (key != null)
            {
                var appInitDlls = key.GetValue("AppInit_DLLs")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(appInitDlls) && appInitDlls != "0")
                {
                    _logger.LogWarning("AppInit_DLLs abuse detected: {Dlls}", appInitDlls);
                    await Task.CompletedTask;
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error detecting AppInit_DLLs abuse");
        }

        await Task.CompletedTask;
        return false;
    }

    private double CalculateFilelessRiskScore(FilelessDetectionResult result)
    {
        double score = 0.0;

        if (result.IsLolbin)
        {
            // Weight by severity of matches
            foreach (var match in result.LolbinMatches)
            {
                score += match.Severity switch
                {
                    "Critical" => 0.4,
                    "High" => 0.3,
                    "Medium" => 0.2,
                    _ => 0.1
                };
            }
        }

        if (result.SuspiciousParentChild)
            score += 0.3;

        if (result.RegistryOnlyPayload)
            score += 0.4;

        if (result.WmiExecution)
            score += 0.35;

        if (result.ScheduledTaskAbuse)
            score += 0.3;

        return Math.Min(score, 1.0);
    }

    private string GetProcessCommandLine(int processId)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
            
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString() ?? "";
            }
        }
        catch { }

        return "";
    }

    private int GetParentProcessId(int processId)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}");
            
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                return Convert.ToInt32(obj["ParentProcessId"]);
            }
        }
        catch { }

        return 0;
    }
}

#region Models

public class FilelessDetectionResult
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public bool IsLolbin { get; set; }
    public List<LolbinMatch> LolbinMatches { get; set; } = new();
    public bool SuspiciousParentChild { get; set; }
    public bool RegistryOnlyPayload { get; set; }
    public bool WmiExecution { get; set; }
    public bool ScheduledTaskAbuse { get; set; }
    public double RiskScore { get; set; }
    public bool IsSuspicious { get; set; }
}

public class LolbinPattern
{
    public string Pattern { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

public class LolbinMatch
{
    public string Pattern { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string MatchedText { get; set; } = string.Empty;
}

public class RegistryMalwarePattern
{
    public string Path { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

public class RegistryMalwareResult
{
    public List<RegistryDetection> Detections { get; set; } = new();
    public bool ComHijackingDetected { get; set; }
    public bool AppInitDllsAbuse { get; set; }
    public bool IsMalwareDetected { get; set; }
}

public class RegistryDetection
{
    public string Path { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

#endregion
