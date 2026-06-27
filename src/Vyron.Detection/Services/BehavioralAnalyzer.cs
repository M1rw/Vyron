using Microsoft.Extensions.Logging;
using Vyron.Core.Models;

namespace Vyron.Detection.Services;

/// <summary>
/// Analyzes process behavior for suspicious activities
/// </summary>
public class BehavioralAnalyzer
{
    private readonly ILogger<BehavioralAnalyzer> _logger;
    private readonly Dictionary<int, ProcessBehavior> _processHistory = new();

    public BehavioralAnalyzer(ILogger<BehavioralAnalyzer> logger)
    {
        _logger = logger;
    }

    public void Initialize()
    {
        _logger.LogInformation("Behavioral analyzer initialized");
    }

    public double AnalyzeProcess(ProcessEvent processEvent)
    {
        try
        {
            double suspicionScore = 0.0;
            var reasons = new List<string>();

            // 1. Check for suspicious parent-child relationships
            if (IsSuspiciousParentChild(processEvent))
            {
                suspicionScore += 0.3;
                reasons.Add("Suspicious parent-child relationship");
            }

            // 2. Check command line for suspicious patterns
            var cmdScore = AnalyzeCommandLine(processEvent.CommandLine);
            suspicionScore += cmdScore;
            if (cmdScore > 0)
            {
                reasons.Add($"Suspicious command line (score: {cmdScore:F2})");
            }

            // 3. Check for privilege escalation attempts
            if (processEvent.IsElevated && !IsExpectedElevatedProcess(processEvent))
            {
                suspicionScore += 0.2;
                reasons.Add("Unexpected elevated privileges");
            }

            // 4. Check for rapid process creation (potential injection/spawning)
            if (IsRapidProcessCreation(processEvent))
            {
                suspicionScore += 0.25;
                reasons.Add("Rapid process creation detected");
            }

            // 5. Check executable location
            if (IsUnusualLocation(processEvent.ExecutablePath))
            {
                suspicionScore += 0.15;
                reasons.Add("Unusual executable location");
            }

            // Track process behavior
            TrackProcessBehavior(processEvent, suspicionScore);

            if (suspicionScore > 0.5)
            {
                _logger.LogWarning("Suspicious process behavior detected: {Process} (Score: {Score:F2}) - {Reasons}",
                    processEvent.ProcessName, suspicionScore, string.Join(", ", reasons));
            }

            return Math.Min(suspicionScore, 1.0); // Cap at 1.0
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing process behavior");
            return 0.0;
        }
    }

    private bool IsSuspiciousParentChild(ProcessEvent processEvent)
    {
        var suspiciousParents = new[]
        {
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"
        };

        var suspiciousChildren = new[]
        {
            "powershell.exe", "cmd.exe", "wmic.exe", "net.exe", "net1.exe", "reg.exe"
        };

        var parentLower = processEvent.ParentProcessName.ToLowerInvariant();
        var childLower = processEvent.ProcessName.ToLowerInvariant();

        // Office documents spawning scripts
        if ((parentLower.Contains("word") || parentLower.Contains("excel") || parentLower.Contains("outlook")) &&
            suspiciousChildren.Any(c => childLower.Contains(c)))
        {
            return true;
        }

        // Scripts spawning other scripts
        if (suspiciousParents.Any(p => parentLower.Contains(p)) &&
            suspiciousChildren.Any(c => childLower.Contains(c)))
        {
            return true;
        }

        return false;
    }

    private double AnalyzeCommandLine(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return 0.0;

        double score = 0.0;
        var cmdLower = commandLine.ToLowerInvariant();

        // PowerShell obfuscation indicators
        if (cmdLower.Contains("-enc") || cmdLower.Contains("-encodedcommand"))
            score += 0.3;
        if (cmdLower.Contains("-nop") || cmdLower.Contains("-noprofile"))
            score += 0.1;
        if (cmdLower.Contains("-w hidden") || cmdLower.Contains("-windowstyle hidden"))
            score += 0.2;
        if (cmdLower.Contains("bypass") && cmdLower.Contains("executionpolicy"))
            score += 0.2;

        // Download indicators
        if (cmdLower.Contains("downloadstring") || cmdLower.Contains("downloadfile"))
            score += 0.3;
        if (cmdLower.Contains("invoke-webrequest") || cmdLower.Contains("iwr") || cmdLower.Contains("wget") || cmdLower.Contains("curl"))
            score += 0.2;

        // Credential access
        if (cmdLower.Contains("mimikatz") || cmdLower.Contains("sekurlsa"))
            score += 0.5;
        if (cmdLower.Contains("lsass"))
            score += 0.3;

        // System modification
        if (cmdLower.Contains("vssadmin delete") || cmdLower.Contains("bcdedit"))
            score += 0.4;
        if (cmdLower.Contains("wmic") && cmdLower.Contains("delete"))
            score += 0.3;

        // Base64 encoded content (potential obfuscation)
        var base64Matches = System.Text.RegularExpressions.Regex.Matches(commandLine, @"[A-Za-z0-9+/]{50,}={0,2}");
        if (base64Matches.Count > 0)
            score += 0.2;

        return Math.Min(score, 0.8); // Cap at 0.8 for command line alone
    }

    private bool IsExpectedElevatedProcess(ProcessEvent processEvent)
    {
        var expectedElevated = new[]
        {
            "services.exe", "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
            "winlogon.exe", "system", "smss.exe"
        };

        return expectedElevated.Any(p => 
            processEvent.ProcessName.Equals(p, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsRapidProcessCreation(ProcessEvent processEvent)
    {
        var behavior = GetOrCreateBehavior(processEvent.ParentProcessId);
        behavior.ChildProcessCount++;
        behavior.LastActivity = DateTime.UtcNow;

        // If a process spawns more than 5 children in 10 seconds, it's suspicious
        if (behavior.ChildProcessCount > 5 && 
            (DateTime.UtcNow - behavior.FirstSeen).TotalSeconds < 10)
        {
            return true;
        }

        return false;
    }

    private bool IsUnusualLocation(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            return false;

        var pathLower = executablePath.ToLowerInvariant();

        // Common unusual locations for executables
        var unusualLocations = new[]
        {
            @"\appdata\local\temp",
            @"\users\public",
            @"\programdata\",
            @"\windows\temp",
            @"\recycle",
            @"\$recycle.bin"
        };

        return unusualLocations.Any(loc => pathLower.Contains(loc));
    }

    private void TrackProcessBehavior(ProcessEvent processEvent, double suspicionScore)
    {
        var behavior = GetOrCreateBehavior(processEvent.ProcessId);
        behavior.ProcessName = processEvent.ProcessName;
        behavior.ExecutablePath = processEvent.ExecutablePath;
        behavior.SuspicionScore = suspicionScore;
        behavior.LastActivity = DateTime.UtcNow;
    }

    private ProcessBehavior GetOrCreateBehavior(int processId)
    {
        if (!_processHistory.ContainsKey(processId))
        {
            _processHistory[processId] = new ProcessBehavior
            {
                ProcessId = processId,
                FirstSeen = DateTime.UtcNow
            };
        }

        return _processHistory[processId];
    }
}

internal class ProcessBehavior
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; }
    public DateTime LastActivity { get; set; }
    public int ChildProcessCount { get; set; }
    public double SuspicionScore { get; set; }
}
