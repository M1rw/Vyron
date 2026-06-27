using Microsoft.Extensions.Logging;
using Vyron.Core.Models;
using Vyron.Core.Services;

namespace Vyron.Detection.Services;

/// <summary>
/// Main detection engine that orchestrates multiple detection methods
/// </summary>
public class DetectionEngine
{
    private readonly ILogger<DetectionEngine> _logger;
    private readonly ConfigurationService _configService;
    private readonly SignatureScanner _signatureScanner;
    private readonly BehavioralAnalyzer _behavioralAnalyzer;
    private readonly ReputationService _reputationService;
    
    public event EventHandler<ThreatEvent>? ThreatDetected;

    public DetectionEngine(
        ILogger<DetectionEngine> logger,
        ConfigurationService configService,
        SignatureScanner signatureScanner,
        BehavioralAnalyzer behavioralAnalyzer,
        ReputationService reputationService)
    {
        _logger = logger;
        _configService = configService;
        _signatureScanner = signatureScanner;
        _behavioralAnalyzer = behavioralAnalyzer;
        _reputationService = reputationService;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initializing detection engine...");

        var config = _configService.GetConfig();

        if (config.Detection.EnableSignatureDetection)
        {
            await _signatureScanner.LoadRulesAsync(config.Detection.YaraRulesPath);
        }

        if (config.Detection.EnableBehavioralDetection)
        {
            _behavioralAnalyzer.Initialize();
        }

        if (config.Detection.EnableReputationCheck)
        {
            await _reputationService.InitializeAsync();
        }

        _logger.LogInformation("Detection engine initialized successfully");
    }

    public async Task<ThreatEvent?> AnalyzeProcessAsync(ProcessEvent processEvent, CancellationToken cancellationToken)
    {
        try
        {
            var config = _configService.GetConfig();
            
            // Check if process is whitelisted
            if (IsWhitelisted(processEvent.ExecutablePath))
            {
                return null;
            }

            var detectionScores = new Dictionary<DetectionMethod, double>();
            var detectionReasons = new List<string>();

            // 1. Signature-based detection
            if (config.Detection.EnableSignatureDetection && File.Exists(processEvent.ExecutablePath))
            {
                var signatureResult = await _signatureScanner.ScanFileAsync(processEvent.ExecutablePath);
                if (signatureResult.IsMatch)
                {
                    detectionScores[DetectionMethod.Signature] = 1.0;
                    detectionReasons.Add($"Signature match: {signatureResult.RuleName}");
                }
            }

            // 2. Behavioral analysis
            if (config.Detection.EnableBehavioralDetection)
            {
                var behaviorScore = _behavioralAnalyzer.AnalyzeProcess(processEvent);
                if (behaviorScore > 0.5)
                {
                    detectionScores[DetectionMethod.Behavioral] = behaviorScore;
                    detectionReasons.Add($"Suspicious behavior detected (score: {behaviorScore:F2})");
                }
            }

            // 3. Reputation check
            if (config.Detection.EnableReputationCheck && !string.IsNullOrEmpty(processEvent.ExecutablePath))
            {
                var reputationScore = await _reputationService.CheckReputationAsync(processEvent.ExecutablePath);
                if (reputationScore < 0.3) // Low reputation = suspicious
                {
                    detectionScores[DetectionMethod.Reputation] = 1.0 - reputationScore;
                    detectionReasons.Add($"Low reputation (score: {reputationScore:F2})");
                }
            }

            // 4. Machine Learning detection (placeholder for now)
            if (config.Detection.EnableMLDetection)
            {
                // TODO: Implement ML-based detection
                // var mlScore = await _mlModel.PredictAsync(processEvent);
            }

            // Calculate overall confidence score (weighted average)
            if (!detectionScores.Any())
            {
                return null; // No threats detected
            }

            var confidenceScore = detectionScores.Values.Average();
            
            // Check if score exceeds threshold
            if (confidenceScore < config.Detection.MinimumConfidenceThreshold)
            {
                return null;
            }

            // Determine threat type and severity
            var threatType = DetermineThreatType(processEvent, detectionReasons);
            var severity = DetermineSeverity(confidenceScore, threatType);

            var threat = new ThreatEvent
            {
                Type = threatType,
                Severity = severity,
                ProcessName = processEvent.ProcessName,
                ProcessId = processEvent.ProcessId,
                FilePath = processEvent.ExecutablePath,
                CommandLine = processEvent.CommandLine,
                ParentProcessName = processEvent.ParentProcessName,
                ParentProcessId = processEvent.ParentProcessId,
                DetectionMethod = detectionScores.Keys.First(),
                ConfidenceScore = confidenceScore,
                Metadata = new Dictionary<string, string>
                {
                    ["DetectionReasons"] = string.Join("; ", detectionReasons),
                    ["DetectionMethods"] = string.Join(", ", detectionScores.Keys)
                }
            };

            ThreatDetected?.Invoke(this, threat);
            return threat;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing process: {Process}", processEvent.ProcessName);
            return null;
        }
    }

    public async Task<ThreatEvent?> AnalyzeFileAsync(FileEvent fileEvent, CancellationToken cancellationToken)
    {
        try
        {
            var config = _configService.GetConfig();
            
            // Check if file is whitelisted
            if (IsWhitelisted(fileEvent.FilePath) || IsHashWhitelisted(fileEvent.FileHash))
            {
                return null;
            }

            var detectionScores = new Dictionary<DetectionMethod, double>();
            var detectionReasons = new List<string>();

            // Signature scanning for executables
            if (fileEvent.IsExecutable && config.Detection.EnableSignatureDetection)
            {
                var signatureResult = await _signatureScanner.ScanFileAsync(fileEvent.FilePath);
                if (signatureResult.IsMatch)
                {
                    detectionScores[DetectionMethod.Signature] = 1.0;
                    detectionReasons.Add($"Signature match: {signatureResult.RuleName}");
                }
            }

            // Reputation check for file hash
            if (config.Detection.EnableReputationCheck && !string.IsNullOrEmpty(fileEvent.FileHash))
            {
                var reputationScore = await _reputationService.CheckFileHashReputationAsync(fileEvent.FileHash);
                if (reputationScore < 0.3)
                {
                    detectionScores[DetectionMethod.Reputation] = 1.0 - reputationScore;
                    detectionReasons.Add($"Known malicious file hash (reputation: {reputationScore:F2})");
                }
            }

            if (!detectionScores.Any())
            {
                return null;
            }

            var confidenceScore = detectionScores.Values.Average();
            
            if (confidenceScore < config.Detection.MinimumConfidenceThreshold)
            {
                return null;
            }

            var threat = new ThreatEvent
            {
                Type = ThreatType.Malware,
                Severity = DetermineSeverity(confidenceScore, ThreatType.Malware),
                ProcessName = fileEvent.ProcessName,
                ProcessId = fileEvent.ProcessId,
                FilePath = fileEvent.FilePath,
                FileHash = fileEvent.FileHash,
                DetectionMethod = detectionScores.Keys.First(),
                ConfidenceScore = confidenceScore,
                Metadata = new Dictionary<string, string>
                {
                    ["DetectionReasons"] = string.Join("; ", detectionReasons),
                    ["FileEventType"] = fileEvent.EventType.ToString()
                }
            };

            ThreatDetected?.Invoke(this, threat);
            return threat;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing file: {File}", fileEvent.FilePath);
            return null;
        }
    }

    private bool IsWhitelisted(string filePath)
    {
        var config = _configService.GetConfig();
        return config.Detection.TrustedProcesses.Any(trusted => 
            filePath.Equals(trusted, StringComparison.OrdinalIgnoreCase) ||
            filePath.StartsWith(trusted, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsHashWhitelisted(string fileHash)
    {
        if (string.IsNullOrEmpty(fileHash))
            return false;

        var config = _configService.GetConfig();
        return config.Detection.TrustedHashes.Contains(fileHash, StringComparer.OrdinalIgnoreCase);
    }

    private ThreatType DetermineThreatType(ProcessEvent processEvent, List<string> reasons)
    {
        var commandLine = processEvent.CommandLine.ToLowerInvariant();
        
        // Ransomware indicators
        if (commandLine.Contains("vssadmin delete shadows") ||
            commandLine.Contains("wbadmin delete catalog") ||
            commandLine.Contains("bcdedit") && commandLine.Contains("recoveryenabled no"))
        {
            return ThreatType.Ransomware;
        }

        // Persistence mechanisms
        if (commandLine.Contains("reg add") && commandLine.Contains("run") ||
            commandLine.Contains("schtasks") && commandLine.Contains("create"))
        {
            return ThreatType.PersistenceMechanism;
        }

        // Command and control
        if (reasons.Any(r => r.Contains("network")) || commandLine.Contains("powershell") && commandLine.Contains("downloadstring"))
        {
            return ThreatType.CommandAndControl;
        }

        return ThreatType.SuspiciousBehavior;
    }

    private ThreatSeverity DetermineSeverity(double confidenceScore, ThreatType type)
    {
        // Ransomware and rootkits are always critical
        if (type == ThreatType.Ransomware || type == ThreatType.Rootkit)
        {
            return ThreatSeverity.Critical;
        }

        // Score-based severity
        if (confidenceScore >= 0.9)
            return ThreatSeverity.Critical;
        if (confidenceScore >= 0.8)
            return ThreatSeverity.High;
        if (confidenceScore >= 0.6)
            return ThreatSeverity.Medium;
        
        return ThreatSeverity.Low;
    }
}
