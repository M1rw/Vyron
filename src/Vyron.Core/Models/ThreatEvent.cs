namespace Vyron.Core.Models;

/// <summary>
/// Represents a detected threat or suspicious event
/// </summary>
public class ThreatEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public ThreatType Type { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string FileHash { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string ParentProcessName { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
    
    /// <summary>
    /// Detection method that identified this threat
    /// </summary>
    public DetectionMethod DetectionMethod { get; set; }
    
    /// <summary>
    /// Confidence score (0.0 to 1.0)
    /// </summary>
    public double ConfidenceScore { get; set; }
    
    /// <summary>
    /// Action taken in response to this threat
    /// </summary>
    public ResponseAction? ActionTaken { get; set; }
    
    /// <summary>
    /// Whether this detection was a true positive (for learning)
    /// </summary>
    public bool? IsConfirmedThreat { get; set; }
    
    /// <summary>
    /// User feedback or analyst notes
    /// </summary>
    public string? Notes { get; set; }
}

public enum ThreatType
{
    Unknown,
    Malware,
    Ransomware,
    Trojan,
    Rootkit,
    Spyware,
    Adware,
    PotentiallyUnwanted,
    SuspiciousBehavior,
    Exploit,
    CommandAndControl,
    DataExfiltration,
    PrivilegeEscalation,
    PersistenceMechanism
}

public enum ThreatSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum DetectionMethod
{
    Signature,
    Heuristic,
    Behavioral,
    MachineLearning,
    Reputation,
    Anomaly,
    Sandbox,
    Hybrid
}

public enum ResponseAction
{
    Alert,
    Block,
    Quarantine,
    TerminateProcess,
    IsolateHost,
    None
}
