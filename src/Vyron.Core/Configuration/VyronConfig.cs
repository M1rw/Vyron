namespace Vyron.Core.Configuration;

/// <summary>
/// Main configuration for Vyron agent
/// </summary>
public class VyronConfig
{
    public DetectionSettings Detection { get; set; } = new();
    public MonitoringSettings Monitoring { get; set; } = new();
    public ResponseSettings Response { get; set; } = new();
    public LearningSettings Learning { get; set; } = new();
    public StorageSettings Storage { get; set; } = new();
    public UpdateSettings Updates { get; set; } = new();
}

public class DetectionSettings
{
    /// <summary>
    /// Detection sensitivity: Low, Medium, High, Paranoid
    /// </summary>
    public string Level { get; set; } = "High";
    
    /// <summary>
    /// Minimum confidence score to trigger alert (0.0-1.0)
    /// </summary>
    public double MinimumConfidenceThreshold { get; set; } = 0.7;
    
    /// <summary>
    /// Enable signature-based detection (YARA rules)
    /// </summary>
    public bool EnableSignatureDetection { get; set; } = true;
    
    /// <summary>
    /// Enable behavioral analysis
    /// </summary>
    public bool EnableBehavioralDetection { get; set; } = true;
    
    /// <summary>
    /// Enable machine learning detection
    /// </summary>
    public bool EnableMLDetection { get; set; } = true;
    
    /// <summary>
    /// Enable reputation checking
    /// </summary>
    public bool EnableReputationCheck { get; set; } = true;
    
    /// <summary>
    /// Path to YARA rules directory
    /// </summary>
    public string YaraRulesPath { get; set; } = @"C:\ProgramData\Vyron\rules";
    
    /// <summary>
    /// Whitelist of trusted file hashes
    /// </summary>
    public List<string> TrustedHashes { get; set; } = new();
    
    /// <summary>
    /// Whitelist of trusted process paths
    /// </summary>
    public List<string> TrustedProcesses { get; set; } = new();
}

public class MonitoringSettings
{
    /// <summary>
    /// Monitor all processes or only specific ones
    /// </summary>
    public string Scope { get; set; } = "All";
    
    /// <summary>
    /// Enable process monitoring
    /// </summary>
    public bool EnableProcessMonitoring { get; set; } = true;
    
    /// <summary>
    /// Enable file system monitoring
    /// </summary>
    public bool EnableFileMonitoring { get; set; } = true;
    
    /// <summary>
    /// Enable network monitoring
    /// </summary>
    public bool EnableNetworkMonitoring { get; set; } = true;
    
    /// <summary>
    /// Enable registry monitoring
    /// </summary>
    public bool EnableRegistryMonitoring { get; set; } = true;
    
    /// <summary>
    /// Paths to monitor for file system events
    /// </summary>
    public List<string> MonitoredPaths { get; set; } = new()
    {
        @"C:\",
        @"C:\Users",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
        @"C:\Windows\System32"
    };
    
    /// <summary>
    /// Paths to exclude from monitoring
    /// </summary>
    public List<string> ExcludedPaths { get; set; } = new()
    {
        @"C:\Windows\Temp",
        @"C:\Windows\SoftwareDistribution"
    };
    
    /// <summary>
    /// File extensions to prioritize
    /// </summary>
    public List<string> HighPriorityExtensions { get; set; } = new()
    {
        ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr"
    };
}

public class ResponseSettings
{
    /// <summary>
    /// Automatically quarantine detected threats
    /// </summary>
    public bool AutoQuarantine { get; set; } = true;
    
    /// <summary>
    /// Automatically terminate malicious processes
    /// </summary>
    public bool AutoTerminateProcess { get; set; } = true;
    
    /// <summary>
    /// Quarantine directory path
    /// </summary>
    public string QuarantinePath { get; set; } = @"C:\ProgramData\Vyron\Quarantine";
    
    /// <summary>
    /// Minimum severity to trigger auto-response
    /// </summary>
    public string MinimumSeverityForAutoResponse { get; set; } = "High";
    
    /// <summary>
    /// Send alerts to event log
    /// </summary>
    public bool EnableEventLog { get; set; } = true;
    
    /// <summary>
    /// Generate alert notifications
    /// </summary>
    public bool EnableNotifications { get; set; } = true;
}

public class LearningSettings
{
    /// <summary>
    /// Enable adaptive learning from detections
    /// </summary>
    public bool Enabled { get; set; } = true;
    
    /// <summary>
    /// Store events for training
    /// </summary>
    public bool StoreTrainingData { get; set; } = true;
    
    /// <summary>
    /// Automatically retrain model
    /// </summary>
    public bool AutoRetrain { get; set; } = false;
    
    /// <summary>
    /// Minimum events before retraining
    /// </summary>
    public int MinimumEventsForRetraining { get; set; } = 10000;
    
    /// <summary>
    /// Days to retain training data
    /// </summary>
    public int TrainingDataRetentionDays { get; set; } = 90;
}

public class StorageSettings
{
    /// <summary>
    /// Base data directory
    /// </summary>
    public string DataPath { get; set; } = @"C:\ProgramData\Vyron\Data";
    
    /// <summary>
    /// Log directory
    /// </summary>
    public string LogPath { get; set; } = @"C:\ProgramData\Vyron\Logs";
    
    /// <summary>
    /// Database connection string
    /// </summary>
    public string DatabasePath { get; set; } = @"C:\ProgramData\Vyron\Data\vyron.db";
    
    /// <summary>
    /// Maximum log file size in MB
    /// </summary>
    public int MaxLogFileSizeMB { get; set; } = 100;
    
    /// <summary>
    /// Days to retain logs
    /// </summary>
    public int LogRetentionDays { get; set; } = 30;
}

public class UpdateSettings
{
    /// <summary>
    /// Enable automatic signature updates
    /// </summary>
    public bool AutoUpdate { get; set; } = true;
    
    /// <summary>
    /// Update check interval in seconds
    /// </summary>
    public int UpdateIntervalSeconds { get; set; } = 3600;
    
    /// <summary>
    /// Update server URL
    /// </summary>
    public string UpdateServerUrl { get; set; } = "https://updates.vyron.local";
}
