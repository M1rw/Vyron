using Microsoft.ML.Data;

namespace Vyron.ML.Models;

/// <summary>
/// Training data for ML model
/// </summary>
public class ThreatTrainingData
{
    // Process features
    [LoadColumn(0)]
    public string ProcessName { get; set; } = string.Empty;
    
    [LoadColumn(1)]
    public string ExecutablePath { get; set; } = string.Empty;
    
    [LoadColumn(2)]
    public string CommandLine { get; set; } = string.Empty;
    
    [LoadColumn(3)]
    public string ParentProcessName { get; set; } = string.Empty;
    
    [LoadColumn(4)]
    public bool IsElevated { get; set; }
    
    [LoadColumn(5)]
    public float IntegrityLevel { get; set; }
    
    // Behavioral features
    [LoadColumn(6)]
    public float ChildProcessCount { get; set; }
    
    [LoadColumn(7)]
    public bool HasSuspiciousParent { get; set; }
    
    [LoadColumn(8)]
    public bool InUnusualLocation { get; set; }
    
    [LoadColumn(9)]
    public float CommandLineComplexity { get; set; }
    
    [LoadColumn(10)]
    public bool UsesObfuscation { get; set; }
    
    [LoadColumn(11)]
    public bool AccessesLsass { get; set; }
    
    [LoadColumn(12)]
    public bool ModifiesRegistry { get; set; }
    
    [LoadColumn(13)]
    public bool DeletesBackups { get; set; }
    
    // File features
    [LoadColumn(14)]
    public float FileSize { get; set; }
    
    [LoadColumn(15)]
    public bool IsSigned { get; set; }
    
    [LoadColumn(16)]
    public float ReputationScore { get; set; }
    
    [LoadColumn(17)]
    public bool HasSignatureMatch { get; set; }
    
    // Network features (future)
    [LoadColumn(18)]
    public bool MakesNetworkConnections { get; set; }
    
    [LoadColumn(19)]
    public float NetworkConnectionCount { get; set; }
    
    // Label (true = malware, false = benign)
    [LoadColumn(20)]
    public bool IsMalware { get; set; }
}

/// <summary>
/// Prediction output
/// </summary>
public class ThreatPrediction
{
    [ColumnName("PredictedLabel")]
    public bool IsMalware { get; set; }
    
    [ColumnName("Probability")]
    public float Probability { get; set; }
    
    [ColumnName("Score")]
    public float Score { get; set; }
}
