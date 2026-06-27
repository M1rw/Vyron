namespace Vyron.Advanced.ZeroTrust;

/// <summary>
/// Represents the trust score for a process in the Zero-Trust security model
/// </summary>
public class ProcessTrustScore
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public double TrustScore { get; set; }
    public string TrustLevel { get; set; } = string.Empty;
    public List<string> RiskFactors { get; set; } = new();
    public DateTime LastEvaluated { get; set; }
    public bool IsBlocked { get; set; }
}
