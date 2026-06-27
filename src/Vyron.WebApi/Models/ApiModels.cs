namespace Vyron.WebApi.Models;

public class ThreatAlertDto
{
    public string Id { get; set; } = "";
    public DateTime Timestamp { get; set; }
    public string ThreatType { get; set; } = "";
    public string Severity { get; set; } = "";
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? FilePath { get; set; }
    public string Description { get; set; } = "";
    public double ConfidenceScore { get; set; }
    public List<string> Indicators { get; set; } = new();
    public List<string> MitreTechniques { get; set; } = new();
    public string Status { get; set; } = "New";
    public string? AssignedTo { get; set; }
    public string EndpointName { get; set; } = "";
    public string UserName { get; set; } = "";
}

public class EndpointDto
{
    public string Id { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public DateTime LastCheckIn { get; set; }
    public string Status { get; set; } = "Protected";
    public int ProtectionScore { get; set; }
    public bool HardwareSecurityEnabled { get; set; }
    public bool FilelessDetectionEnabled { get; set; }
    public bool MemoryForensicsEnabled { get; set; }
    public bool ZeroTrustEnabled { get; set; }
    public bool UebaEnabled { get; set; }
    public int VulnerablePackages { get; set; }
}

public class DashboardStatsDto
{
    public int TotalThreatsToday { get; set; }
    public int CriticalThreats { get; set; }
    public int HighThreats { get; set; }
    public int MediumThreats { get; set; }
    public int LowThreats { get; set; }
    public double DetectionRate { get; set; }
    public int ProtectedEndpoints { get; set; }
    public int VulnerableEndpoints { get; set; }
    public int OfflineEndpoints { get; set; }
    public int IsolatedEndpoints { get; set; }
    public double CpuUsage { get; set; }
    public long MemoryUsageMb { get; set; }
    public int DetectionLatencyMs { get; set; }
    public double FalsePositiveRate { get; set; }
}

public class LoginRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class LoginResponse
{
    public string AccessToken { get; set; } = "";
    public string RefreshToken { get; set; } = "";
    public string Username { get; set; } = "";
    public string Role { get; set; } = "";
    public int ExpiresIn { get; set; }
}

public class ResponseActionRequest
{
    public string ThreatId { get; set; } = "";
    public string Action { get; set; } = ""; // KillProcess, IsolateEndpoint, Quarantine, MarkFalsePositive
    public string? Reason { get; set; }
}

public class QueryRequest
{
    public string QueryText { get; set; } = "";
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public int MaxResults { get; set; } = 100;
}
