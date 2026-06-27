using Vyron.WebApi.Models;

namespace Vyron.WebApi.Services;

// Mock implementation for quick demo
public class MockThreatService : IThreatService
{
    private static readonly List<ThreatAlertDto> _mockThreats = new();
    private static readonly Random _random = new();

    public Task<List<ThreatAlertDto>> GetThreatsAsync(string? severity = null, string? status = null, int page = 1, int pageSize = 20)
    {
        var threats = _mockThreats.AsQueryable();

        if (!string.IsNullOrEmpty(severity))
            threats = threats.Where(t => t.Severity == severity);

        if (!string.IsNullOrEmpty(status))
            threats = threats.Where(t => t.Status == status);

        return Task.FromResult(threats.Skip((page - 1) * pageSize).Take(pageSize).ToList());
    }

    public Task<ThreatAlertDto?> GetThreatByIdAsync(string id)
    {
        return Task.FromResult(_mockThreats.FirstOrDefault(t => t.Id == id));
    }

    public Task<DashboardStatsDto> GetDashboardStatsAsync()
    {
        return Task.FromResult(new DashboardStatsDto
        {
            TotalThreatsToday = _mockThreats.Count,
            CriticalThreats = _mockThreats.Count(t => t.Severity == "Critical"),
            HighThreats = _mockThreats.Count(t => t.Severity == "High"),
            MediumThreats = _mockThreats.Count(t => t.Severity == "Medium"),
            LowThreats = _mockThreats.Count(t => t.Severity == "Low"),
            DetectionRate = 96.1,
            ProtectedEndpoints = 42,
            VulnerableEndpoints = 3,
            OfflineEndpoints = 1,
            IsolatedEndpoints = 0,
            CpuUsage = _random.Next(10, 30),
            MemoryUsageMb = _random.Next(500, 1000),
            DetectionLatencyMs = _random.Next(5, 15),
            FalsePositiveRate = 0.02
        });
    }

    public Task<List<ThreatAlertDto>> GetRecentThreatsAsync(int count = 10)
    {
        return Task.FromResult(_mockThreats.OrderByDescending(t => t.Timestamp).Take(count).ToList());
    }

    public Task ExecuteResponseActionAsync(string id, ResponseActionRequest action)
    {
        var threat = _mockThreats.FirstOrDefault(t => t.Id == id);
        if (threat != null)
        {
            threat.Status = "Resolved";
        }
        return Task.CompletedTask;
    }

    public Task UpdateThreatStatusAsync(string id, string status, string? assignedTo = null)
    {
        var threat = _mockThreats.FirstOrDefault(t => t.Id == id);
        if (threat != null)
        {
            threat.Status = status;
            threat.AssignedTo = assignedTo;
        }
        return Task.CompletedTask;
    }

    // Method to add mock threats for testing
    public static void AddMockThreat(ThreatAlertDto threat)
    {
        _mockThreats.Add(threat);
        if (_mockThreats.Count > 100)
            _mockThreats.RemoveAt(0);
    }
}

public class MockAuthService : IAuthService
{
    public Task<LoginResponse> LoginAsync(LoginRequest request)
    {
        // Demo credentials: admin/admin
        if (request.Username == "admin" && request.Password == "admin")
        {
            return Task.FromResult(new LoginResponse
            {
                Token = "demo_jwt_token_" + Guid.NewGuid().ToString("N"),
                RefreshToken = Guid.NewGuid().ToString("N"),
                ExpiresAt = DateTime.UtcNow.AddHours(8).ToString("O")
            });
        }

        throw new UnauthorizedAccessException("Invalid credentials");
    }

    public Task<LoginResponse> RefreshTokenAsync(string refreshToken)
    {
        return Task.FromResult(new LoginResponse
        {
            Token = "demo_jwt_token_" + Guid.NewGuid().ToString("N"),
            RefreshToken = Guid.NewGuid().ToString("N"),
            ExpiresAt = DateTime.UtcNow.AddHours(8).ToString("O")
        });
    }
}
