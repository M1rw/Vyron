using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using Vyron.WebApi.Data;
using Vyron.WebApi.Models;

namespace Vyron.WebApi.Services;

public class ThreatService : IThreatService
{
    private readonly VyronDbContext _context;
    private readonly ILogger<ThreatService> _logger;

    public ThreatService(VyronDbContext context, ILogger<ThreatService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<List<ThreatAlertDto>> GetThreatsAsync(string? severity, string? status, int page, int pageSize)
    {
        var query = _context.Threats.AsQueryable();

        if (!string.IsNullOrEmpty(severity))
            query = query.Where(t => t.Severity == severity);

        if (!string.IsNullOrEmpty(status))
            query = query.Where(t => t.Status == status);

        var threats = await query
            .OrderByDescending(t => t.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return threats.Select(MapToDto).ToList();
    }

    public async Task<ThreatAlertDto?> GetThreatByIdAsync(string id)
    {
        var threat = await _context.Threats.FindAsync(id);
        return threat == null ? null : MapToDto(threat);
    }

    public async Task<DashboardStatsDto> GetDashboardStatsAsync()
    {
        var today = DateTime.UtcNow.Date;
        var todayThreats = await _context.Threats
            .Where(t => t.Timestamp >= today)
            .ToListAsync();

        var endpoints = await _context.Endpoints.ToListAsync();

        return new DashboardStatsDto
        {
            TotalThreatsToday = todayThreats.Count,
            CriticalThreats = todayThreats.Count(t => t.Severity == "Critical"),
            HighThreats = todayThreats.Count(t => t.Severity == "High"),
            MediumThreats = todayThreats.Count(t => t.Severity == "Medium"),
            LowThreats = todayThreats.Count(t => t.Severity == "Low"),
            DetectionRate = 96.1,
            ProtectedEndpoints = endpoints.Count(e => e.Status == "Protected"),
            VulnerableEndpoints = endpoints.Count(e => e.Status == "Vulnerable"),
            OfflineEndpoints = endpoints.Count(e => e.Status == "Offline"),
            IsolatedEndpoints = endpoints.Count(e => e.Status == "Isolated"),
            CpuUsage = 5.2,
            MemoryUsageMb = 220,
            DetectionLatencyMs = 85,
            FalsePositiveRate = 1.8
        };
    }

    public async Task<List<ThreatAlertDto>> GetRecentThreatsAsync(int count)
    {
        var threats = await _context.Threats
            .OrderByDescending(t => t.Timestamp)
            .Take(count)
            .ToListAsync();

        return threats.Select(MapToDto).ToList();
    }

    public async Task<ResponseActionResult> ExecuteResponseActionAsync(string threatId, ResponseActionRequest request)
    {
        var threat = await _context.Threats.FindAsync(threatId);
        
        if (threat == null)
            return new ResponseActionResult { Success = false, Message = "Threat not found" };

        _logger.LogInformation("Executing action {Action} on threat {ThreatId}", request.Action, threatId);

        // In production, this would call the actual agent to perform actions
        switch (request.Action.ToLower())
        {
            case "killprocess":
                threat.Status = "Resolved";
                break;
            case "isolateendpoint":
                var endpoint = await _context.Endpoints.FirstOrDefaultAsync(e => e.Id == threat.EndpointId);
                if (endpoint != null)
                    endpoint.Status = "Isolated";
                threat.Status = "Resolved";
                break;
            case "quarantine":
                threat.Status = "Quarantined";
                break;
            case "markfalsepositive":
                threat.Status = "FalsePositive";
                break;
            default:
                return new ResponseActionResult { Success = false, Message = "Unknown action" };
        }

        await _context.SaveChangesAsync();

        return new ResponseActionResult { Success = true, Message = $"Action {request.Action} executed successfully" };
    }

    public async Task UpdateThreatStatusAsync(string threatId, string status, string? assignedTo)
    {
        var threat = await _context.Threats.FindAsync(threatId);
        
        if (threat != null)
        {
            threat.Status = status;
            threat.AssignedTo = assignedTo;
            await _context.SaveChangesAsync();
        }
    }

    private static ThreatAlertDto MapToDto(ThreatAlert threat)
    {
        return new ThreatAlertDto
        {
            Id = threat.Id,
            Timestamp = threat.Timestamp,
            ThreatType = threat.ThreatType,
            Severity = threat.Severity,
            ProcessId = threat.ProcessId,
            ProcessName = threat.ProcessName,
            FilePath = threat.FilePath,
            Description = threat.Description,
            ConfidenceScore = threat.ConfidenceScore,
            Indicators = JsonSerializer.Deserialize<List<string>>(threat.Indicators) ?? new(),
            MitreTechniques = JsonSerializer.Deserialize<List<string>>(threat.MitreTechniques) ?? new(),
            Status = threat.Status,
            AssignedTo = threat.AssignedTo,
            EndpointName = threat.EndpointId,
            UserName = threat.UserName
        };
    }
}

public class EndpointService : IEndpointService
{
    private readonly VyronDbContext _context;

    public EndpointService(VyronDbContext context)
    {
        _context = context;
    }

    public async Task<List<EndpointDto>> GetEndpointsAsync()
    {
        var endpoints = await _context.Endpoints.ToListAsync();
        return endpoints.Select(MapToDto).ToList();
    }

    public async Task<EndpointDto?> GetEndpointByIdAsync(string id)
    {
        var endpoint = await _context.Endpoints.FindAsync(id);
        return endpoint == null ? null : MapToDto(endpoint);
    }

    private static EndpointDto MapToDto(Endpoint endpoint)
    {
        return new EndpointDto
        {
            Id = endpoint.Id,
            Hostname = endpoint.Hostname,
            IpAddress = endpoint.IpAddress,
            OsVersion = endpoint.OsVersion,
            AgentVersion = endpoint.AgentVersion,
            LastCheckIn = endpoint.LastCheckIn,
            Status = endpoint.Status,
            ProtectionScore = endpoint.ProtectionScore,
            HardwareSecurityEnabled = endpoint.HardwareSecurityEnabled,
            FilelessDetectionEnabled = endpoint.FilelessDetectionEnabled,
            MemoryForensicsEnabled = endpoint.MemoryForensicsEnabled,
            ZeroTrustEnabled = endpoint.ZeroTrustEnabled,
            UebaEnabled = endpoint.UebaEnabled,
            VulnerablePackages = endpoint.VulnerablePackages
        };
    }
}

public class PolicyService : IPolicyService
{
    private readonly VyronDbContext _context;

    public PolicyService(VyronDbContext context)
    {
        _context = context;
    }

    public async Task<string> GetPolicyAsync()
    {
        var policy = await _context.Policies.OrderByDescending(p => p.UpdatedAt).FirstOrDefaultAsync();
        return policy?.PolicyJson ?? "{}";
    }

    public async Task UpdatePolicyAsync(string policyJson)
    {
        var policy = new Policy
        {
            Name = "Detection Policy",
            PolicyJson = policyJson,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = "admin"
        };

        _context.Policies.Add(policy);
        await _context.SaveChangesAsync();
    }
}

public class AuthService : IAuthService
{
    private readonly VyronDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        VyronDbContext context,
        IConfiguration configuration,
        ILogger<AuthService> logger)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<LoginResponse?> LoginAsync(string username, string password)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        
        if (user == null)
            return null;

        // In production, use proper password hashing (BCrypt, Argon2, etc.)
        // This is simplified for demonstration
        if (password != "admin") // CHANGE IN PRODUCTION
            return null;

        user.LastLogin = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return new LoginResponse
        {
            AccessToken = GenerateJwtToken(user),
            RefreshToken = GenerateRefreshToken(),
            Username = user.Username,
            Role = user.Role,
            ExpiresIn = 900 // 15 minutes
        };
    }

    public async Task<LoginResponse?> RefreshTokenAsync(string refreshToken)
    {
        // In production, validate refresh token from database
        // This is simplified
        return await Task.FromResult<LoginResponse?>(null);
    }

    private string GenerateJwtToken(User user)
    {
        // In production, generate actual JWT token
        return "demo-jwt-token";
    }

    private string GenerateRefreshToken()
    {
        return Guid.NewGuid().ToString();
    }
}
