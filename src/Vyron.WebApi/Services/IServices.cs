using Vyron.WebApi.Models;

namespace Vyron.WebApi.Services;

public interface IThreatService
{
    Task<List<ThreatAlertDto>> GetThreatsAsync(string? severity, string? status, int page, int pageSize);
    Task<ThreatAlertDto?> GetThreatByIdAsync(string id);
    Task<DashboardStatsDto> GetDashboardStatsAsync();
    Task<List<ThreatAlertDto>> GetRecentThreatsAsync(int count);
    Task<ResponseActionResult> ExecuteResponseActionAsync(string threatId, ResponseActionRequest request);
    Task UpdateThreatStatusAsync(string threatId, string status, string? assignedTo);
}

public interface IEndpointService
{
    Task<List<EndpointDto>> GetEndpointsAsync();
    Task<EndpointDto?> GetEndpointByIdAsync(string id);
}

public interface IPolicyService
{
    Task<string> GetPolicyAsync();
    Task UpdatePolicyAsync(string policyJson);
}

public interface IAuthService
{
    Task<LoginResponse?> LoginAsync(string username, string password);
    Task<LoginResponse?> RefreshTokenAsync(string refreshToken);
}

public class ResponseActionResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
}
