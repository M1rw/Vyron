using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vyron.WebApi.Models;
using Vyron.WebApi.Services;

namespace Vyron.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DashboardController : ControllerBase
{
    private readonly IThreatService _threatService;
    private readonly IEndpointService _endpointService;
    private readonly ILogger<DashboardController> _logger;

    public DashboardController(
        IThreatService threatService,
        IEndpointService endpointService,
        ILogger<DashboardController> logger)
    {
        _threatService = threatService;
        _endpointService = endpointService;
        _logger = logger;
    }

    [HttpGet("stats")]
    public async Task<ActionResult<DashboardStatsDto>> GetDashboardStats()
    {
        try
        {
            var stats = await _threatService.GetDashboardStatsAsync();
            return Ok(stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving dashboard stats");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("recent-threats")]
    public async Task<ActionResult<List<ThreatAlertDto>>> GetRecentThreats([FromQuery] int count = 10)
    {
        try
        {
            var threats = await _threatService.GetRecentThreatsAsync(count);
            return Ok(threats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving recent threats");
            return StatusCode(500, "Internal server error");
        }
    }
}
