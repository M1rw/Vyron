using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vyron.WebApi.Models;
using Vyron.WebApi.Services;

namespace Vyron.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ThreatsController : ControllerBase
{
    private readonly IThreatService _threatService;
    private readonly ILogger<ThreatsController> _logger;

    public ThreatsController(
        IThreatService threatService,
        ILogger<ThreatsController> logger)
    {
        _threatService = threatService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<List<ThreatAlertDto>>> GetThreats(
        [FromQuery] string? severity = null,
        [FromQuery] string? status = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50)
    {
        try
        {
            var threats = await _threatService.GetThreatsAsync(severity, status, page, pageSize);
            return Ok(threats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving threats");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ThreatAlertDto>> GetThreat(string id)
    {
        try
        {
            var threat = await _threatService.GetThreatByIdAsync(id);
            
            if (threat == null)
                return NotFound();
            
            return Ok(threat);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving threat {ThreatId}", id);
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpPost("{id}/respond")]
    public async Task<ActionResult> RespondToThreat(string id, [FromBody] ResponseActionRequest request)
    {
        try
        {
            var result = await _threatService.ExecuteResponseActionAsync(id, request);
            
            if (!result.Success)
                return BadRequest(result.Message);
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing response action for threat {ThreatId}", id);
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpPut("{id}/status")]
    public async Task<ActionResult> UpdateThreatStatus(string id, [FromBody] UpdateStatusRequest request)
    {
        try
        {
            await _threatService.UpdateThreatStatusAsync(id, request.Status, request.AssignedTo);
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating threat status");
            return StatusCode(500, "Internal server error");
        }
    }
}

public class UpdateStatusRequest
{
    public string Status { get; set; } = "";
    public string? AssignedTo { get; set; }
}
