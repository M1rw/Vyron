using Microsoft.AspNetCore.Mvc;
using Vyron.WebApi.Models;
using Vyron.WebApi.Services;

namespace Vyron.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IAuthService _authService,
        ILogger<AuthController> logger)
    {
        this._authService = _authService;
        _logger = logger;
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request)
    {
        try
        {
            var response = await _authService.LoginAsync(request.Username, request.Password);
            
            if (response == null)
                return Unauthorized(new { message = "Invalid credentials" });
            
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error for user {Username}", request.Username);
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<LoginResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var response = await _authService.RefreshTokenAsync(request.RefreshToken);
            
            if (response == null)
                return Unauthorized(new { message = "Invalid refresh token" });
            
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh error");
            return StatusCode(500, "Internal server error");
        }
    }
}

public class RefreshTokenRequest
{
    public string RefreshToken { get; set; } = "";
}
