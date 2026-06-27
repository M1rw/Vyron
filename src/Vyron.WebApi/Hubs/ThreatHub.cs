using Microsoft.AspNetCore.SignalR;
using Vyron.WebApi.Models;

namespace Vyron.WebApi.Hubs;

/// <summary>
/// SignalR Hub for real-time threat alerts
/// </summary>
public class ThreatHub : Hub
{
    private readonly ILogger<ThreatHub> _logger;

    public ThreatHub(ILogger<ThreatHub> logger)
    {
        _logger = logger;
    }

    public override async Task OnConnectedAsync()
    {
        _logger.LogInformation("Client connected: {ConnectionId}", Context.ConnectionId);
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        _logger.LogInformation("Client disconnected: {ConnectionId}", Context.ConnectionId);
        await base.OnDisconnectedAsync(exception);
    }

    public async Task SubscribeToSeverity(string severity)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, severity);
        _logger.LogInformation("Client {ConnectionId} subscribed to {Severity}", 
            Context.ConnectionId, severity);
    }

    public async Task UnsubscribeFromSeverity(string severity)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, severity);
        _logger.LogInformation("Client {ConnectionId} unsubscribed from {Severity}", 
            Context.ConnectionId, severity);
    }
}

public interface IThreatHubService
{
    Task SendThreatAlertAsync(ThreatAlertDto alert);
    Task SendSystemHealthUpdateAsync(DashboardStatsDto stats);
}

public class ThreatHubService : IThreatHubService
{
    private readonly IHubContext<ThreatHub> _hubContext;
    private readonly ILogger<ThreatHubService> _logger;

    public ThreatHubService(
        IHubContext<ThreatHub> hubContext,
        ILogger<ThreatHubService> logger)
    {
        _hubContext = hubContext;
        _logger = logger;
    }

    public async Task SendThreatAlertAsync(ThreatAlertDto alert)
    {
        try
        {
            // Send to all clients
            await _hubContext.Clients.All.SendAsync("ReceiveThreat", alert);
            
            // Send to severity-specific groups
            await _hubContext.Clients.Group(alert.Severity)
                .SendAsync("ReceiveThreat", alert);
            
            _logger.LogInformation("Threat alert sent: {ThreatId} - {Severity}", 
                alert.Id, alert.Severity);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending threat alert");
        }
    }

    public async Task SendSystemHealthUpdateAsync(DashboardStatsDto stats)
    {
        try
        {
            await _hubContext.Clients.All.SendAsync("ReceiveHealthUpdate", stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending health update");
        }
    }
}
