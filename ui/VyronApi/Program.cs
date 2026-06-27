var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSignalR();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowAll");
app.MapControllers();
app.MapHub<ThreatHub>("/hubs/threats");

// Health endpoint
app.MapGet("/api/health", () => new
{
    status = "Healthy",
    version = "2.0.0",
    detectionRate = 96.1,
    timestamp = DateTime.UtcNow
});

// Dashboard stats
app.MapGet("/api/dashboard/stats", () => new
{
    totalThreatsToday = 47,
    criticalThreats = 8,
    highThreats = 12,
    mediumThreats = 19,
    lowThreats = 8,
    detectionRate = 96.1,
    protectedEndpoints = 42,
    vulnerableEndpoints = 3,
    offlineEndpoints = 1,
    isolatedEndpoints = 0,
    cpuUsage = 18,
    memoryUsageMb = 742,
    detectionLatencyMs = 8,
    falsePositiveRate = 0.02
});

// Auth endpoint (demo)
app.MapPost("/api/auth/login", (LoginRequest req) =>
{
    if (req.Username == "admin" && req.Password == "admin")
    {
        return Results.Ok(new
        {
            token = "demo_token_" + Guid.NewGuid().ToString("N"),
            refreshToken = Guid.NewGuid().ToString("N"),
            expiresAt = DateTime.UtcNow.AddHours(8).ToString("O")
        });
    }
    return Results.Unauthorized();
});

app.Run();

record LoginRequest(string Username, string Password);

// SignalR Hub
public class ThreatHub : Microsoft.AspNetCore.SignalR.Hub
{
    public async Task SubscribeToSeverity(string severity)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, severity);
    }
}
