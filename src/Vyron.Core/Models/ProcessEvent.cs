namespace Vyron.Core.Models;

/// <summary>
/// Represents a process creation or modification event
/// </summary>
public class ProcessEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public ProcessEventType EventType { get; set; }
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public string ParentProcessName { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public IntegrityLevel IntegrityLevel { get; set; }
    public bool IsElevated { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public enum ProcessEventType
{
    Created,
    Terminated,
    Modified,
    InjectionDetected
}

public enum IntegrityLevel
{
    Untrusted,
    Low,
    Medium,
    High,
    System
}
