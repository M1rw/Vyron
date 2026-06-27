namespace Vyron.Core.Models;

/// <summary>
/// Represents a file system event
/// </summary>
public class FileEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public FileEventType EventType { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string FileExtension { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public string FileHash { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string UserName { get; set; } = string.Empty;
    public bool IsSystemFile { get; set; }
    public bool IsExecutable { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new();
}

public enum FileEventType
{
    Created,
    Modified,
    Deleted,
    Renamed,
    Accessed,
    AttributeChanged
}
