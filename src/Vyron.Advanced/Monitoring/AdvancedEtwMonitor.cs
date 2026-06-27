using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using Vyron.Core.Models;

namespace Vyron.Advanced.Monitoring;

/// <summary>
/// Advanced ETW monitoring for DNS, Network, Registry, WMI, and more
/// Uses multiple ETW providers for comprehensive visibility
/// </summary>
public class AdvancedEtwMonitor
{
    private readonly ILogger<AdvancedEtwMonitor> _logger;
    private readonly List<TraceEventSession> _sessions = new();
    private CancellationTokenSource? _cts;

    public event EventHandler<NetworkEvent>? NetworkEventDetected;
    public event EventHandler<RegistryEvent>? RegistryEventDetected;
    public event EventHandler<DnsQueryEvent>? DnsQueryDetected;
    public event EventHandler<WmiEvent>? WmiEventDetected;
    public event EventHandler<ThreadEvent>? ThreadEventDetected;
    public event EventHandler<ImageLoadEvent>? ImageLoadDetected;

    public AdvancedEtwMonitor(ILogger<AdvancedEtwMonitor> logger)
    {
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting advanced ETW monitoring...");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        try
        {
            // Start multiple monitoring tasks
            var tasks = new[]
            {
                Task.Run(() => MonitorDnsQueries(_cts.Token), _cts.Token),
                Task.Run(() => MonitorNetworkConnections(_cts.Token), _cts.Token),
                Task.Run(() => MonitorRegistryOperations(_cts.Token), _cts.Token),
                Task.Run(() => MonitorWmiActivity(_cts.Token), _cts.Token),
                Task.Run(() => MonitorThreadOperations(_cts.Token), _cts.Token),
                Task.Run(() => MonitorImageLoads(_cts.Token), _cts.Token)
            };

            await Task.WhenAll(tasks);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Advanced ETW monitoring failed");
        }
    }

    private void MonitorDnsQueries(CancellationToken cancellationToken)
    {
        try
        {
            var sessionName = "VyronDnsMonitor";
            CleanupSession(sessionName);

            var session = new TraceEventSession(sessionName);
            _sessions.Add(session);

            // Enable DNS Client provider
            session.EnableProvider("Microsoft-Windows-DNS-Client", TraceEventLevel.Informational);

            session.Source.Dynamic.All += data =>
            {
                try
                {
                    if (data.ProviderName.Contains("DNS") && data.EventName.Contains("Query"))
                    {
                        var queryName = data.PayloadStringByName("QueryName") ?? string.Empty;
                        var queryType = data.PayloadStringByName("QueryType") ?? string.Empty;
                        var processId = data.ProcessID;

                        var dnsEvent = new DnsQueryEvent
                        {
                            QueryName = queryName,
                            QueryType = queryType,
                            ProcessId = processId,
                            Timestamp = data.TimeStamp
                        };

                        // Detect suspicious DNS queries
                        if (IsSuspiciousDnsQuery(queryName))
                        {
                            _logger.LogWarning("Suspicious DNS query: {Query} from PID {Pid}", queryName, processId);
                            DnsQueryDetected?.Invoke(this, dnsEvent);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing DNS event");
                }
            };

            _logger.LogInformation("DNS monitoring started");
            session.Source.Process();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DNS monitoring failed");
        }
    }

    private void MonitorNetworkConnections(CancellationToken cancellationToken)
    {
        try
        {
            var sessionName = "VyronNetworkMonitor";
            CleanupSession(sessionName);

            var session = new TraceEventSession(sessionName);
            _sessions.Add(session);

            // Enable TCP/IP provider
            session.EnableProvider("Microsoft-Windows-TCPIP", TraceEventLevel.Informational,
                keywords: 0x0000000000000001); // Connect/Disconnect events

            session.Source.Dynamic.All += data =>
            {
                try
                {
                    if (data.EventName.Contains("Connect") || data.EventName.Contains("Accept"))
                    {
                        var processId = data.ProcessID;
                        var remoteAddress = data.PayloadStringByName("daddr") ?? string.Empty;
                        var remotePort = data.PayloadByName("dport") as uint? ?? 0;
                        var localAddress = data.PayloadStringByName("saddr") ?? string.Empty;
                        var localPort = data.PayloadByName("sport") as uint? ?? 0;

                        var networkEvent = new NetworkEvent
                        {
                            ProcessId = processId,
                            RemoteAddress = remoteAddress,
                            RemotePort = (int)remotePort,
                            LocalAddress = localAddress,
                            LocalPort = (int)localPort,
                            EventType = data.EventName.Contains("Connect") ? "Outbound" : "Inbound",
                            Timestamp = data.TimeStamp
                        };

                        // Detect suspicious connections
                        if (IsSuspiciousConnection(networkEvent))
                        {
                            _logger.LogWarning("Suspicious network connection: {Remote}:{Port} from PID {Pid}",
                                remoteAddress, remotePort, processId);
                            NetworkEventDetected?.Invoke(this, networkEvent);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing network event");
                }
            };

            _logger.LogInformation("Network monitoring started");
            session.Source.Process();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Network monitoring failed");
        }
    }

    private void MonitorRegistryOperations(CancellationToken cancellationToken)
    {
        try
        {
            var sessionName = "VyronRegistryMonitor";
            CleanupSession(sessionName);

            var session = new TraceEventSession(sessionName);
            _sessions.Add(session);

            // Enable Registry provider
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Registry);

            session.Source.Kernel.RegistrySetValue += data =>
            {
                try
                {
                    var keyName = data.KeyName ?? string.Empty;
                    var valueName = data.ValueName ?? string.Empty;
                    var processId = data.ProcessID;

                    if (IsSuspiciousRegistryOperation(keyName, valueName))
                    {
                        var regEvent = new RegistryEvent
                        {
                            ProcessId = processId,
                            KeyPath = keyName,
                            ValueName = valueName,
                            Operation = "SetValue",
                            Timestamp = data.TimeStamp
                        };

                        _logger.LogWarning("Suspicious registry modification: {Key}\\{Value} by PID {Pid}",
                            keyName, valueName, processId);
                        RegistryEventDetected?.Invoke(this, regEvent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing registry event");
                }
            };

            session.Source.Kernel.RegistryCreate += data =>
            {
                try
                {
                    var keyName = data.KeyName ?? string.Empty;
                    var processId = data.ProcessID;

                    if (IsSuspiciousRegistryOperation(keyName, ""))
                    {
                        var regEvent = new RegistryEvent
                        {
                            ProcessId = processId,
                            KeyPath = keyName,
                            Operation = "CreateKey",
                            Timestamp = data.TimeStamp
                        };

                        RegistryEventDetected?.Invoke(this, regEvent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing registry create event");
                }
            };

            _logger.LogInformation("Registry monitoring started");
            session.Source.Process();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registry monitoring failed");
        }
    }

    private void MonitorWmiActivity(CancellationToken cancellationToken)
    {
        try
        {
            var sessionName = "VyronWmiMonitor";
            CleanupSession(sessionName);

            var session = new TraceEventSession(sessionName);
            _sessions.Add(session);

            // Enable WMI Activity provider
            session.EnableProvider("Microsoft-Windows-WMI-Activity", TraceEventLevel.Informational);

            session.Source.Dynamic.All += data =>
            {
                try
                {
                    if (data.EventName.Contains("Execute"))
                    {
                        var query = data.PayloadStringByName("Query") ?? string.Empty;
                        var processId = data.ProcessID;

                        if (IsSuspiciousWmiQuery(query))
                        {
                            var wmiEvent = new WmiEvent
                            {
                                ProcessId = processId,
                                Query = query,
                                Timestamp = data.TimeStamp
                            };

                            _logger.LogWarning("Suspicious WMI query: {Query} from PID {Pid}", query, processId);
                            WmiEventDetected?.Invoke(this, wmiEvent);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing WMI event");
                }
            };

            _logger.LogInformation("WMI monitoring started");
            session.Source.Process();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WMI monitoring failed");
        }
    }

    private void MonitorThreadOperations(CancellationToken cancellationToken)
    {
        try
        {
            var sessionName = "VyronThreadMonitor";
            CleanupSession(sessionName);

            var session = new TraceEventSession(sessionName);
            _sessions.Add(session);

            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Thread);

            session.Source.Kernel.ThreadStart += data =>
            {
                try
                {
                    // Detect thread injection - thread created in remote process
                    if (data.ProcessID != data.ThreadID)
                    {
                        var threadEvent = new ThreadEvent
                        {
                            ProcessId = data.ProcessID,
                            ThreadId = data.ThreadID,
                            TargetProcessId = data.ProcessID,
                            EventType = "RemoteThreadCreate",
                            Timestamp = data.TimeStamp
                        };

                        _logger.LogWarning("Potential thread injection detected: Thread {Tid} created in process {Pid}",
                            data.ThreadID, data.ProcessID);
                        ThreadEventDetected?.Invoke(this, threadEvent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing thread event");
                }
            };

            _logger.LogInformation("Thread monitoring started");
            session.Source.Process();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Thread monitoring failed");
        }
    }

    private void MonitorImageLoads(CancellationToken cancellationToken)
    {
        try
        {
            var sessionName = "VyronImageLoadMonitor";
            CleanupSession(sessionName);

            var session = new TraceEventSession(sessionName);
            _sessions.Add(session);

            session.EnableKernelProvider(KernelTraceEventParser.Keywords.ImageLoad);

            session.Source.Kernel.ImageLoad += data =>
            {
                try
                {
                    var imageName = data.FileName ?? string.Empty;
                    var processId = data.ProcessID;

                    // Detect suspicious DLL loads
                    if (IsSuspiciousDllLoad(imageName))
                    {
                        var imageEvent = new ImageLoadEvent
                        {
                            ProcessId = processId,
                            ImagePath = imageName,
                            ImageBase = data.ImageBase,
                            ImageSize = (long)data.ImageSize,
                            Timestamp = data.TimeStamp
                        };

                        _logger.LogWarning("Suspicious DLL load: {Image} into PID {Pid}", imageName, processId);
                        ImageLoadDetected?.Invoke(this, imageEvent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing image load event");
                }
            };

            _logger.LogInformation("Image load monitoring started");
            session.Source.Process();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Image load monitoring failed");
        }
    }

    private bool IsSuspiciousDnsQuery(string queryName)
    {
        var lower = queryName.ToLowerInvariant();
        
        // Check for DNS tunneling (excessive length, entropy)
        if (lower.Length > 60)
            return true;

        // Known C2 domains (simplified - use threat intel in production)
        var suspiciousTlds = new[] { ".tk", ".ml", ".ga", ".cf", ".onion", ".bit" };
        if (suspiciousTlds.Any(tld => lower.EndsWith(tld)))
            return true;

        // DGA (Domain Generation Algorithm) detection - check for high consonant ratio
        var consonants = "bcdfghjklmnpqrstvwxyz";
        var consonantCount = lower.Count(c => consonants.Contains(c));
        if (consonantCount > lower.Length * 0.7)
            return true;

        return false;
    }

    private bool IsSuspiciousConnection(NetworkEvent networkEvent)
    {
        // Known malicious ports
        var suspiciousPorts = new[] { 4444, 5555, 6666, 7777, 8888, 31337, 12345 };
        if (suspiciousPorts.Contains(networkEvent.RemotePort))
            return true;

        // Connection to localhost (potential port forwarding/tunneling)
        if (networkEvent.RemoteAddress.StartsWith("127.") && networkEvent.RemotePort > 8000)
            return true;

        // Private IP ranges from public process (potential pivot)
        var privateRanges = new[] { "10.", "172.16.", "192.168." };
        if (privateRanges.Any(r => networkEvent.RemoteAddress.StartsWith(r)))
        {
            // Check if it's a system process making the connection
            return false; // Implement process whitelist check
        }

        return false;
    }

    private bool IsSuspiciousRegistryOperation(string keyName, string valueName)
    {
        var keyLower = keyName.ToLowerInvariant();

        // Persistence locations
        var persistenceKeys = new[]
        {
            @"software\microsoft\windows\currentversion\run",
            @"software\microsoft\windows\currentversion\runonce",
            @"software\microsoft\windows nt\currentversion\winlogon",
            @"system\currentcontrolset\services",
            @"software\microsoft\windows\currentversion\policies\explorer\run"
        };

        if (persistenceKeys.Any(pk => keyLower.Contains(pk)))
            return true;

        // Security settings modification
        if (keyLower.Contains("firewall") || keyLower.Contains("antivirus") || keyLower.Contains("defender"))
            return true;

        return false;
    }

    private bool IsSuspiciousWmiQuery(string query)
    {
        var lower = query.ToLowerInvariant();

        // Reconnaissance queries
        if (lower.Contains("win32_process") || lower.Contains("win32_service") || 
            lower.Contains("win32_product") || lower.Contains("antivirusproduct"))
            return true;

        // Lateral movement
        if (lower.Contains("create") && lower.Contains("win32_process"))
            return true;

        return false;
    }

    private bool IsSuspiciousDllLoad(string imageName)
    {
        var lower = imageName.ToLowerInvariant();

        // DLLs loaded from suspicious locations
        var suspiciousLocations = new[]
        {
            @"\temp\", @"\appdata\local\temp\", @"\users\public\",
            @"\programdata\", @"\windows\temp\"
        };

        if (suspiciousLocations.Any(loc => lower.Contains(loc)))
            return true;

        // Known malicious DLL names
        var maliciousDlls = new[] { "mimikatz", "pwdump", "procdump", "inject" };
        if (maliciousDlls.Any(dll => lower.Contains(dll)))
            return true;

        return false;
    }

    private void CleanupSession(string sessionName)
    {
        try
        {
            var existing = TraceEventSession.GetActiveSession(sessionName);
            existing?.Dispose();
        }
        catch { }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping advanced ETW monitoring...");
        _cts?.Cancel();
        
        foreach (var session in _sessions)
        {
            session.Dispose();
        }
        
        _sessions.Clear();
        return Task.CompletedTask;
    }
}

// Event models
public class DnsQueryEvent
{
    public string QueryName { get; set; } = string.Empty;
    public string QueryType { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime Timestamp { get; set; }
}

public class NetworkEvent
{
    public int ProcessId { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string EventType { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

public class RegistryEvent
{
    public int ProcessId { get; set; }
    public string KeyPath { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public string Operation { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

public class WmiEvent
{
    public int ProcessId { get; set; }
    public string Query { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

public class ThreadEvent
{
    public int ProcessId { get; set; }
    public int ThreadId { get; set; }
    public int TargetProcessId { get; set; }
    public string EventType { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

public class ImageLoadEvent
{
    public int ProcessId { get; set; }
    public string ImagePath { get; set; } = string.Empty;
    public ulong ImageBase { get; set; }
    public long ImageSize { get; set; }
    public DateTime Timestamp { get; set; }
}
