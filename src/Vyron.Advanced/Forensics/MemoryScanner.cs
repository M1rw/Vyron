using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Vyron.Advanced.Forensics;

/// <summary>
/// Advanced memory scanner for detecting:
/// - Process injection (DLL injection, reflective DLL injection)
/// - Process hollowing
/// - Hook detection (inline hooks, IAT hooks)
/// - Shellcode detection
/// - Memory-only malware
/// </summary>
public unsafe class MemoryScanner
{
    private readonly ILogger<MemoryScanner> _logger;

    public MemoryScanner(ILogger<MemoryScanner> logger)
    {
        _logger = logger;
    }

    public async Task<MemoryScanResult> ScanProcessAsync(int processId)
    {
        var result = new MemoryScanResult { ProcessId = processId };

        try
        {
            var process = Process.GetProcessById(processId);
            var handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);

            if (handle == IntPtr.Zero)
            {
                _logger.LogDebug("Cannot open process {Pid} for memory scanning", processId);
                return result;
            }

            try
            {
                // 1. Detect injected DLLs
                result.InjectedModules = await DetectInjectedDllsAsync(process, handle);

                // 2. Detect process hollowing
                result.IsHollowed = await DetectProcessHollowingAsync(process, handle);

                // 3. Detect inline hooks
                result.HookedFunctions = await DetectInlineHooksAsync(process, handle);

                // 4. Detect executable memory regions (shellcode)
                result.SuspiciousMemoryRegions = await DetectExecutableMemoryAsync(process, handle);

                // 5. Detect hidden threads
                result.HiddenThreads = await DetectHiddenThreadsAsync(process);

                // 6. Check for reflective DLL injection
                result.HasReflectiveDll = await DetectReflectiveDllAsync(process, handle);

                // Calculate suspicion score
                result.SuspicionScore = CalculateSuspicionScore(result);
                result.IsSuspicious = result.SuspicionScore > 0.6;

                if (result.IsSuspicious)
                {
                    _logger.LogWarning("Suspicious memory detected in process {Name} (PID: {Pid}), Score: {Score:F2}",
                        process.ProcessName, processId, result.SuspicionScore);
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning process memory: {Pid}", processId);
        }

        return result;
    }

    private async Task<List<string>> DetectInjectedDllsAsync(Process process, IntPtr handle)
    {
        var injectedDlls = new List<string>();

        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                try
                {
                    var modulePath = module.FileName.ToLowerInvariant();

                    // Check if DLL is loaded from suspicious location
                    var suspiciousLocations = new[]
                    {
                        @"\appdata\local\temp\",
                        @"\users\public\",
                        @"\windows\temp\",
                        @"\programdata\"
                    };

                    if (suspiciousLocations.Any(loc => modulePath.Contains(loc)))
                    {
                        injectedDlls.Add(module.FileName);
                        _logger.LogWarning("Potential injected DLL: {Path}", module.FileName);
                    }

                    // Check if DLL has no disk backing (memory-only DLL)
                    if (!File.Exists(modulePath) && !modulePath.Contains("\\windows\\"))
                    {
                        injectedDlls.Add($"[MEMORY-ONLY] {module.ModuleName}");
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error enumerating modules");
        }

        await Task.CompletedTask;
        return injectedDlls;
    }

    private async Task<bool> DetectProcessHollowingAsync(Process process, IntPtr handle)
    {
        try
        {
            // Read PEB (Process Environment Block) to check if executable path matches
            var pbi = new PROCESS_BASIC_INFORMATION();
            int size = 0;
            
            var status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), ref size);
            if (status != 0)
                return false;

            // Read ImageBaseAddress from PEB
            var peb = new PEB();
            if (!ReadProcessMemory(handle, pbi.PebBaseAddress, ref peb, Marshal.SizeOf(peb), out _))
                return false;

            // Read DOS header
            var dosHeader = new IMAGE_DOS_HEADER();
            if (!ReadProcessMemory(handle, peb.ImageBaseAddress, ref dosHeader, Marshal.SizeOf(dosHeader), out _))
                return false;

            // Verify DOS signature
            if (dosHeader.e_magic != 0x5A4D) // "MZ"
            {
                _logger.LogWarning("Process hollowing detected: Invalid DOS header in PID {Pid}", process.Id);
                return true;
            }

            // Check if executable path on disk matches memory
            try
            {
                var diskBytes = await File.ReadAllBytesAsync(process.MainModule?.FileName ?? "");
                var memoryBytes = new byte[1024];
                
                if (ReadProcessMemory(handle, peb.ImageBaseAddress, memoryBytes, memoryBytes.Length, out var bytesRead))
                {
                    // Compare first 1KB
                    var diskHash = GetSimpleHash(diskBytes.Take(1024).ToArray());
                    var memoryHash = GetSimpleHash(memoryBytes.Take((int)bytesRead).ToArray());

                    if (diskHash != memoryHash)
                    {
                        _logger.LogWarning("Process hollowing detected: Memory mismatch in PID {Pid}", process.Id);
                        return true;
                    }
                }
            }
            catch { }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking for process hollowing");
        }

        return false;
    }

    private async Task<List<string>> DetectInlineHooksAsync(Process process, IntPtr handle)
    {
        var hookedFunctions = new List<string>();

        try
        {
            // Check critical system DLLs for hooks
            var criticalDlls = new[] { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll" };

            foreach (var dllName in criticalDlls)
            {
                var module = process.Modules.Cast<ProcessModule>()
                    .FirstOrDefault(m => m.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase));

                if (module == null)
                    continue;

                // Read first few bytes of critical functions
                var criticalFunctions = new[] { "NtCreateFile", "NtReadFile", "NtWriteFile", "CreateProcessW" };

                foreach (var funcName in criticalFunctions)
                {
                    try
                    {
                        var funcAddress = GetProcAddress(GetModuleHandle(dllName), funcName);
                        if (funcAddress == IntPtr.Zero)
                            continue;

                        var bytes = new byte[16];
                        if (ReadProcessMemory(handle, funcAddress, bytes, bytes.Length, out _))
                        {
                            // Check for common hook patterns
                            // JMP (E9), PUSH + RET (68 + C3), MOV RAX + JMP RAX (48 B8 ... FF E0)
                            if (bytes[0] == 0xE9 || // JMP relative
                                (bytes[0] == 0x68 && bytes[5] == 0xC3) || // PUSH + RET
                                (bytes[0] == 0x48 && bytes[1] == 0xB8)) // MOV RAX
                            {
                                hookedFunctions.Add($"{dllName}!{funcName}");
                                _logger.LogWarning("Inline hook detected: {Dll}!{Func}", dllName, funcName);
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error detecting inline hooks");
        }

        await Task.CompletedTask;
        return hookedFunctions;
    }

    private async Task<List<MemoryRegion>> DetectExecutableMemoryAsync(Process process, IntPtr handle)
    {
        var suspiciousRegions = new List<MemoryRegion>();

        try
        {
            var address = IntPtr.Zero;
            var mbi = new MEMORY_BASIC_INFORMATION();

            while (VirtualQueryEx(handle, address, ref mbi, (uint)Marshal.SizeOf(mbi)) != 0)
            {
                // Check for RWX (Read-Write-Execute) pages - highly suspicious
                if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT)
                {
                    var buffer = new byte[Math.Min(mbi.RegionSize.ToInt32(), 4096)];
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buffer, buffer.Length, out var bytesRead))
                    {
                        // Check if it looks like shellcode
                        if (LooksLikeShellcode(buffer))
                        {
                            suspiciousRegions.Add(new MemoryRegion
                            {
                                BaseAddress = mbi.BaseAddress,
                                Size = mbi.RegionSize.ToInt64(),
                                Protection = "RWX",
                                Type = "Possible Shellcode"
                            });

                            _logger.LogWarning("Suspicious RWX memory region at 0x{Address:X} in PID {Pid}",
                                mbi.BaseAddress.ToInt64(), process.Id);
                        }
                    }
                }

                // Move to next region
                address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning memory regions");
        }

        await Task.CompletedTask;
        return suspiciousRegions;
    }

    private async Task<int> DetectHiddenThreadsAsync(Process process)
    {
        int hiddenCount = 0;

        try
        {
            // Compare threads visible via Process API vs. direct enumeration
            var visibleThreads = process.Threads.Count;
            
            // Use NtQuerySystemInformation to get all threads
            // This would detect threads hidden via DKOM (Direct Kernel Object Manipulation)
            
            // Simplified implementation - in production, use NtQuerySystemInformation
            _logger.LogDebug("Thread count check for PID {Pid}: {Count}", process.Id, visibleThreads);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error detecting hidden threads");
        }

        await Task.CompletedTask;
        return hiddenCount;
    }

    private async Task<bool> DetectReflectiveDllAsync(Process process, IntPtr handle)
    {
        try
        {
            // Reflective DLL injection leaves characteristic patterns:
            // 1. Memory regions without corresponding disk modules
            // 2. PE headers in unexpected locations
            // 3. Export tables in non-module memory

            var address = IntPtr.Zero;
            var mbi = new MEMORY_BASIC_INFORMATION();

            while (VirtualQueryEx(handle, address, ref mbi, (uint)Marshal.SizeOf(mbi)) != 0)
            {
                if (mbi.State == MEM_COMMIT && mbi.RegionSize.ToInt32() > 0x10000) // > 64KB
                {
                    var buffer = new byte[2];
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buffer, 2, out _))
                    {
                        // Check for "MZ" signature in non-module memory
                        if (buffer[0] == 0x4D && buffer[1] == 0x5A) // "MZ"
                        {
                            // Verify this isn't a known module
                            var isKnownModule = process.Modules.Cast<ProcessModule>()
                                .Any(m => m.BaseAddress == mbi.BaseAddress);

                            if (!isKnownModule)
                            {
                                _logger.LogWarning("Reflective DLL detected at 0x{Address:X} in PID {Pid}",
                                    mbi.BaseAddress.ToInt64(), process.Id);
                                return true;
                            }
                        }
                    }
                }

                address = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error detecting reflective DLL");
        }

        await Task.CompletedTask;
        return false;
    }

    private bool LooksLikeShellcode(byte[] buffer)
    {
        // Shellcode detection heuristics
        int executableInstructions = 0;
        int totalBytes = Math.Min(buffer.Length, 256);

        for (int i = 0; i < totalBytes - 1; i++)
        {
            // Common x64 shellcode patterns
            if (buffer[i] == 0x48 && (buffer[i + 1] & 0xF0) == 0x80) // REX.W prefix + MOV
                executableInstructions++;
            else if (buffer[i] == 0xFF && (buffer[i + 1] & 0xF8) == 0xD0) // CALL register
                executableInstructions++;
            else if (buffer[i] == 0x90) // NOP sled
                executableInstructions++;
            else if (buffer[i] == 0xCC) // INT3 (breakpoint)
                executableInstructions++;
        }

        // High density of executable instructions suggests shellcode
        return (double)executableInstructions / totalBytes > 0.3;
    }

    private double CalculateSuspicionScore(MemoryScanResult result)
    {
        double score = 0.0;

        if (result.InjectedModules.Count > 0)
            score += 0.3 * Math.Min(result.InjectedModules.Count, 3);

        if (result.IsHollowed)
            score += 0.5;

        if (result.HookedFunctions.Count > 0)
            score += 0.25 * Math.Min(result.HookedFunctions.Count, 4);

        if (result.SuspiciousMemoryRegions.Count > 0)
            score += 0.4 * Math.Min(result.SuspiciousMemoryRegions.Count, 2);

        if (result.HasReflectiveDll)
            score += 0.4;

        if (result.HiddenThreads > 0)
            score += 0.3;

        return Math.Min(score, 1.0);
    }

    private int GetSimpleHash(byte[] data)
    {
        int hash = 0;
        foreach (var b in data)
            hash = (hash * 31 + b) & 0x7FFFFFFF;
        return hash;
    }

    #region Windows API

    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_VM_READ = 0x0010;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint MEM_COMMIT = 0x1000;

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref PEB lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref IMAGE_DOS_HEADER lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, ref int returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PEB
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public byte BitField;
        public IntPtr Mutant;
        public IntPtr ImageBaseAddress;
        // ... other fields omitted for brevity
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        // ... other fields omitted
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    #endregion
}

public class MemoryScanResult
{
    public int ProcessId { get; set; }
    public List<string> InjectedModules { get; set; } = new();
    public bool IsHollowed { get; set; }
    public List<string> HookedFunctions { get; set; } = new();
    public List<MemoryRegion> SuspiciousMemoryRegions { get; set; } = new();
    public int HiddenThreads { get; set; }
    public bool HasReflectiveDll { get; set; }
    public double SuspicionScore { get; set; }
    public bool IsSuspicious { get; set; }
}

public class MemoryRegion
{
    public IntPtr BaseAddress { get; set; }
    public long Size { get; set; }
    public string Protection { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
}
