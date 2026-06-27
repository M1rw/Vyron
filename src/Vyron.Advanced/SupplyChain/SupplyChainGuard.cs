using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Vyron.Advanced.SupplyChain;

/// <summary>
/// Supply Chain Attack Prevention System
/// Validates code signatures, tracks Software Bill of Materials (SBOM),
/// monitors package managers (npm, NuGet, pip), and detects CI/CD compromises
/// </summary>
public class SupplyChainGuard
{
    private readonly ILogger<SupplyChainGuard> _logger;
    private readonly Dictionary<string, SbomEntry> _sbomDatabase = new();
    private readonly HashSet<string> _trustedPublishers = new();
    private readonly HashSet<string> _vulnerablePackages = new();

    // Known malicious package patterns
    private readonly List<MaliciousPackagePattern> _maliciousPatterns = new()
    {
        new() { Pattern = @".*typosquat.*", Description = "Typosquatting attempt", Severity = "Critical" },
        new() { Pattern = @".*\d{8}.*", Description = "Suspicious version number (date)", Severity = "Medium" },
        new() { Pattern = @".*test.*prod.*", Description = "Test package in production", Severity = "High" },
    };

    public SupplyChainGuard(ILogger<SupplyChainGuard> logger)
    {
        _logger = logger;
        InitializeTrustedPublishers();
        LoadVulnerabilityDatabase();
    }

    private void InitializeTrustedPublishers()
    {
        // Microsoft trusted publishers
        _trustedPublishers.Add("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US");
        _trustedPublishers.Add("CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US");
        
        // Add more trusted publishers as needed
        _logger.LogInformation("Initialized {Count} trusted publishers", _trustedPublishers.Count);
    }

    private void LoadVulnerabilityDatabase()
    {
        // In production: Load from NIST NVD, GitHub Advisory Database, etc.
        // For demonstration, adding some known vulnerable packages
        _vulnerablePackages.Add("log4j-core:2.14.0"); // Log4Shell
        _vulnerablePackages.Add("spring-core:5.3.0"); // Spring4Shell
        _vulnerablePackages.Add("jackson-databind:2.9.8"); // Deserialization
        
        _logger.LogInformation("Loaded {Count} vulnerable package signatures", _vulnerablePackages.Count);
    }

    public async Task<CodeSignatureValidationResult> ValidateCodeSignatureAsync(string filePath)
    {
        var result = new CodeSignatureValidationResult
        {
            FilePath = filePath,
            ValidationTime = DateTime.UtcNow
        };

        try
        {
            if (!File.Exists(filePath))
            {
                result.IsValid = false;
                result.ErrorMessage = "File not found";
                return result;
            }

            // Check for Authenticode signature
            var certificate = await GetAuthenticodeCertificateAsync(filePath);
            if (certificate == null)
            {
                result.IsSigned = false;
                result.IsValid = false;
                result.ThreatLevel = "High";
                result.ErrorMessage = "File is not digitally signed";
                
                _logger.LogWarning("Unsigned executable detected: {Path}", filePath);
                return result;
            }

            result.IsSigned = true;
            result.SignerName = certificate.Subject;
            result.IssuerName = certificate.Issuer;
            result.ValidFrom = certificate.NotBefore;
            result.ValidTo = certificate.NotAfter;

            // Validate certificate chain
            result.IsValid = ValidateCertificateChain(certificate);

            // Check if publisher is trusted
            result.IsTrustedPublisher = _trustedPublishers.Contains(certificate.Subject);

            // Check certificate expiration
            result.IsExpired = DateTime.Now > certificate.NotAfter || DateTime.Now < certificate.NotBefore;

            // Validate timestamp
            result.HasTimestamp = await ValidateTimestampAsync(filePath);

            // Check for certificate revocation
            result.IsRevoked = await CheckRevocationStatusAsync(certificate);

            // Calculate threat level
            result.ThreatLevel = CalculateSignatureThreatLevel(result);

            if (result.ThreatLevel == "Critical" || result.ThreatLevel == "High")
            {
                _logger.LogWarning(
                    "Suspicious code signature: {Path}, Signer: {Signer}, Threat: {Threat}",
                    filePath, result.SignerName, result.ThreatLevel);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating code signature: {Path}", filePath);
            result.IsValid = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    private async Task<X509Certificate2?> GetAuthenticodeCertificateAsync(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            var cert2 = new X509Certificate2(cert);
            await Task.CompletedTask;
            return cert2;
        }
        catch
        {
            return null;
        }
    }

    private bool ValidateCertificateChain(X509Certificate2 certificate)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            
            return chain.Build(certificate);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error validating certificate chain");
            return false;
        }
    }

    private async Task<bool> ValidateTimestampAsync(string filePath)
    {
        // In production: Use SignTool or Windows API to validate Authenticode timestamp
        // For now, simplified check
        await Task.CompletedTask;
        return true; // Assume timestamped for demonstration
    }

    private async Task<bool> CheckRevocationStatusAsync(X509Certificate2 certificate)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            
            chain.Build(certificate);
            
            foreach (var status in chain.ChainStatus)
            {
                if (status.Status == X509ChainStatusFlags.Revoked)
                {
                    _logger.LogCritical("Revoked certificate detected: {Subject}", certificate.Subject);
                    await Task.CompletedTask;
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking revocation status");
        }

        await Task.CompletedTask;
        return false;
    }

    public async Task<SbomAnalysisResult> AnalyzeSoftwareBillOfMaterialsAsync(string projectPath)
    {
        var result = new SbomAnalysisResult
        {
            ProjectPath = projectPath,
            AnalysisTime = DateTime.UtcNow
        };

        try
        {
            _logger.LogInformation("Analyzing SBOM for: {Path}", projectPath);

            // Detect package managers and scan dependencies
            result.NuGetPackages = await ScanNuGetPackagesAsync(projectPath);
            result.NpmPackages = await ScanNpmPackagesAsync(projectPath);
            result.PipPackages = await ScanPipPackagesAsync(projectPath);

            // Check for vulnerable packages
            result.VulnerablePackages = await IdentifyVulnerablePackagesAsync(result);

            // Check for malicious package patterns
            result.SuspiciousPackages = await IdentifySuspiciousPackagesAsync(result);

            // Check for license compliance issues
            result.LicenseIssues = await CheckLicenseComplianceAsync(result);

            // Generate SBOM hash for integrity tracking
            result.SbomHash = GenerateSbomHash(result);

            result.IsSafe = result.VulnerablePackages.Count == 0 && 
                           result.SuspiciousPackages.Count == 0;

            if (!result.IsSafe)
            {
                _logger.LogWarning(
                    "Supply chain issues detected: {Vulnerable} vulnerable, {Suspicious} suspicious packages",
                    result.VulnerablePackages.Count, result.SuspiciousPackages.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing SBOM: {Path}", projectPath);
        }

        return result;
    }

    private async Task<List<PackageInfo>> ScanNuGetPackagesAsync(string projectPath)
    {
        var packages = new List<PackageInfo>();

        try
        {
            // Find packages.config or *.csproj files
            var configFiles = Directory.GetFiles(projectPath, "packages.config", SearchOption.AllDirectories);
            var projectFiles = Directory.GetFiles(projectPath, "*.csproj", SearchOption.AllDirectories);

            // Parse packages.config
            foreach (var configFile in configFiles)
            {
                var content = await File.ReadAllTextAsync(configFile);
                // Parse XML to extract package references
                // Simplified for demonstration
            }

            // Parse PackageReference from .csproj
            foreach (var projFile in projectFiles)
            {
                var content = await File.ReadAllTextAsync(projFile);
                // Parse XML to extract PackageReference elements
                // Simplified for demonstration
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning NuGet packages");
        }

        return packages;
    }

    private async Task<List<PackageInfo>> ScanNpmPackagesAsync(string projectPath)
    {
        var packages = new List<PackageInfo>();

        try
        {
            var packageJsonPath = Path.Combine(projectPath, "package.json");
            if (File.Exists(packageJsonPath))
            {
                var json = await File.ReadAllTextAsync(packageJsonPath);
                var packageJson = JsonSerializer.Deserialize<NpmPackageJson>(json);

                if (packageJson?.Dependencies != null)
                {
                    foreach (var dep in packageJson.Dependencies)
                    {
                        packages.Add(new PackageInfo
                        {
                            Name = dep.Key,
                            Version = dep.Value,
                            PackageManager = "npm"
                        });
                    }
                }

                if (packageJson?.DevDependencies != null)
                {
                    foreach (var dep in packageJson.DevDependencies)
                    {
                        packages.Add(new PackageInfo
                        {
                            Name = dep.Key,
                            Version = dep.Value,
                            PackageManager = "npm",
                            IsDevelopment = true
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning npm packages");
        }

        return packages;
    }

    private async Task<List<PackageInfo>> ScanPipPackagesAsync(string projectPath)
    {
        var packages = new List<PackageInfo>();

        try
        {
            var requirementsPath = Path.Combine(projectPath, "requirements.txt");
            if (File.Exists(requirementsPath))
            {
                var lines = await File.ReadAllLinesAsync(requirementsPath);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    var parts = line.Split(new[] { "==", ">=", "<=" }, StringSplitOptions.None);
                    if (parts.Length >= 2)
                    {
                        packages.Add(new PackageInfo
                        {
                            Name = parts[0].Trim(),
                            Version = parts[1].Trim(),
                            PackageManager = "pip"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error scanning pip packages");
        }

        return packages;
    }

    private async Task<List<VulnerablePackage>> IdentifyVulnerablePackagesAsync(SbomAnalysisResult sbom)
    {
        var vulnerable = new List<VulnerablePackage>();

        var allPackages = sbom.NuGetPackages
            .Concat(sbom.NpmPackages)
            .Concat(sbom.PipPackages);

        foreach (var pkg in allPackages)
        {
            var signature = $"{pkg.Name}:{pkg.Version}";
            if (_vulnerablePackages.Contains(signature))
            {
                vulnerable.Add(new VulnerablePackage
                {
                    Name = pkg.Name,
                    Version = pkg.Version,
                    PackageManager = pkg.PackageManager,
                    Cve = "CVE-XXXX-YYYY", // Would be looked up from NVD
                    Severity = "Critical",
                    Description = "Known vulnerability detected"
                });

                _logger.LogCritical(
                    "Vulnerable package detected: {Package} {Version}",
                    pkg.Name, pkg.Version);
            }
        }

        await Task.CompletedTask;
        return vulnerable;
    }

    private async Task<List<SuspiciousPackage>> IdentifySuspiciousPackagesAsync(SbomAnalysisResult sbom)
    {
        var suspicious = new List<SuspiciousPackage>();

        var allPackages = sbom.NuGetPackages
            .Concat(sbom.NpmPackages)
            .Concat(sbom.PipPackages);

        foreach (var pkg in allPackages)
        {
            // Check against malicious patterns
            foreach (var pattern in _maliciousPatterns)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(pkg.Name, pattern.Pattern, 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                {
                    suspicious.Add(new SuspiciousPackage
                    {
                        Name = pkg.Name,
                        Version = pkg.Version,
                        PackageManager = pkg.PackageManager,
                        Reason = pattern.Description,
                        Severity = pattern.Severity
                    });

                    _logger.LogWarning(
                        "Suspicious package detected: {Package} - {Reason}",
                        pkg.Name, pattern.Description);
                }
            }

            // Check for typosquatting (simplified)
            if (await IsTyposquattingAttemptAsync(pkg.Name))
            {
                suspicious.Add(new SuspiciousPackage
                {
                    Name = pkg.Name,
                    Version = pkg.Version,
                    PackageManager = pkg.PackageManager,
                    Reason = "Possible typosquatting",
                    Severity = "Critical"
                });
            }
        }

        return suspicious;
    }

    private async Task<bool> IsTyposquattingAttemptAsync(string packageName)
    {
        // Known popular packages (simplified list)
        var popularPackages = new[] 
        { 
            "react", "angular", "vue", "lodash", "express", "axios", 
            "newtonsoft.json", "entityframework", "automapper" 
        };

        foreach (var popular in popularPackages)
        {
            // Calculate Levenshtein distance
            var distance = LevenshteinDistance(packageName.ToLower(), popular);
            if (distance > 0 && distance <= 2) // Very similar but not exact
            {
                _logger.LogWarning(
                    "Possible typosquatting: {Package} is similar to {Popular}",
                    packageName, popular);
                await Task.CompletedTask;
                return true;
            }
        }

        await Task.CompletedTask;
        return false;
    }

    private int LevenshteinDistance(string s1, string s2)
    {
        var matrix = new int[s1.Length + 1, s2.Length + 1];

        for (int i = 0; i <= s1.Length; i++)
            matrix[i, 0] = i;
        
        for (int j = 0; j <= s2.Length; j++)
            matrix[0, j] = j;

        for (int i = 1; i <= s1.Length; i++)
        {
            for (int j = 1; j <= s2.Length; j++)
            {
                int cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
                matrix[i, j] = Math.Min(Math.Min(
                    matrix[i - 1, j] + 1,
                    matrix[i, j - 1] + 1),
                    matrix[i - 1, j - 1] + cost);
            }
        }

        return matrix[s1.Length, s2.Length];
    }

    private async Task<List<LicenseIssue>> CheckLicenseComplianceAsync(SbomAnalysisResult sbom)
    {
        var issues = new List<LicenseIssue>();

        // Problematic licenses for commercial use
        var problematicLicenses = new[] { "GPL-3.0", "AGPL-3.0", "SSPL" };

        var allPackages = sbom.NuGetPackages
            .Concat(sbom.NpmPackages)
            .Concat(sbom.PipPackages);

        foreach (var pkg in allPackages)
        {
            // In production: Query package registry for license information
            // For demonstration, random check
            var license = "MIT"; // Placeholder

            if (problematicLicenses.Contains(license))
            {
                issues.Add(new LicenseIssue
                {
                    PackageName = pkg.Name,
                    License = license,
                    Issue = $"{license} may not be compatible with commercial use"
                });
            }
        }

        await Task.CompletedTask;
        return issues;
    }

    private string GenerateSbomHash(SbomAnalysisResult sbom)
    {
        var allPackages = sbom.NuGetPackages
            .Concat(sbom.NpmPackages)
            .Concat(sbom.PipPackages)
            .OrderBy(p => p.Name)
            .ThenBy(p => p.Version);

        var sbomString = string.Join("|", allPackages.Select(p => $"{p.Name}:{p.Version}"));
        
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(sbomString));
        return Convert.ToBase64String(hashBytes);
    }

    public async Task<CiCdCompromiseResult> DetectCiCdCompromiseAsync(string buildLogPath)
    {
        var result = new CiCdCompromiseResult
        {
            BuildLogPath = buildLogPath,
            AnalysisTime = DateTime.UtcNow
        };

        try
        {
            if (!File.Exists(buildLogPath))
            {
                result.IsCompromised = false;
                return result;
            }

            var logContent = await File.ReadAllTextAsync(buildLogPath);

            // Check for suspicious activities in build logs
            result.SuspiciousCommands = await DetectSuspiciousBuildCommandsAsync(logContent);
            result.UnauthorizedNetworkAccess = await DetectUnauthorizedNetworkAccessAsync(logContent);
            result.SecretExfiltration = await DetectSecretExfiltrationAsync(logContent);
            result.BuildToolTampering = await DetectBuildToolTamperingAsync(logContent);

            result.IsCompromised = result.SuspiciousCommands.Count > 0 ||
                                  result.UnauthorizedNetworkAccess.Count > 0 ||
                                  result.SecretExfiltration.Count > 0 ||
                                  result.BuildToolTampering;

            if (result.IsCompromised)
            {
                _logger.LogCritical(
                    "CI/CD compromise detected in build log: {Path}",
                    buildLogPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing CI/CD build log: {Path}", buildLogPath);
        }

        return result;
    }

    private async Task<List<string>> DetectSuspiciousBuildCommandsAsync(string logContent)
    {
        var suspicious = new List<string>();

        var patterns = new[]
        {
            @"curl.*\|.*bash",
            @"wget.*&&.*sh",
            @"powershell.*-enc",
            @"base64.*decode",
            @"npm.*install.*http://",  // Non-HTTPS package source
            @"pip.*install.*--index-url.*http://"
        };

        foreach (var pattern in patterns)
        {
            var matches = System.Text.RegularExpressions.Regex.Matches(logContent, pattern);
            suspicious.AddRange(matches.Select(m => m.Value));
        }

        await Task.CompletedTask;
        return suspicious;
    }

    private async Task<List<string>> DetectUnauthorizedNetworkAccessAsync(string logContent)
    {
        var unauthorized = new List<string>();

        // Check for connections to suspicious domains
        var suspiciousDomains = new[] { "pastebin.com", "hastebin.com", "temp.sh" };

        foreach (var domain in suspiciousDomains)
        {
            if (logContent.Contains(domain, StringComparison.OrdinalIgnoreCase))
            {
                unauthorized.Add($"Connection to suspicious domain: {domain}");
                _logger.LogWarning("Suspicious network access in build: {Domain}", domain);
            }
        }

        await Task.CompletedTask;
        return unauthorized;
    }

    private async Task<List<string>> DetectSecretExfiltrationAsync(string logContent)
    {
        var exfiltrations = new List<string>();

        // Check for potential secret exposure
        var patterns = new[]
        {
            @"AWS_SECRET_ACCESS_KEY",
            @"-----BEGIN.*PRIVATE KEY-----",
            @"api[_-]?key.*[:=]",
            @"token.*[:=]"
        };

        foreach (var pattern in patterns)
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(logContent, pattern, 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            {
                exfiltrations.Add($"Potential secret exposure: {pattern}");
                _logger.LogCritical("Secret exposure detected in build log: {Pattern}", pattern);
            }
        }

        await Task.CompletedTask;
        return exfiltrations;
    }

    private async Task<bool> DetectBuildToolTamperingAsync(string logContent)
    {
        // Check for modifications to build tools or scripts
        var tamperingIndicators = new[]
        {
            "modified: package.json",
            "modified: requirements.txt",
            "modified: .csproj",
            "checksum mismatch",
            "integrity check failed"
        };

        foreach (var indicator in tamperingIndicators)
        {
            if (logContent.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Build tool tampering indicator: {Indicator}", indicator);
                await Task.CompletedTask;
                return true;
            }
        }

        await Task.CompletedTask;
        return false;
    }

    private string CalculateSignatureThreatLevel(CodeSignatureValidationResult result)
    {
        if (!result.IsSigned)
            return "Critical";

        if (result.IsRevoked)
            return "Critical";

        if (!result.IsValid)
            return "High";

        if (result.IsExpired)
            return "High";

        if (!result.IsTrustedPublisher)
            return "Medium";

        if (!result.HasTimestamp)
            return "Medium";

        return "Low";
    }
}

#region Models

public class CodeSignatureValidationResult
{
    public string FilePath { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public bool IsValid { get; set; }
    public string SignerName { get; set; } = string.Empty;
    public string IssuerName { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public bool IsTrustedPublisher { get; set; }
    public bool IsExpired { get; set; }
    public bool HasTimestamp { get; set; }
    public bool IsRevoked { get; set; }
    public string ThreatLevel { get; set; } = "Unknown";
    public string ErrorMessage { get; set; } = string.Empty;
    public DateTime ValidationTime { get; set; }
}

public class SbomAnalysisResult
{
    public string ProjectPath { get; set; } = string.Empty;
    public List<PackageInfo> NuGetPackages { get; set; } = new();
    public List<PackageInfo> NpmPackages { get; set; } = new();
    public List<PackageInfo> PipPackages { get; set; } = new();
    public List<VulnerablePackage> VulnerablePackages { get; set; } = new();
    public List<SuspiciousPackage> SuspiciousPackages { get; set; } = new();
    public List<LicenseIssue> LicenseIssues { get; set; } = new();
    public string SbomHash { get; set; } = string.Empty;
    public bool IsSafe { get; set; }
    public DateTime AnalysisTime { get; set; }
}

public class PackageInfo
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string PackageManager { get; set; } = string.Empty;
    public bool IsDevelopment { get; set; }
}

public class VulnerablePackage
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string PackageManager { get; set; } = string.Empty;
    public string Cve { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public class SuspiciousPackage
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string PackageManager { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

public class LicenseIssue
{
    public string PackageName { get; set; } = string.Empty;
    public string License { get; set; } = string.Empty;
    public string Issue { get; set; } = string.Empty;
}

public class CiCdCompromiseResult
{
    public string BuildLogPath { get; set; } = string.Empty;
    public List<string> SuspiciousCommands { get; set; } = new();
    public List<string> UnauthorizedNetworkAccess { get; set; } = new();
    public List<string> SecretExfiltration { get; set; } = new();
    public bool BuildToolTampering { get; set; }
    public bool IsCompromised { get; set; }
    public DateTime AnalysisTime { get; set; }
}

public class SbomEntry
{
    public string ComponentName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Hash { get; set; } = string.Empty;
}

public class MaliciousPackagePattern
{
    public string Pattern { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}

public class NpmPackageJson
{
    public Dictionary<string, string>? Dependencies { get; set; }
    public Dictionary<string, string>? DevDependencies { get; set; }
}

#endregion
