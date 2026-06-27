using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Vyron.Advanced.UEBA;

/// <summary>
/// Advanced User and Entity Behavior Analytics (UEBA)
/// Implements machine learning-based anomaly detection for:
/// - Keystroke dynamics
/// - Mouse movement biometrics
/// - Time-based anomalies
/// - Peer group analysis
/// - Impossible travel detection
/// - Data exfiltration patterns
/// - Insider threat detection
/// </summary>
public class UebaEngine
{
    private readonly ILogger<UebaEngine> _logger;
    private readonly Dictionary<string, UserProfile> _userProfiles = new();
    private readonly Dictionary<string, EntityProfile> _entityProfiles = new();

    public UebaEngine(ILogger<UebaEngine> logger)
    {
        _logger = logger;
    }

    public async Task<UebaAnalysisResult> AnalyzeUserBehaviorAsync(UserBehaviorContext context)
    {
        var result = new UebaAnalysisResult
        {
            AnalysisTime = DateTime.UtcNow,
            UserName = context.UserName
        };

        try
        {
            var startTime = DateTime.UtcNow;

            // Get or create user profile
            var profile = await GetOrCreateUserProfileAsync(context.UserName);

            // 1. Keystroke dynamics analysis
            result.KeystrokeDynamicsAnalysis = await AnalyzeKeystrokeDynamicsAsync(context, profile);

            // 2. Mouse movement biometrics
            result.MouseBiometricsAnalysis = await AnalyzeMouseBiometricsAsync(context, profile);

            // 3. Time-based behavior analysis
            result.TimeBasedAnalysis = await AnalyzeTimeBasedBehaviorAsync(context, profile);

            // 4. Peer group analysis
            result.PeerGroupAnalysis = await AnalyzePeerGroupDeviationAsync(context, profile);

            // 5. Impossible travel detection
            result.ImpossibleTravelAnalysis = await DetectImpossibleTravelAsync(context, profile);

            // 6. Data exfiltration detection
            result.DataExfiltrationAnalysis = await DetectDataExfiltrationAsync(context, profile);

            // 7. Privilege escalation detection
            result.PrivilegeEscalationAnalysis = await DetectPrivilegeEscalationAsync(context, profile);

            // 8. Lateral movement detection
            result.LateralMovementAnalysis = await DetectLateralMovementAsync(context, profile);

            // Calculate overall anomaly score
            result.AnomalyScore = CalculateOverallAnomalyScore(result);
            result.RiskLevel = ClassifyRiskLevel(result.AnomalyScore);
            result.IsAnomalous = result.AnomalyScore > 0.7;

            // Update user profile with new behavior
            await UpdateUserProfileAsync(profile, context);

            var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;
            result.AnalysisTimeMs = duration;

            if (result.IsAnomalous)
            {
                _logger.LogCritical(
                    "UEBA anomaly detected: User={User}, Score={Score:F2}, Risk={Risk}, " +
                    "Keystroke={Ks:F2}, Mouse={Ms:F2}, Time={Tb:F2}, Peer={Pg:F2}, Travel={Tr}, Exfil={Ex}, PrivEsc={Pe}, Lateral={Lm}",
                    context.UserName, result.AnomalyScore, result.RiskLevel,
                    result.KeystrokeDynamicsAnalysis.AnomalyScore,
                    result.MouseBiometricsAnalysis.AnomalyScore,
                    result.TimeBasedAnalysis.AnomalyScore,
                    result.PeerGroupAnalysis.DeviationScore,
                    result.ImpossibleTravelAnalysis.IsImpossibleTravel,
                    result.DataExfiltrationAnalysis.IsExfiltrationDetected,
                    result.PrivilegeEscalationAnalysis.IsPrivilegeEscalation,
                    result.LateralMovementAnalysis.IsLateralMovement);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing user behavior");
        }

        return result;
    }

    private async Task<KeystrokeDynamicsResult> AnalyzeKeystrokeDynamicsAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new KeystrokeDynamicsResult();

        try
        {
            if (context.KeystrokeData == null || context.KeystrokeData.Count == 0)
            {
                result.AnomalyScore = 0.5; // Insufficient data
                return result;
            }

            // Extract keystroke features
            result.AverageTypingSpeed = CalculateAverageTypingSpeed(context.KeystrokeData);
            result.DwellTime = CalculateAverageDwellTime(context.KeystrokeData);
            result.FlightTime = CalculateAverageFlightTime(context.KeystrokeData);
            result.TypingRhythm = CalculateTypingRhythm(context.KeystrokeData);

            // Compare with baseline profile
            if (profile.KeystrokeBaseline != null)
            {
                var speedDeviation = Math.Abs(result.AverageTypingSpeed - profile.KeystrokeBaseline.AverageTypingSpeed) /
                                    profile.KeystrokeBaseline.AverageTypingSpeed;
                var dwellDeviation = Math.Abs(result.DwellTime - profile.KeystrokeBaseline.DwellTime) /
                                    profile.KeystrokeBaseline.DwellTime;
                var flightDeviation = Math.Abs(result.FlightTime - profile.KeystrokeBaseline.FlightTime) /
                                     profile.KeystrokeBaseline.FlightTime;

                result.AnomalyScore = (speedDeviation + dwellDeviation + flightDeviation) / 3.0;
                result.IsAnomaly = result.AnomalyScore > 0.3; // 30% deviation threshold

                if (result.IsAnomaly)
                {
                    _logger.LogWarning(
                        "Keystroke dynamics anomaly: User={User}, Speed deviation={Spd:F2}, Dwell deviation={Dwell:F2}, Flight deviation={Flight:F2}",
                        context.UserName, speedDeviation, dwellDeviation, flightDeviation);
                }
            }
            else
            {
                // First-time baseline establishment
                profile.KeystrokeBaseline = new KeystrokeBaseline
                {
                    AverageTypingSpeed = result.AverageTypingSpeed,
                    DwellTime = result.DwellTime,
                    FlightTime = result.FlightTime,
                    TypingRhythm = result.TypingRhythm
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing keystroke dynamics");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<MouseBiometricsResult> AnalyzeMouseBiometricsAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new MouseBiometricsResult();

        try
        {
            if (context.MouseData == null || context.MouseData.Count == 0)
            {
                result.AnomalyScore = 0.5; // Insufficient data
                return result;
            }

            // Extract mouse movement features
            result.AverageSpeed = CalculateMouseSpeed(context.MouseData);
            result.AverageAcceleration = CalculateMouseAcceleration(context.MouseData);
            result.MovementCurvature = CalculateMovementCurvature(context.MouseData);
            result.ClickRate = CalculateClickRate(context.MouseData);

            // Compare with baseline profile
            if (profile.MouseBaseline != null)
            {
                var speedDeviation = Math.Abs(result.AverageSpeed - profile.MouseBaseline.AverageSpeed) /
                                    profile.MouseBaseline.AverageSpeed;
                var accelDeviation = Math.Abs(result.AverageAcceleration - profile.MouseBaseline.AverageAcceleration) /
                                    profile.MouseBaseline.AverageAcceleration;
                var curvatureDeviation = Math.Abs(result.MovementCurvature - profile.MouseBaseline.MovementCurvature) /
                                        profile.MouseBaseline.MovementCurvature;

                result.AnomalyScore = (speedDeviation + accelDeviation + curvatureDeviation) / 3.0;
                result.IsAnomaly = result.AnomalyScore > 0.35;

                if (result.IsAnomaly)
                {
                    _logger.LogWarning(
                        "Mouse biometrics anomaly: User={User}, Speed deviation={Spd:F2}, Accel deviation={Acc:F2}",
                        context.UserName, speedDeviation, accelDeviation);
                }
            }
            else
            {
                // Establish baseline
                profile.MouseBaseline = new MouseBaseline
                {
                    AverageSpeed = result.AverageSpeed,
                    AverageAcceleration = result.AverageAcceleration,
                    MovementCurvature = result.MovementCurvature,
                    ClickRate = result.ClickRate
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing mouse biometrics");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<TimeBasedAnalysisResult> AnalyzeTimeBasedBehaviorAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new TimeBasedAnalysisResult();

        try
        {
            var currentTime = DateTime.UtcNow;
            var currentHour = currentTime.Hour;
            var currentDayOfWeek = currentTime.DayOfWeek;

            // Check if activity is within normal working hours
            result.IsNormalWorkingHours = currentHour >= 8 && currentHour <= 18;
            result.IsWeekend = currentDayOfWeek == DayOfWeek.Saturday || currentDayOfWeek == DayOfWeek.Sunday;

            // Compare with user's typical activity patterns
            if (profile.ActivityTimeline != null && profile.ActivityTimeline.Count > 0)
            {
                var typicalActivityAtThisHour = profile.ActivityTimeline
                    .Count(a => a.Hour == currentHour && a.DayOfWeek == currentDayOfWeek);

                var totalActivity = profile.ActivityTimeline.Count;
                var activityProbability = (double)typicalActivityAtThisHour / totalActivity;

                result.ActivityProbability = activityProbability;
                result.IsUnusualTime = activityProbability < 0.05; // Less than 5% of historical activity

                if (result.IsUnusualTime)
                {
                    result.AnomalyScore = 0.8;
                    result.IsAnomaly = true;
                    _logger.LogWarning(
                        "Time-based anomaly: User={User}, Hour={Hour}, Day={Day}, Probability={Prob:F2}%",
                        context.UserName, currentHour, currentDayOfWeek, activityProbability * 100);
                }
                else
                {
                    result.AnomalyScore = 1.0 - activityProbability;
                }
            }
            else
            {
                // Build activity timeline
                profile.ActivityTimeline.Add(new ActivityEntry
                {
                    Hour = currentHour,
                    DayOfWeek = currentDayOfWeek,
                    Timestamp = currentTime
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing time-based behavior");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<PeerGroupAnalysisResult> AnalyzePeerGroupDeviationAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new PeerGroupAnalysisResult();

        try
        {
            // Determine user's peer group (department, role, etc.)
            result.PeerGroup = profile.Department ?? "Unknown";

            // Get peer group statistics
            var peerProfiles = _userProfiles.Values
                .Where(p => p.Department == profile.Department && p.UserName != profile.UserName)
                .ToList();

            if (peerProfiles.Count == 0)
            {
                result.DeviationScore = 0.5; // No peers to compare
                return result;
            }

            // Compare data transfer volume
            var peerAverageDataTransfer = peerProfiles.Average(p => p.AverageDataTransferMb);
            var dataTransferDeviation = Math.Abs(context.DataTransferredMb - peerAverageDataTransfer) / peerAverageDataTransfer;
            result.DataTransferDeviation = dataTransferDeviation;

            // Compare application usage
            var userApps = context.ApplicationsUsed ?? new List<string>();
            var peerCommonApps = peerProfiles
                .SelectMany(p => p.CommonApplications)
                .GroupBy(app => app)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => g.Key)
                .ToList();

            var appOverlap = userApps.Intersect(peerCommonApps).Count();
            var appDeviationScore = 1.0 - ((double)appOverlap / Math.Max(userApps.Count, peerCommonApps.Count));
            result.ApplicationUsageDeviation = appDeviationScore;

            // Compare network access patterns
            var peerAverageConnections = peerProfiles.Average(p => p.AverageNetworkConnections);
            var connectionDeviation = Math.Abs(context.NetworkConnections - peerAverageConnections) / peerAverageConnections;
            result.NetworkAccessDeviation = connectionDeviation;

            // Calculate overall peer group deviation
            result.DeviationScore = (dataTransferDeviation + appDeviationScore + connectionDeviation) / 3.0;
            result.IsDeviant = result.DeviationScore > 0.5;

            if (result.IsDeviant)
            {
                _logger.LogWarning(
                    "Peer group deviation: User={User}, PeerGroup={Group}, Deviation={Dev:F2}",
                    context.UserName, result.PeerGroup, result.DeviationScore);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing peer group deviation");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<ImpossibleTravelResult> DetectImpossibleTravelAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new ImpossibleTravelResult();

        try
        {
            if (profile.LastLocation == null || context.CurrentLocation == null)
            {
                // Store first location
                profile.LastLocation = context.CurrentLocation;
                profile.LastLocationTime = DateTime.UtcNow;
                return result;
            }

            // Calculate distance between locations
            var distance = CalculateDistance(profile.LastLocation, context.CurrentLocation);
            result.DistanceKm = distance;

            // Calculate time elapsed
            var timeElapsed = (DateTime.UtcNow - profile.LastLocationTime).TotalHours;
            result.TimeElapsedHours = timeElapsed;

            // Calculate required speed
            var requiredSpeed = distance / timeElapsed; // km/h
            result.RequiredSpeedKmh = requiredSpeed;

            // Maximum realistic travel speed (including commercial flights)
            const double maxRealisticSpeed = 900; // km/h (commercial jet)

            result.IsImpossibleTravel = requiredSpeed > maxRealisticSpeed;

            if (result.IsImpossibleTravel)
            {
                _logger.LogCritical(
                    "Impossible travel detected: User={User}, From={From}, To={To}, Distance={Dist:F0}km, Time={Time:F1}h, Speed={Speed:F0}km/h",
                    context.UserName, profile.LastLocation.City, context.CurrentLocation.City,
                    distance, timeElapsed, requiredSpeed);
            }

            // Update last location
            profile.LastLocation = context.CurrentLocation;
            profile.LastLocationTime = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error detecting impossible travel");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<DataExfiltrationResult> DetectDataExfiltrationAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new DataExfiltrationResult();

        try
        {
            // Check for unusual data transfer volume
            var averageTransfer = profile.AverageDataTransferMb;
            var currentTransfer = context.DataTransferredMb;

            if (averageTransfer > 0)
            {
                var transferRatio = currentTransfer / averageTransfer;
                result.TransferVolumeRatio = transferRatio;
                result.IsUnusualVolume = transferRatio > 3.0; // 3x normal volume
            }

            // Check for unusual data transfer destinations
            var typicalDestinations = profile.TypicalNetworkDestinations ?? new List<string>();
            var currentDestinations = context.NetworkDestinations ?? new List<string>();
            var unusualDestinations = currentDestinations.Except(typicalDestinations).ToList();
            result.UnusualDestinations = unusualDestinations;
            result.HasUnusualDestinations = unusualDestinations.Count > 0;

            // Check for data transfer to external storage
            result.ExternalStorageAccess = context.ExternalStorageAccess;

            // Check for after-hours data transfer
            var currentHour = DateTime.UtcNow.Hour;
            result.IsAfterHours = currentHour < 6 || currentHour > 22;

            // Check for compressed/encrypted files
            result.CompressedFilesTransferred = context.CompressedFilesCount;
            result.EncryptedFilesTransferred = context.EncryptedFilesCount;
            result.HasSuspiciousFiles = result.CompressedFilesTransferred > 10 || result.EncryptedFilesTransferred > 5;

            // Overall exfiltration detection
            result.IsExfiltrationDetected = result.IsUnusualVolume ||
                                           (result.HasUnusualDestinations && result.IsAfterHours) ||
                                           (result.ExternalStorageAccess && result.HasSuspiciousFiles);

            if (result.IsExfiltrationDetected)
            {
                _logger.LogCritical(
                    "Data exfiltration detected: User={User}, Volume={Vol:F1}MB (ratio={Ratio:F1}x), " +
                    "Unusual destinations={Dest}, External storage={Ext}, After hours={Ah}, Suspicious files={Files}",
                    context.UserName, currentTransfer, result.TransferVolumeRatio,
                    unusualDestinations.Count, result.ExternalStorageAccess, result.IsAfterHours, result.HasSuspiciousFiles);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error detecting data exfiltration");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<PrivilegeEscalationResult> DetectPrivilegeEscalationAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new PrivilegeEscalationResult();

        try
        {
            // Check for privilege changes
            var currentPrivileges = context.CurrentPrivileges ?? new List<string>();
            var baselinePrivileges = profile.BaselinePrivileges ?? new List<string>();

            result.NewPrivileges = currentPrivileges.Except(baselinePrivileges).ToList();
            result.HasNewPrivileges = result.NewPrivileges.Count > 0;

            // Check for administrator group membership
            result.IsAdministrator = currentPrivileges.Contains("Administrators");
            result.WasNotAdministratorBefore = !baselinePrivileges.Contains("Administrators");

            // Check for sensitive privilege escalation
            var sensitivePrivileges = new[] { "SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege" };
            result.SensitivePrivilegesAdded = result.NewPrivileges.Intersect(sensitivePrivileges).ToList();
            result.HasSensitivePrivileges = result.SensitivePrivilegesAdded.Count > 0;

            // Overall privilege escalation detection
            result.IsPrivilegeEscalation = result.HasNewPrivileges &&
                                          (result.IsAdministrator && result.WasNotAdministratorBefore ||
                                           result.HasSensitivePrivileges);

            if (result.IsPrivilegeEscalation)
            {
                _logger.LogCritical(
                    "Privilege escalation detected: User={User}, New privileges={New}, Sensitive={Sens}, Admin={Admin}",
                    context.UserName, string.Join(", ", result.NewPrivileges),
                    string.Join(", ", result.SensitivePrivilegesAdded), result.IsAdministrator);
            }

            // Update baseline
            if (!result.IsPrivilegeEscalation)
            {
                profile.BaselinePrivileges = currentPrivileges;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error detecting privilege escalation");
        }

        await Task.CompletedTask;
        return result;
    }

    private async Task<LateralMovementResult> DetectLateralMovementAsync(UserBehaviorContext context, UserProfile profile)
    {
        var result = new LateralMovementResult();

        try
        {
            // Check for remote connections to other systems
            var remoteConnections = context.RemoteConnections ?? new List<string>();
            result.RemoteConnectionCount = remoteConnections.Count;

            // Check for typical remote tools (PsExec, WinRM, RDP, etc.)
            var lateralMovementTools = new[] { "psexec", "winrm", "wmic", "powershell", "sc.exe" };
            var toolsUsed = context.ProcessesExecuted?
                .Where(p => lateralMovementTools.Any(t => p.Contains(t, StringComparison.OrdinalIgnoreCase)))
                .ToList() ?? new List<string>();
            result.LateralMovementTools = toolsUsed;
            result.HasLateralMovementTools = toolsUsed.Count > 0;

            // Check for credential access attempts
            result.CredentialAccessAttempts = context.CredentialAccessAttempts;

            // Check for SMB/RPC connections
            result.SmbConnections = context.SmbConnections;
            result.RpcConnections = context.RpcConnections;

            // Overall lateral movement detection
            result.IsLateralMovement = (result.RemoteConnectionCount > 3 && result.HasLateralMovementTools) ||
                                      (result.CredentialAccessAttempts > 0 && result.RemoteConnectionCount > 0) ||
                                      (result.SmbConnections > 5 && result.RpcConnections > 5);

            if (result.IsLateralMovement)
            {
                _logger.LogCritical(
                    "Lateral movement detected: User={User}, Remote connections={Conn}, Tools={Tools}, Cred access={Cred}",
                    context.UserName, result.RemoteConnectionCount,
                    string.Join(", ", result.LateralMovementTools), result.CredentialAccessAttempts);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error detecting lateral movement");
        }

        await Task.CompletedTask;
        return result;
    }

    private double CalculateOverallAnomalyScore(UebaAnalysisResult result)
    {
        double score = 0.0;

        score += result.KeystrokeDynamicsAnalysis.AnomalyScore * 0.10;
        score += result.MouseBiometricsAnalysis.AnomalyScore * 0.10;
        score += result.TimeBasedAnalysis.AnomalyScore * 0.15;
        score += result.PeerGroupAnalysis.DeviationScore * 0.15;
        score += (result.ImpossibleTravelAnalysis.IsImpossibleTravel ? 1.0 : 0.0) * 0.20;
        score += (result.DataExfiltrationAnalysis.IsExfiltrationDetected ? 1.0 : 0.0) * 0.15;
        score += (result.PrivilegeEscalationAnalysis.IsPrivilegeEscalation ? 1.0 : 0.0) * 0.10;
        score += (result.LateralMovementAnalysis.IsLateralMovement ? 1.0 : 0.0) * 0.05;

        return Math.Min(score, 1.0);
    }

    private string ClassifyRiskLevel(double anomalyScore)
    {
        return anomalyScore switch
        {
            >= 0.9 => "Critical",
            >= 0.7 => "High",
            >= 0.5 => "Medium",
            >= 0.3 => "Low",
            _ => "Minimal"
        };
    }

    private async Task<UserProfile> GetOrCreateUserProfileAsync(string userName)
    {
        if (!_userProfiles.TryGetValue(userName, out var profile))
        {
            profile = new UserProfile
            {
                UserName = userName,
                CreatedAt = DateTime.UtcNow
            };
            _userProfiles[userName] = profile;
        }

        await Task.CompletedTask;
        return profile;
    }

    private async Task UpdateUserProfileAsync(UserProfile profile, UserBehaviorContext context)
    {
        // Update profile with new behavior data
        profile.LastActivity = DateTime.UtcNow;
        profile.TotalActivities++;

        if (context.DataTransferredMb > 0)
        {
            profile.AverageDataTransferMb = (profile.AverageDataTransferMb * (profile.TotalActivities - 1) + context.DataTransferredMb) / profile.TotalActivities;
        }

        await Task.CompletedTask;
    }

    // Feature extraction helpers
    private double CalculateAverageTypingSpeed(List<KeystrokeEvent> keystrokes)
    {
        if (keystrokes.Count < 2) return 0;
        var totalTime = (keystrokes.Last().Timestamp - keystrokes.First().Timestamp).TotalSeconds;
        return keystrokes.Count / totalTime; // keys per second
    }

    private double CalculateAverageDwellTime(List<KeystrokeEvent> keystrokes)
    {
        if (keystrokes.Count == 0) return 0;
        return keystrokes.Average(k => k.DwellTimeMs);
    }

    private double CalculateAverageFlightTime(List<KeystrokeEvent> keystrokes)
    {
        if (keystrokes.Count < 2) return 0;
        var flightTimes = new List<double>();
        for (int i = 0; i < keystrokes.Count - 1; i++)
        {
            flightTimes.Add((keystrokes[i + 1].Timestamp - keystrokes[i].Timestamp).TotalMilliseconds);
        }
        return flightTimes.Average();
    }

    private double CalculateTypingRhythm(List<KeystrokeEvent> keystrokes)
    {
        // Simplified rhythm calculation (standard deviation of flight times)
        if (keystrokes.Count < 3) return 0;
        var flightTimes = new List<double>();
        for (int i = 0; i < keystrokes.Count - 1; i++)
        {
            flightTimes.Add((keystrokes[i + 1].Timestamp - keystrokes[i].Timestamp).TotalMilliseconds);
        }
        var mean = flightTimes.Average();
        var variance = flightTimes.Sum(ft => Math.Pow(ft - mean, 2)) / flightTimes.Count;
        return Math.Sqrt(variance);
    }

    private double CalculateMouseSpeed(List<MouseEvent> mouseEvents)
    {
        if (mouseEvents.Count < 2) return 0;
        double totalDistance = 0;
        for (int i = 0; i < mouseEvents.Count - 1; i++)
        {
            var dx = mouseEvents[i + 1].X - mouseEvents[i].X;
            var dy = mouseEvents[i + 1].Y - mouseEvents[i].Y;
            totalDistance += Math.Sqrt(dx * dx + dy * dy);
        }
        var totalTime = (mouseEvents.Last().Timestamp - mouseEvents.First().Timestamp).TotalSeconds;
        return totalDistance / totalTime; // pixels per second
    }

    private double CalculateMouseAcceleration(List<MouseEvent> mouseEvents)
    {
        if (mouseEvents.Count < 3) return 0;
        var velocities = new List<double>();
        for (int i = 0; i < mouseEvents.Count - 1; i++)
        {
            var dx = mouseEvents[i + 1].X - mouseEvents[i].X;
            var dy = mouseEvents[i + 1].Y - mouseEvents[i].Y;
            var dt = (mouseEvents[i + 1].Timestamp - mouseEvents[i].Timestamp).TotalSeconds;
            var velocity = Math.Sqrt(dx * dx + dy * dy) / dt;
            velocities.Add(velocity);
        }
        // Calculate acceleration as change in velocity
        double totalAccel = 0;
        for (int i = 0; i < velocities.Count - 1; i++)
        {
            totalAccel += Math.Abs(velocities[i + 1] - velocities[i]);
        }
        return totalAccel / velocities.Count;
    }

    private double CalculateMovementCurvature(List<MouseEvent> mouseEvents)
    {
        if (mouseEvents.Count < 3) return 0;
        double totalAngleChange = 0;
        for (int i = 1; i < mouseEvents.Count - 1; i++)
        {
            var v1x = mouseEvents[i].X - mouseEvents[i - 1].X;
            var v1y = mouseEvents[i].Y - mouseEvents[i - 1].Y;
            var v2x = mouseEvents[i + 1].X - mouseEvents[i].X;
            var v2y = mouseEvents[i + 1].Y - mouseEvents[i].Y;

            var angle1 = Math.Atan2(v1y, v1x);
            var angle2 = Math.Atan2(v2y, v2x);
            totalAngleChange += Math.Abs(angle2 - angle1);
        }
        return totalAngleChange / (mouseEvents.Count - 2);
    }

    private double CalculateClickRate(List<MouseEvent> mouseEvents)
    {
        var clicks = mouseEvents.Count(me => me.IsClick);
        var totalTime = (mouseEvents.Last().Timestamp - mouseEvents.First().Timestamp).TotalSeconds;
        return clicks / totalTime; // clicks per second
    }

    private double CalculateDistance(Location from, Location to)
    {
        // Haversine formula for distance between two coordinates
        const double earthRadiusKm = 6371;

        var dLat = ToRadians(to.Latitude - from.Latitude);
        var dLon = ToRadians(to.Longitude - from.Longitude);

        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                Math.Cos(ToRadians(from.Latitude)) * Math.Cos(ToRadians(to.Latitude)) *
                Math.Sin(dLon / 2) * Math.Sin(dLon / 2);

        var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));

        return earthRadiusKm * c;
    }

    private double ToRadians(double degrees)
    {
        return degrees * Math.PI / 180;
    }
}

#region Models

public class UserBehaviorContext
{
    public string UserName { get; set; } = string.Empty;
    public List<KeystrokeEvent>? KeystrokeData { get; set; }
    public List<MouseEvent>? MouseData { get; set; }
    public Location? CurrentLocation { get; set; }
    public double DataTransferredMb { get; set; }
    public List<string>? NetworkDestinations { get; set; }
    public bool ExternalStorageAccess { get; set; }
    public int CompressedFilesCount { get; set; }
    public int EncryptedFilesCount { get; set; }
    public List<string>? CurrentPrivileges { get; set; }
    public List<string>? ApplicationsUsed { get; set; }
    public int NetworkConnections { get; set; }
    public List<string>? RemoteConnections { get; set; }
    public List<string>? ProcessesExecuted { get; set; }
    public int CredentialAccessAttempts { get; set; }
    public int SmbConnections { get; set; }
    public int RpcConnections { get; set; }
}

public class UebaAnalysisResult
{
    public DateTime AnalysisTime { get; set; }
    public string UserName { get; set; } = string.Empty;
    public KeystrokeDynamicsResult KeystrokeDynamicsAnalysis { get; set; } = new();
    public MouseBiometricsResult MouseBiometricsAnalysis { get; set; } = new();
    public TimeBasedAnalysisResult TimeBasedAnalysis { get; set; } = new();
    public PeerGroupAnalysisResult PeerGroupAnalysis { get; set; } = new();
    public ImpossibleTravelResult ImpossibleTravelAnalysis { get; set; } = new();
    public DataExfiltrationResult DataExfiltrationAnalysis { get; set; } = new();
    public PrivilegeEscalationResult PrivilegeEscalationAnalysis { get; set; } = new();
    public LateralMovementResult LateralMovementAnalysis { get; set; } = new();
    public double AnomalyScore { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public bool IsAnomalous { get; set; }
    public double AnalysisTimeMs { get; set; }
}

public class KeystrokeDynamicsResult
{
    public double AverageTypingSpeed { get; set; }
    public double DwellTime { get; set; }
    public double FlightTime { get; set; }
    public double TypingRhythm { get; set; }
    public double AnomalyScore { get; set; }
    public bool IsAnomaly { get; set; }
}

public class MouseBiometricsResult
{
    public double AverageSpeed { get; set; }
    public double AverageAcceleration { get; set; }
    public double MovementCurvature { get; set; }
    public double ClickRate { get; set; }
    public double AnomalyScore { get; set; }
    public bool IsAnomaly { get; set; }
}

public class TimeBasedAnalysisResult
{
    public bool IsNormalWorkingHours { get; set; }
    public bool IsWeekend { get; set; }
    public double ActivityProbability { get; set; }
    public bool IsUnusualTime { get; set; }
    public double AnomalyScore { get; set; }
    public bool IsAnomaly { get; set; }
}

public class PeerGroupAnalysisResult
{
    public string PeerGroup { get; set; } = string.Empty;
    public double DataTransferDeviation { get; set; }
    public double ApplicationUsageDeviation { get; set; }
    public double NetworkAccessDeviation { get; set; }
    public double DeviationScore { get; set; }
    public bool IsDeviant { get; set; }
}

public class ImpossibleTravelResult
{
    public double DistanceKm { get; set; }
    public double TimeElapsedHours { get; set; }
    public double RequiredSpeedKmh { get; set; }
    public bool IsImpossibleTravel { get; set; }
}

public class DataExfiltrationResult
{
    public double TransferVolumeRatio { get; set; }
    public bool IsUnusualVolume { get; set; }
    public List<string> UnusualDestinations { get; set; } = new();
    public bool HasUnusualDestinations { get; set; }
    public bool ExternalStorageAccess { get; set; }
    public bool IsAfterHours { get; set; }
    public int CompressedFilesTransferred { get; set; }
    public int EncryptedFilesTransferred { get; set; }
    public bool HasSuspiciousFiles { get; set; }
    public bool IsExfiltrationDetected { get; set; }
}

public class PrivilegeEscalationResult
{
    public List<string> NewPrivileges { get; set; } = new();
    public bool HasNewPrivileges { get; set; }
    public bool IsAdministrator { get; set; }
    public bool WasNotAdministratorBefore { get; set; }
    public List<string> SensitivePrivilegesAdded { get; set; } = new();
    public bool HasSensitivePrivileges { get; set; }
    public bool IsPrivilegeEscalation { get; set; }
}

public class LateralMovementResult
{
    public int RemoteConnectionCount { get; set; }
    public List<string> LateralMovementTools { get; set; } = new();
    public bool HasLateralMovementTools { get; set; }
    public int CredentialAccessAttempts { get; set; }
    public int SmbConnections { get; set; }
    public int RpcConnections { get; set; }
    public bool IsLateralMovement { get; set; }
}

public class UserProfile
{
    public string UserName { get; set; } = string.Empty;
    public string? Department { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime LastActivity { get; set; }
    public int TotalActivities { get; set; }
    public KeystrokeBaseline? KeystrokeBaseline { get; set; }
    public MouseBaseline? MouseBaseline { get; set; }
    public List<ActivityEntry> ActivityTimeline { get; set; } = new();
    public double AverageDataTransferMb { get; set; }
    public List<string> CommonApplications { get; set; } = new();
    public int AverageNetworkConnections { get; set; }
    public Location? LastLocation { get; set; }
    public DateTime LastLocationTime { get; set; }
    public List<string>? TypicalNetworkDestinations { get; set; }
    public List<string>? BaselinePrivileges { get; set; }
}

public class EntityProfile
{
    public string EntityId { get; set; } = string.Empty;
    public string EntityType { get; set; } = string.Empty;
}

public class KeystrokeBaseline
{
    public double AverageTypingSpeed { get; set; }
    public double DwellTime { get; set; }
    public double FlightTime { get; set; }
    public double TypingRhythm { get; set; }
}

public class MouseBaseline
{
    public double AverageSpeed { get; set; }
    public double AverageAcceleration { get; set; }
    public double MovementCurvature { get; set; }
    public double ClickRate { get; set; }
}

public class ActivityEntry
{
    public int Hour { get; set; }
    public DayOfWeek DayOfWeek { get; set; }
    public DateTime Timestamp { get; set; }
}

public class KeystrokeEvent
{
    public DateTime Timestamp { get; set; }
    public char Key { get; set; }
    public double DwellTimeMs { get; set; }
}

public class MouseEvent
{
    public DateTime Timestamp { get; set; }
    public int X { get; set; }
    public int Y { get; set; }
    public bool IsClick { get; set; }
}

public class Location
{
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public string City { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
}

#endregion
