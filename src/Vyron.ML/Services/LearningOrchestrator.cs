using Microsoft.Extensions.Logging;
using System.Text.Json;
using Vyron.Core.Models;

namespace Vyron.ML.Services;

/// <summary>
/// Manages feedback loop for continuous learning
/// </summary>
public class LearningOrchestrator
{
    private readonly ILogger<LearningOrchestrator> _logger;
    private readonly MachineLearningService _mlService;
    private readonly string _feedbackPath;

    public LearningOrchestrator(
        ILogger<LearningOrchestrator> logger,
        MachineLearningService mlService)
    {
        _logger = logger;
        _mlService = mlService;
        
        _feedbackPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Vyron", "Data", "feedback");
        
        Directory.CreateDirectory(_feedbackPath);
    }

    /// <summary>
    /// Record analyst feedback on a detection
    /// </summary>
    public async Task RecordFeedbackAsync(Guid threatId, bool isTruePositive, string? notes = null)
    {
        try
        {
            var feedback = new DetectionFeedback
            {
                ThreatId = threatId,
                IsTruePositive = isTruePositive,
                FeedbackDate = DateTime.UtcNow,
                Notes = notes ?? string.Empty
            };

            var fileName = $"{threatId}.json";
            var filePath = Path.Combine(_feedbackPath, fileName);

            var json = JsonSerializer.Serialize(feedback, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(filePath, json);

            _logger.LogInformation("Feedback recorded for threat {Id}: TruePositive={Value}", 
                threatId, isTruePositive);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record feedback for threat {Id}", threatId);
        }
    }

    /// <summary>
    /// Trigger model retraining based on accumulated feedback
    /// </summary>
    public async Task<bool> RetrainModelAsync(int minimumSamples = 100)
    {
        try
        {
            _logger.LogInformation("Initiating model retraining...");

            // Load all labeled threat events
            var labeledEvents = await LoadLabeledEventsAsync();

            if (labeledEvents.Count < minimumSamples)
            {
                _logger.LogWarning("Insufficient samples for retraining: {Count}/{Required}", 
                    labeledEvents.Count, minimumSamples);
                return false;
            }

            // Trigger ML service to retrain
            await _mlService.TrainModelAsync(labeledEvents);

            _logger.LogInformation("Model retraining completed successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrain model");
            return false;
        }
    }

    private async Task<List<ThreatEvent>> LoadLabeledEventsAsync()
    {
        var labeledEvents = new List<ThreatEvent>();

        try
        {
            var threatsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Vyron", "Data", "threats");

            if (!Directory.Exists(threatsPath))
                return labeledEvents;

            var threatFiles = Directory.GetFiles(threatsPath, "*.json");

            foreach (var file in threatFiles)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var threat = JsonSerializer.Deserialize<ThreatEvent>(json);
                    
                    if (threat != null)
                    {
                        // Check if there's feedback for this threat
                        var feedbackFile = Path.Combine(_feedbackPath, $"{threat.Id}.json");
                        if (File.Exists(feedbackFile))
                        {
                            var feedbackJson = await File.ReadAllTextAsync(feedbackFile);
                            var feedback = JsonSerializer.Deserialize<DetectionFeedback>(feedbackJson);
                            
                            if (feedback != null)
                            {
                                threat.IsConfirmedThreat = feedback.IsTruePositive;
                                threat.Notes = feedback.Notes;
                                labeledEvents.Add(threat);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to load threat file: {File}", file);
                }
            }

            _logger.LogInformation("Loaded {Count} labeled events for training", labeledEvents.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading labeled events");
        }

        return labeledEvents;
    }

    /// <summary>
    /// Calculate detection accuracy metrics
    /// </summary>
    public async Task<DetectionMetrics> CalculateMetricsAsync()
    {
        var metrics = new DetectionMetrics();

        try
        {
            var labeledEvents = await LoadLabeledEventsAsync();

            if (!labeledEvents.Any())
                return metrics;

            metrics.TotalDetections = labeledEvents.Count;
            metrics.TruePositives = labeledEvents.Count(e => e.IsConfirmedThreat == true);
            metrics.FalsePositives = labeledEvents.Count(e => e.IsConfirmedThreat == false);

            if (metrics.TotalDetections > 0)
            {
                metrics.Accuracy = (double)metrics.TruePositives / metrics.TotalDetections;
            }

            _logger.LogInformation("Detection Metrics - Total: {Total}, TP: {TP}, FP: {FP}, Accuracy: {Acc:P2}",
                metrics.TotalDetections, metrics.TruePositives, metrics.FalsePositives, metrics.Accuracy);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calculating metrics");
        }

        return metrics;
    }
}

public class DetectionFeedback
{
    public Guid ThreatId { get; set; }
    public bool IsTruePositive { get; set; }
    public DateTime FeedbackDate { get; set; }
    public string Notes { get; set; } = string.Empty;
}

public class DetectionMetrics
{
    public int TotalDetections { get; set; }
    public int TruePositives { get; set; }
    public int FalsePositives { get; set; }
    public double Accuracy { get; set; }
}
