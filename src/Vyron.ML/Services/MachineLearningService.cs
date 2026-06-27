using Microsoft.Extensions.Logging;
using Microsoft.ML;
using Microsoft.ML.Data;
using Vyron.Core.Models;
using Vyron.ML.Models;

namespace Vyron.ML.Services;

/// <summary>
/// ML-based threat detection and model training
/// </summary>
public class MachineLearningService
{
    private readonly ILogger<MachineLearningService> _logger;
    private readonly MLContext _mlContext;
    private ITransformer? _model;
    private readonly string _modelPath;
    private readonly string _trainingDataPath;

    public MachineLearningService(ILogger<MachineLearningService> logger)
    {
        _logger = logger;
        _mlContext = new MLContext(seed: 42);
        
        var basePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Vyron", "Models");
        
        _modelPath = Path.Combine(basePath, "threat_detection.zip");
        _trainingDataPath = Path.Combine(basePath, "training_data.csv");
        
        Directory.CreateDirectory(basePath);
    }

    public async Task InitializeAsync()
    {
        _logger.LogInformation("Initializing ML service...");

        try
        {
            if (File.Exists(_modelPath))
            {
                _model = _mlContext.Model.Load(_modelPath, out var modelSchema);
                _logger.LogInformation("Loaded existing ML model from: {Path}", _modelPath);
            }
            else
            {
                _logger.LogWarning("No trained model found. ML detection will be unavailable until training.");
                
                // Create initial training data if it doesn't exist
                if (!File.Exists(_trainingDataPath))
                {
                    await CreateInitialTrainingDataAsync();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize ML service");
        }
    }

    public async Task<ThreatPrediction?> PredictAsync(ProcessEvent processEvent)
    {
        if (_model == null)
        {
            _logger.LogDebug("ML model not loaded - prediction unavailable");
            return null;
        }

        try
        {
            var input = ConvertToTrainingData(processEvent, false);
            var predictionEngine = _mlContext.Model.CreatePredictionEngine<ThreatTrainingData, ThreatPrediction>(_model);
            var prediction = predictionEngine.Predict(input);

            _logger.LogDebug("ML Prediction for {Process}: IsMalware={IsMalware}, Probability={Prob:F2}",
                processEvent.ProcessName, prediction.IsMalware, prediction.Probability);

            return prediction;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error making ML prediction");
            return null;
        }
    }

    public async Task TrainModelAsync(IEnumerable<ThreatEvent> labeledEvents)
    {
        try
        {
            _logger.LogInformation("Starting ML model training with {Count} events", labeledEvents.Count());

            // Convert threat events to training data
            var trainingData = new List<ThreatTrainingData>();
            
            foreach (var evt in labeledEvents)
            {
                if (evt.IsConfirmedThreat.HasValue)
                {
                    var data = ConvertThreatEventToTrainingData(evt);
                    trainingData.Add(data);
                }
            }

            if (trainingData.Count < 100)
            {
                _logger.LogWarning("Insufficient training data ({Count} samples). Minimum 100 required.", 
                    trainingData.Count);
                return;
            }

            // Load data into IDataView
            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

            // Split data for training and testing
            var split = _mlContext.Data.TrainTestSplit(dataView, testFraction: 0.2);

            // Define training pipeline
            var pipeline = _mlContext.Transforms.Text.FeaturizeText("ProcessNameFeatures", nameof(ThreatTrainingData.ProcessName))
                .Append(_mlContext.Transforms.Text.FeaturizeText("CommandLineFeatures", nameof(ThreatTrainingData.CommandLine)))
                .Append(_mlContext.Transforms.Concatenate("Features",
                    "ProcessNameFeatures",
                    "CommandLineFeatures",
                    nameof(ThreatTrainingData.IntegrityLevel),
                    nameof(ThreatTrainingData.IsElevated),
                    nameof(ThreatTrainingData.ChildProcessCount),
                    nameof(ThreatTrainingData.HasSuspiciousParent),
                    nameof(ThreatTrainingData.InUnusualLocation),
                    nameof(ThreatTrainingData.CommandLineComplexity),
                    nameof(ThreatTrainingData.UsesObfuscation),
                    nameof(ThreatTrainingData.AccessesLsass),
                    nameof(ThreatTrainingData.ModifiesRegistry),
                    nameof(ThreatTrainingData.DeletesBackups),
                    nameof(ThreatTrainingData.FileSize),
                    nameof(ThreatTrainingData.IsSigned),
                    nameof(ThreatTrainingData.ReputationScore),
                    nameof(ThreatTrainingData.HasSignatureMatch)))
                .Append(_mlContext.BinaryClassification.Trainers.FastTree(
                    labelColumnName: nameof(ThreatTrainingData.IsMalware),
                    featureColumnName: "Features",
                    numberOfLeaves: 20,
                    numberOfTrees: 100,
                    minimumExampleCountPerLeaf: 10));

            // Train the model
            _logger.LogInformation("Training model...");
            _model = pipeline.Fit(split.TrainSet);

            // Evaluate the model
            var predictions = _model.Transform(split.TestSet);
            var metrics = _mlContext.BinaryClassification.Evaluate(predictions, 
                labelColumnName: nameof(ThreatTrainingData.IsMalware));

            _logger.LogInformation("Model training completed");
            _logger.LogInformation("Accuracy: {Acc:P2}", metrics.Accuracy);
            _logger.LogInformation("AUC: {Auc:F4}", metrics.AreaUnderRocCurve);
            _logger.LogInformation("F1 Score: {F1:F4}", metrics.F1Score);
            _logger.LogInformation("Precision: {Prec:P2}", metrics.PositivePrecision);
            _logger.LogInformation("Recall: {Rec:P2}", metrics.PositiveRecall);

            // Save the model
            _mlContext.Model.Save(_model, dataView.Schema, _modelPath);
            _logger.LogInformation("Model saved to: {Path}", _modelPath);

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error training ML model");
        }
    }

    private ThreatTrainingData ConvertToTrainingData(ProcessEvent processEvent, bool isMalware)
    {
        var commandLine = processEvent.CommandLine.ToLowerInvariant();
        
        return new ThreatTrainingData
        {
            ProcessName = processEvent.ProcessName,
            ExecutablePath = processEvent.ExecutablePath,
            CommandLine = processEvent.CommandLine,
            ParentProcessName = processEvent.ParentProcessName,
            IsElevated = processEvent.IsElevated,
            IntegrityLevel = (float)processEvent.IntegrityLevel,
            
            // Behavioral analysis
            HasSuspiciousParent = IsSuspiciousParent(processEvent),
            InUnusualLocation = IsUnusualLocation(processEvent.ExecutablePath),
            CommandLineComplexity = CalculateCommandLineComplexity(commandLine),
            UsesObfuscation = commandLine.Contains("-enc") || commandLine.Contains("base64"),
            AccessesLsass = commandLine.Contains("lsass"),
            ModifiesRegistry = commandLine.Contains("reg ") && commandLine.Contains("add"),
            DeletesBackups = commandLine.Contains("vssadmin delete") || commandLine.Contains("wbadmin delete"),
            
            IsMalware = isMalware
        };
    }

    private ThreatTrainingData ConvertThreatEventToTrainingData(ThreatEvent threat)
    {
        var commandLine = threat.CommandLine.ToLowerInvariant();
        
        return new ThreatTrainingData
        {
            ProcessName = threat.ProcessName,
            ExecutablePath = threat.FilePath,
            CommandLine = threat.CommandLine,
            ParentProcessName = threat.ParentProcessName,
            
            HasSuspiciousParent = IsSuspiciousParentName(threat.ParentProcessName, threat.ProcessName),
            InUnusualLocation = IsUnusualLocation(threat.FilePath),
            CommandLineComplexity = CalculateCommandLineComplexity(commandLine),
            UsesObfuscation = commandLine.Contains("-enc") || commandLine.Contains("base64"),
            AccessesLsass = commandLine.Contains("lsass"),
            ModifiesRegistry = commandLine.Contains("reg ") && commandLine.Contains("add"),
            DeletesBackups = commandLine.Contains("vssadmin delete") || commandLine.Contains("wbadmin delete"),
            HasSignatureMatch = threat.DetectionMethod == DetectionMethod.Signature,
            ReputationScore = (float)(1.0 - threat.ConfidenceScore),
            
            IsMalware = threat.IsConfirmedThreat ?? (threat.Severity >= ThreatSeverity.High)
        };
    }

    private bool IsSuspiciousParent(ProcessEvent processEvent)
    {
        return IsSuspiciousParentName(processEvent.ParentProcessName, processEvent.ProcessName);
    }

    private bool IsSuspiciousParentName(string parent, string child)
    {
        var parentLower = parent.ToLowerInvariant();
        var childLower = child.ToLowerInvariant();
        
        // Office spawning scripts
        if ((parentLower.Contains("word") || parentLower.Contains("excel")) &&
            (childLower.Contains("powershell") || childLower.Contains("cmd")))
        {
            return true;
        }
        
        return false;
    }

    private bool IsUnusualLocation(string path)
    {
        if (string.IsNullOrEmpty(path))
            return false;
            
        var pathLower = path.ToLowerInvariant();
        return pathLower.Contains("\\temp") || 
               pathLower.Contains("\\appdata\\local") ||
               pathLower.Contains("\\programdata");
    }

    private float CalculateCommandLineComplexity(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
            return 0f;
            
        float complexity = 0f;
        
        // Length-based complexity
        complexity += Math.Min(commandLine.Length / 1000f, 0.3f);
        
        // Special character density
        var specialChars = commandLine.Count(c => "!@#$%^&*(){}[]|\\;:'\",<>?".Contains(c));
        complexity += Math.Min(specialChars / 50f, 0.3f);
        
        // Encoded content
        if (commandLine.Contains("-enc") || commandLine.Contains("base64"))
            complexity += 0.4f;
            
        return Math.Min(complexity, 1f);
    }

    private async Task CreateInitialTrainingDataAsync()
    {
        _logger.LogInformation("Creating initial training data set");

        // Create a minimal training dataset with known good/bad patterns
        var initialData = @"ProcessName,ExecutablePath,CommandLine,ParentProcessName,IsElevated,IntegrityLevel,ChildProcessCount,HasSuspiciousParent,InUnusualLocation,CommandLineComplexity,UsesObfuscation,AccessesLsass,ModifiesRegistry,DeletesBackups,FileSize,IsSigned,ReputationScore,HasSignatureMatch,MakesNetworkConnections,NetworkConnectionCount,IsMalware
notepad.exe,C:\Windows\System32\notepad.exe,notepad.exe,explorer.exe,False,2,0,False,False,0,False,False,False,False,100000,True,1.0,False,False,0,False
explorer.exe,C:\Windows\explorer.exe,C:\Windows\explorer.exe,userinit.exe,False,2,5,False,False,0,False,False,False,False,500000,True,1.0,False,False,0,False
powershell.exe,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,powershell.exe -nop -w hidden -enc abc123,winword.exe,False,2,0,True,False,0.8,True,False,False,False,300000,True,0.5,False,False,0,True
cmd.exe,C:\Users\Public\cmd.exe,vssadmin delete shadows /all,explorer.exe,True,3,0,False,True,0.5,False,False,False,True,50000,False,0.2,False,False,0,True
mimikatz.exe,C:\Temp\mimikatz.exe,mimikatz.exe sekurlsa::logonpasswords,cmd.exe,True,3,0,True,True,0.4,False,True,False,False,150000,False,0.1,True,False,0,True
";

        await File.WriteAllTextAsync(_trainingDataPath, initialData);
        _logger.LogInformation("Initial training data created at: {Path}", _trainingDataPath);
    }
}
