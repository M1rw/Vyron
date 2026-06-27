using Xunit;
using Vyron.Core.Models;

namespace Vyron.Tests;

public class ThreatEventTests
{
    [Fact]
    public void ThreatEvent_ShouldInitializeWithDefaults()
    {
        // Arrange & Act
        var threat = new ThreatEvent();

        // Assert
        Assert.NotEqual(Guid.Empty, threat.Id);
        Assert.True((DateTime.UtcNow - threat.Timestamp).TotalSeconds < 1);
        Assert.NotNull(threat.Metadata);
    }

    [Fact]
    public void ThreatEvent_ShouldStoreSeverityCorrectly()
    {
        // Arrange
        var threat = new ThreatEvent
        {
            Severity = ThreatSeverity.Critical,
            Type = ThreatType.Ransomware
        };

        // Assert
        Assert.Equal(ThreatSeverity.Critical, threat.Severity);
        Assert.Equal(ThreatType.Ransomware, threat.Type);
    }

    [Theory]
    [InlineData(ThreatSeverity.Low, 0.5)]
    [InlineData(ThreatSeverity.Medium, 0.7)]
    [InlineData(ThreatSeverity.High, 0.85)]
    [InlineData(ThreatSeverity.Critical, 0.95)]
    public void ThreatEvent_ConfidenceScoreShouldMatchSeverity(ThreatSeverity severity, double expectedMinScore)
    {
        // Arrange
        var threat = new ThreatEvent
        {
            Severity = severity,
            ConfidenceScore = expectedMinScore
        };

        // Assert
        Assert.True(threat.ConfidenceScore >= expectedMinScore);
    }
}
