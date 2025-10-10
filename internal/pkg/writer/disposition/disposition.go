package disposition

import (
	"fmt"
	"rmm-hunter/internal/suspicious"
	"strings"
)

type Disposition struct {
	Score   float64 `json:"score"`
	Rating  string  `json:"rating"`
	Summary string  `json:"summary"`
}

// CalculateDisposition analyzes the Hunter's findings and returns a risk assessment
func CalculateDisposition(sus *suspicious.Suspicious) *Disposition {
	if sus == nil {
		return &Disposition{
			Score:   0.0,
			Rating:  "Low",
			Summary: "No suspicious activity detected",
		}
	}

	var score float64
	var findings []string

	// Score based on different categories
	if len(sus.Processes) > 0 {
		score += float64(len(sus.Processes)) * 1.5
		findings = append(findings, fmt.Sprintf("%d suspicious processes", len(sus.Processes)))
	}

	if len(sus.Services) > 0 {
		score += float64(len(sus.Services)) * 2.0
		findings = append(findings, fmt.Sprintf("%d suspicious services", len(sus.Services)))
	}

	if len(sus.OutboundConnections) > 0 {
		score += float64(len(sus.OutboundConnections)) * 1.8
		findings = append(findings, fmt.Sprintf("%d suspicious outbound connections", len(sus.OutboundConnections)))
	}

	if len(sus.ScheduledTasks) > 0 {
		score += float64(len(sus.ScheduledTasks)) * 1.2
		findings = append(findings, fmt.Sprintf("%d suspicious scheduled tasks", len(sus.ScheduledTasks)))
	}

	if len(sus.AutoRuns) > 0 {
		score += float64(len(sus.AutoRuns)) * 1.3
		findings = append(findings, fmt.Sprintf("%d suspicious autoruns", len(sus.AutoRuns)))
	}

	if len(sus.Binaries) > 0 {
		score += float64(len(sus.Binaries)) * 0.8
		findings = append(findings, fmt.Sprintf("%d suspicious binaries", len(sus.Binaries)))
	}

	if len(sus.Directories) > 0 {
		score += float64(len(sus.Directories)) * 0.5
		findings = append(findings, fmt.Sprintf("%d suspicious directories", len(sus.Directories)))
	}

	// Normalize score to 0-10 scale
	if score > 10 {
		score = 10.0
	}

	// Determine rating
	var rating string
	switch {
	case score <= 3.0:
		rating = "Low"
	case score <= 6.0:
		rating = "Medium"
	default:
		rating = "High"
	}

	// Generate summary
	var summary string
	if len(findings) == 0 {
		summary = "No suspicious activity detected"
	} else {
		summary = fmt.Sprintf("Detected: %s", strings.Join(findings, ", "))
	}

	return &Disposition{
		Score:   score,
		Rating:  rating,
		Summary: summary,
	}
}
