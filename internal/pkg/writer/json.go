package writer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"rmm-hunter/internal/pkg"
	"rmm-hunter/internal/pkg/writer/disposition"
	"rmm-hunter/internal/suspicious"
	"time"
)

type JSONReport struct {
	ReportName  string                   `json:"reportName"`
	GeneratedAt string                   `json:"generatedAt"`
	RiskRating  *disposition.Disposition `json:"riskRating"`
	Findings    interface{}              `json:"findings"`
}

// WriteJSONReport generates a JSON report from Hunter findings
func WriteJSONReport(sus *suspicious.Suspicious, opts *pkg.RunOptions) error {
	if sus == nil {
		return fmt.Errorf("suspicious instance is nil")
	}

	if opts == nil {
		opts = &pkg.RunOptions{Name: "rmm-hunter-report"}
	}

	if opts.Name == "" {
		opts.Name = "rmm-hunter-report"
	}

	// Calculate risk disposition
	riskRating := disposition.CalculateDisposition(sus)

	// Create report structure
	report := JSONReport{
		ReportName:  opts.Name,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		RiskRating:  riskRating,
		Findings:    safeFindings(sus),
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Ensure output directory exists
	filename := fmt.Sprintf("%s.json", opts.Name)
	if err := ensureDir(filepath.Dir(filename)); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	fmt.Printf("[+] JSON report written to: %s\n", filename)
	return nil
}

// safeFindings ensures all findings are safe for JSON serialization
func safeFindings(sus interface{}) interface{} {
	if sus == nil {
		return map[string]interface{}{}
	}
	return sus
}

// ensureDir creates directory if it doesn't exist
func ensureDir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}
