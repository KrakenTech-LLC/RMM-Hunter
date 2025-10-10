package writer

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"rmm-hunter/internal/pkg"
	"rmm-hunter/internal/pkg/writer/disposition"
	"rmm-hunter/internal/suspicious"
	"strings"
	"time"
)

type HTMLReportData struct {
	ReportName  string
	GeneratedAt string
	RiskRating  *disposition.Disposition
	Findings    interface{}
}

// WriteHTMLReport generates an HTML report from Hunter findings
func WriteHTMLReport(sus *suspicious.Suspicious, opts *pkg.RunOptions) error {
	if opts == nil {
		opts = &pkg.RunOptions{Name: "rmm-hunter-report"}
	}

	if opts.Name == "" {
		opts.Name = "rmm-hunter-report"
	}

	if sus == nil {
		return fmt.Errorf("suspicious instance is nil")
	}

	// Calculate risk disposition
	riskRating := disposition.CalculateDisposition(sus)

	// Prepare template data
	data := HTMLReportData{
		ReportName:  opts.Name,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		RiskRating:  riskRating,
		Findings:    sus,
	}

	// Parse template
	tmpl, err := template.New("report").Funcs(templateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	// Ensure output directory exists
	filename := fmt.Sprintf("%s.html", opts.Name)
	if err := ensureDir(filepath.Dir(filename)); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	fmt.Printf("[+] HTML report written to: %s\n", filename)
	return nil
}

// templateFuncs provides helper functions for the HTML template
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"riskColor": func(rating string) string {
			switch strings.ToLower(rating) {
			case "low":
				return "#28a745"
			case "medium":
				return "#ffc107"
			case "high":
				return "#dc3545"
			default:
				return "#6c757d"
			}
		},
		"len": func(v interface{}) int {
			if v == nil {
				return 0
			}
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			case []*suspicious.Service:
				return len(val)
			case []suspicious.Process:
				return len(val)
			case []suspicious.NetworkConnection:
				return len(val)
			case []*suspicious.ScheduledTask:
				return len(val)
			case []suspicious.AutoRun:
				return len(val)
			default:
				return 0
			}
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
	}
}
