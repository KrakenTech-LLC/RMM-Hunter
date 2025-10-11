package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// writeTestReport creates a minimal JSON report envelope with empty findings
func writeTestReport(t *testing.T, dir, name string, withFindings bool) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var content string
	if withFindings {
		content = `{
			"reportName": "rmm-hunter-report",
			"generatedAt": "2025-01-01T00:00:00Z",
			"riskRating": {"score":0, "rating":"Low", "summary":""},
			"findings": {"processes":[],"services":[],"binaries":[],"autoRuns":[],"scheduledTasks":[],"outboundConnections":[],"directories":[]}
		}`
	} else {
		content = `{}`
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test report: %v", err)
	}
	return path
}

func TestAppFlow_SelectFile_SelectType_Back_Quit(t *testing.T) {
	// Run in a temp dir so file picker sees our .json
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	_ = writeTestReport(t, tmp, "test.json", true)

	p := tea.NewProgram(NewApp(), tea.WithoutRenderer())
	done := make(chan error, 1)
	go func() {
		_, err := p.Run()
		done <- err
	}()

	// Give init a moment to load files
	time.Sleep(100 * time.Millisecond)

	// Select file
	p.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(50 * time.Millisecond)

	// Choose type 1 (autoruns)
	p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	time.Sleep(50 * time.Millisecond)

	// Go back to type picker
	p.Send(tea.KeyMsg{Type: tea.KeyLeft})
	time.Sleep(50 * time.Millisecond)

	// Quit
	p.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("program error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("program did not exit in time")
	}
}

func TestApp_ErrorOnBadJSON(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	_ = writeTestReport(t, tmp, "bad.json", false)

	p := tea.NewProgram(NewApp(), tea.WithoutRenderer())
	done := make(chan error, 1)
	go func() {
		_, err := p.Run()
		done <- err
	}()

	time.Sleep(100 * time.Millisecond)
	// Select file -> should error
	p.Send(tea.KeyMsg{Type: tea.KeyEnter})
	// Any key quits on error screen
	time.Sleep(50 * time.Millisecond)
	p.Send(tea.KeyMsg{Type: tea.KeyEsc})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("program error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("program did not exit in time")
	}
}
