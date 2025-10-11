package tui

import (
	"fmt"
	"path/filepath"
	"rmm-hunter/internal/suspicious"
	"strings"
)

// WarnBlock is a non-fatal warning condition (rendered as a warning modal)
type WarnBlock struct{ Reason string }

func (w WarnBlock) Error() string { return w.Reason }

// normalize a Windows-like path for robust comparisons
func normPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "\"") // strip surrounding quotes if any
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.ToLower(p)
}

// extract the executable path from a command/BinaryPathName that may include quotes/args
func exeFromCommand(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return s
	}
	if strings.HasPrefix(s, "\"") {
		s = s[1:]
		if i := strings.Index(s, "\""); i >= 0 {
			return s[:i]
		}
		return s
	}
	// no quotes; split on space
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// CheckBinaryBlocked returns a WarnBlock if the path is in use by an active process or enabled+active service
func CheckBinaryBlocked(path string, data suspicious.Suspicious) error {
	np := normPath(path)
	// active process: listed in data.Processes
	for _, p := range data.Processes {
		if normPath(p.Path) == np {
			return WarnBlock{Reason: fmt.Sprintf("Binary in use by running process %s (PID %d). Eliminate the process first.", p.Name, p.PID)}
		}
	}
	// enabled+active service: service uses this binary AND a running process exists for it
	for _, s := range data.Services {
		sp := normPath(exeFromCommand(s.BinaryPathName))
		if sp == np && !strings.EqualFold(strings.TrimSpace(s.StartType), "disabled") {
			// Is it active? infer by checking matching running process
			for _, p := range data.Processes {
				if normPath(p.Path) == sp {
					return WarnBlock{Reason: fmt.Sprintf("Binary used by active and enabled service %s. Stop/delete the service first.", s.Name)}
				}
			}
		}
	}
	return nil
}

// CheckDirectoryBlocked returns a WarnBlock if any process or enabled+active service binary is inside the directory
func CheckDirectoryBlocked(dir string, data suspicious.Suspicious) error {
	dn := normPath(dir)
	if !strings.HasSuffix(dn, "/") {
		dn += "/"
	}
	inDir := func(p string) bool {
		pp := normPath(p)
		if pp == "" {
			return false
		}
		if strings.HasPrefix(pp, dn) {
			return true
		}
		// try with filepath.Rel for robustness
		rel, err := filepath.Rel(dn, pp)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
	}
	for _, p := range data.Processes {
		if inDir(p.Path) {
			return WarnBlock{Reason: fmt.Sprintf("Directory contains running process %s (PID %d). Eliminate the process first.", p.Name, p.PID)}
		}
	}
	for _, s := range data.Services {
		sp := exeFromCommand(s.BinaryPathName)
		if inDir(sp) && !strings.EqualFold(strings.TrimSpace(s.StartType), "disabled") {
			// infer active via running process
			for _, p := range data.Processes {
				if normPath(p.Path) == normPath(sp) {
					return WarnBlock{Reason: fmt.Sprintf("Directory contains active and enabled service binary for %s. Stop/delete the service first.", s.Name)}
				}
			}
		}
	}
	return nil
}

// Elimination placeholders; TODO: replace with internal/pkg/hunt/eliminate/*
var (
	EliminateAutoRun       = func(ar suspicious.AutoRun) error { return eliminateAutoRun(ar) }
	EliminateBinary        = func(path string) error { return eliminateBinary(path) }
	EliminateConnection    = func(conn suspicious.NetworkConnection) error { return eliminateConnection(conn) }
	EliminateDirectory     = func(path string) error { return eliminateDirectory(path) }
	EliminateProcess       = func(p suspicious.Process) error { return eliminateProcess(p) }
	EliminateScheduledTask = func(t suspicious.ScheduledTask) error { return eliminateScheduledTask(t) }
	EliminateService       = func(s suspicious.Service) error { return eliminateService(s) }
)

func eliminateAutoRun(ar suspicious.AutoRun) error {
	return fmt.Errorf("eliminate autorun not implemented")
}
func eliminateBinary(path string) error                           { return nil }
func eliminateConnection(conn suspicious.NetworkConnection) error { return nil }
func eliminateDirectory(path string) error                        { return nil }
func eliminateProcess(p suspicious.Process) error                 { return nil }
func eliminateScheduledTask(t suspicious.ScheduledTask) error     { return nil }
func eliminateService(s suspicious.Service) error                 { return nil }
