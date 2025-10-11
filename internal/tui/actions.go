package tui

import (
	"fmt"
	"rmm-hunter/internal/suspicious"
)

// Elimination placeholders; replace with real implementations later
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

func eliminateBinary(path string) error {
	return nil
}

func eliminateConnection(conn suspicious.NetworkConnection) error {
	return nil
}

func eliminateDirectory(path string) error {
	return nil
}

func eliminateProcess(p suspicious.Process) error {
	return nil
}

func eliminateScheduledTask(t suspicious.ScheduledTask) error {
	return nil
}

func eliminateService(s suspicious.Service) error {
	return nil
}
