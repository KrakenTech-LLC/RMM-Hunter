package eliminate

import (
	. "rmm-hunter/internal/suspicious"

	scurvy "github.com/Kraken-OffSec/Scurvy"
)

// EliminateProcess kills a process and removes its binary from the system
func EliminateProcess(p Process) error {
	err, proc := scurvy.FindProcessByPID(p.PID)
	if err != nil {
		return err
	}
	return proc.Kill()
}
