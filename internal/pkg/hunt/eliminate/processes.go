package eliminate

import (
	"fmt"

	. "rmm-hunter/internal/suspicious"

	scurvy "github.com/Kraken-OffSec/Scurvy"
)

// EliminateProcess kills a process and removes its binary from the system
func EliminateProcess(p Process) error {
	err, procs := scurvy.ListProcesses()
	if err != nil {
		return err
	}

	for _, proc := range procs {
		if proc.Pid() == p.PID {
			return proc.Kill()
		}
	}

	return fmt.Errorf("process %d not found", p.PID)
}
