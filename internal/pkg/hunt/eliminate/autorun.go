package eliminate

import (
	"fmt"
	. "rmm-hunter/internal/suspicious"

	"github.com/Kraken-OffSec/Scurvy"
)

// EliminateAutoRun removes an autorun entry from the system
func EliminateAutoRun(ar AutoRun) error {
	all := scurvy.ListAutoruns()
	for _, a := range all {
		if a.MD5 == ar.MD5 {
			// Found it, delete it
			return scurvy.DeleteAutorun(a)
		}
	}
	return fmt.Errorf("%s | %s not found", ar.Location, ar.Entry)
}
