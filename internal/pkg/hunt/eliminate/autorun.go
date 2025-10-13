package eliminate

import (
	"fmt"
	. "rmm-hunter/internal/suspicious"

	"github.com/Kraken-OffSec/Scurvy"
)

// EliminateAutoRun removes an autorun entry from the system
func EliminateAutoRun(ar AutoRun) error {
	all := scurvy.ListAutoruns()

	// Try to find by MD5 first
	for _, a := range all {
		if a.MD5 == ar.MD5 && a.MD5 != "" {
			return scurvy.DeleteAutorun(a)
		}
	}

	// If not found by MD5, try to find by location (for registry entries)
	for _, a := range all {
		if a.Location == ar.Location && ar.Location != "" {
			return scurvy.DeleteAutorun(a)
		}
	}

	// Build a descriptive error message
	location := ar.Location
	if location == "" {
		location = "unknown location"
	}
	entry := ar.Entry
	if entry == "" {
		entry = ar.ImageName
	}
	if entry == "" {
		entry = "unknown entry"
	}

	return fmt.Errorf("autorun entry not found at %s (%s) - it may have already been removed", location, entry)
}
