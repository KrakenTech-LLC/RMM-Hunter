package eliminate

import (
	. "rmm-hunter/internal/suspicious"

	scurvy "github.com/Kraken-OffSec/Scurvy"
)

// EliminateService stops and removes a service from the system
func EliminateService(s Service) error {
	return scurvy.RemoveService(s.Name)
}
