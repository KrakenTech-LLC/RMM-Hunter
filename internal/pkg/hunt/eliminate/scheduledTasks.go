package eliminate

import (
	. "rmm-hunter/internal/suspicious"

	scurvy "github.com/Kraken-OffSec/Scurvy"
)

func EliminateScheduledTask(t ScheduledTask) error {
	return scurvy.DeleteScheduledTask(t.Name)
}
