package hunter

import (
	"rmm-hunter/internal/pkg"
	"rmm-hunter/internal/pkg/hunt/detect/autorun"
	"rmm-hunter/internal/pkg/hunt/detect/binaries"
	"rmm-hunter/internal/pkg/hunt/detect/connections"
	"rmm-hunter/internal/pkg/hunt/detect/directory"
	"rmm-hunter/internal/pkg/hunt/detect/processes"
	"rmm-hunter/internal/pkg/hunt/detect/scheduledTasks"
	"rmm-hunter/internal/pkg/hunt/detect/services"
	. "rmm-hunter/internal/suspicious"
)

type Hunter struct {
	Options pkg.RunOptions
	Sus     Suspicious
}

func Start(options pkg.RunOptions) {
	hunter := Hunter{
		Options: options,
	}
	hunter.run()
}

func (h *Hunter) run() {
	// Find suspicious processes
	processes := processes.Detect()
	h.Sus.Processes = processes

	// Find suspicious services
	services := services.Detect()
	h.Sus.Services = services

	// Find suspicious autoruns
	autoruns := autorun.Detect()
	h.Sus.AutoRuns = autoruns

	// Find suspicious outbound connections
	connections := connections.DetectOutboundConnections()
	h.Sus.OutboundConnections = connections

	// Find suspicious scheduled tasks
	tasks := scheduledTasks.Detect()
	h.Sus.ScheduledTasks = tasks

	// Find suspicious binaries
	binaries := binaries.Detect()
	h.Sus.Binaries = binaries

	// Find suspicious directories
	directories := directory.Detect()
	h.Sus.Directories = directories
}
