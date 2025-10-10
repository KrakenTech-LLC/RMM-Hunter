package hunter

import (
	"fmt"
	"rmm-hunter/internal/pkg"
	"rmm-hunter/internal/pkg/hunt/detect/autorun"
	"rmm-hunter/internal/pkg/hunt/detect/binaries"
	"rmm-hunter/internal/pkg/hunt/detect/connections"
	"rmm-hunter/internal/pkg/hunt/detect/directory"
	"rmm-hunter/internal/pkg/hunt/detect/processes"
	"rmm-hunter/internal/pkg/hunt/detect/scheduledTasks"
	"rmm-hunter/internal/pkg/hunt/detect/services"
	"rmm-hunter/internal/pkg/writer"
	. "rmm-hunter/internal/suspicious"
)

type Hunter struct {
	Options pkg.RunOptions
	Sus     *Suspicious
}

func Start(options pkg.RunOptions) {
	hunter := Hunter{
		Options: options,
		Sus:     &Suspicious{},
	}
	hunter.run()
}

func (h *Hunter) run() {
	// Find suspicious suspiciousProcesses
	suspiciousProcesses := processes.Detect()
	h.Sus.Processes = suspiciousProcesses

	// Find suspicious suspiciousServices
	suspiciousServices := services.Detect()
	h.Sus.Services = suspiciousServices

	// Find suspicious autoruns
	autoruns := autorun.Detect()
	h.Sus.AutoRuns = autoruns

	// Find suspicious outbound outboundConnections
	outboundConnections := connections.DetectOutboundConnections()
	h.Sus.OutboundConnections = outboundConnections

	// Find suspicious scheduled tasks
	tasks := scheduledTasks.Detect()
	h.Sus.ScheduledTasks = tasks

	// Find suspicious suspiciousBinaries
	suspiciousBinaries := binaries.Detect()
	h.Sus.Binaries = suspiciousBinaries

	// Find suspicious directories
	directories := directory.Detect()
	h.Sus.Directories = directories

	// Write to json
	err := writer.WriteJSONReport(h.Sus, &h.Options)
	if err != nil {
		fmt.Printf("[-] Error writing JSON report: %s\n", err.Error())
	}

	// Write to html
	err = writer.WriteHTMLReport(h.Sus, &h.Options)
	if err != nil {
		fmt.Printf("[-] Error writing HTML report: %s\n", err.Error())
	}
}
