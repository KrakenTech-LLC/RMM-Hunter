package processes

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"github.com/Kraken-OffSec/Scurvy/core/process"
)

// Whitelist for our own tool and legitimate system components
var whitelist = []string{
	"rmm-hunter",
}

func isWhitelisted(proc process.Process) bool {
	allText := strings.ToLower(strings.Join([]string{
		proc.Executable(), proc.Path(),
	}, "|"))
	for _, w := range whitelist {
		if strings.Contains(allText, w) {
			return true
		}
	}
	return false
}

func Detect() []Process {
	fmt.Printf("[*] Enumerating Processes \n")

	processes, err := process.Processes()
	if err != nil {
		fmt.Printf("[-] Error enumerating processes: %s\n", err.Error())
		return []Process{}
	}

	fmt.Printf("   [>] Dispositioning %d Processes\n", len(processes))

	return compareProcesses(processes)
}

func compareProcesses(processes []process.Process) []Process {
	var suspiciousProcesses []Process

	for _, proc := range processes {
		// Skip whitelisted processes (our own tool)
		if isWhitelisted(proc) {
			continue
		}

		procName := proc.Executable()
		procNameLower := strings.ToLower(procName)

		// Get full executable path if available
		var fullPath string
		if proc.Path() != "" {
			fullPath = proc.Path()
		}

		// Check against known RMMs
		isRMMMatch := false
		for _, rmm := range common.CommonRMMs {
			rmmLower := strings.ToLower(rmm)
			if strings.Contains(procNameLower, rmmLower) {
				isRMMMatch = true
				break
			}
		}

		// Check for suspicious path
		isPathSuspicious := false
		pathReason := ""
		if fullPath != "" {
			isPathSuspicious, pathReason = common.AnalyzeExecutablePath(fullPath)
		}

		if isRMMMatch || isPathSuspicious {
			args := ""
			if isPathSuspicious {
				args = fmt.Sprintf("[%s]", pathReason)
			}

			fmt.Printf("      [?] Found %s\n", procName)
			suspiciousProcesses = append(suspiciousProcesses, Process{
				Name: procName,
				PID:  proc.Pid(),
				PPID: proc.PPid(),
				Path: fullPath,
				Args: args,
			})
		}
	}

	fmt.Printf("[+] Found %d Suspicious Processes\n", len(suspiciousProcesses))
	return suspiciousProcesses
}
