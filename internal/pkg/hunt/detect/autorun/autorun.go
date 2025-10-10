package autorun

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func Detect() []AutoRun {
	var suspiciousAutoRuns []AutoRun

	fmt.Printf("[*] Enumerating AutoRun Applications\n")

	// Check common autorun registry locations
	autorunKeys := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,
		`SOFTWARE\Microsoft\Active Setup\Installed Components`,
	}

	// Check both HKLM and HKCU
	roots := []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER}
	rootNames := []string{"HKLM", "HKCU"}

	totalEntries := 0
	for i, root := range roots {
		for _, keyPath := range autorunKeys {
			entries := checkAutoRunKey(root, keyPath, rootNames[i])
			totalEntries += len(entries)
			suspiciousAutoRuns = append(suspiciousAutoRuns, entries...)
		}
	}

	fmt.Printf("   [>] Dispositioning %d AutoRun Entries\n", totalEntries)
	fmt.Printf("[+] Found %d Suspicious AutoRun Applications\n", len(suspiciousAutoRuns))

	return suspiciousAutoRuns
}

func checkAutoRunKey(root registry.Key, keyPath, rootName string) []AutoRun {
	var autoRuns []AutoRun

	key, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return autoRuns
	}
	defer key.Close()

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return autoRuns
	}

	for _, valueName := range valueNames {
		value, _, err := key.GetStringValue(valueName)
		if err != nil {
			continue
		}

		// Check if this autorun entry matches any known Suspicious patterns
		if isSuspiciousAutoRun(valueName, value) {
			// Analyze the executable path for additional suspicious indicators
			isPathSuspicious, pathReason := analyzeExecutablePath(value)
			description := extractDescription(value)
			if isPathSuspicious {
				description += fmt.Sprintf(" [%s]", pathReason)
			}

			fmt.Printf("   [?] Found %s\\%s: %s = %s\n", rootName, keyPath, valueName, value)
			autoRuns = append(autoRuns, AutoRun{
				Name:        valueName,
				Command:     value,
				Location:    fmt.Sprintf("%s\\%s", rootName, keyPath),
				Enabled:     true,
				Description: description,
			})
		}
	}

	return autoRuns
}

func isSuspiciousAutoRun(name, command string) bool {
	// Convert to lowercase for case-insensitive comparison
	nameLower := strings.ToLower(name)
	commandLower := strings.ToLower(command)

	// Check against known Suspicious names
	for _, rmm := range common.CommonRMMs {
		rmmLower := strings.ToLower(rmm)
		if strings.Contains(nameLower, rmmLower) || strings.Contains(commandLower, rmmLower) {
			return true
		}
	}

	// Check against common Suspicious executable patterns
	for _, imageEnd := range common.CommonImageEnds {
		imageEndLower := strings.ToLower(imageEnd)
		if strings.Contains(commandLower, imageEndLower) {
			return true
		}
	}

	// Additional suspicious patterns
	suspiciousPatterns := []string{
		"remote", "control", "assist", "support", "vnc", "rdp", "teamview",
		"anydesk", "logmein", "screenconnect", "splashtop", "ultravnc",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(nameLower, pattern) || strings.Contains(commandLower, pattern) {
			return true
		}
	}

	return false
}

func extractDescription(command string) string {
	// Extract just the executable name from the command
	parts := strings.Fields(command)
	if len(parts) > 0 {
		return parts[0]
	}
	return command
}

func analyzeExecutablePath(command string) (bool, string) {
	// Extract executable path from command
	var execPath string
	if strings.HasPrefix(command, "\"") {
		// Handle quoted paths
		endQuote := strings.Index(command[1:], "\"")
		if endQuote != -1 {
			execPath = command[1 : endQuote+1]
		}
	} else {
		// Handle unquoted paths
		parts := strings.Fields(command)
		if len(parts) > 0 {
			execPath = parts[0]
		}
	}

	// Check for suspicious installation paths
	suspiciousPaths := []string{
		"\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
		"\\users\\public\\", "\\programdata\\",
		"\\windows\\temp\\", "\\%temp%\\",
	}

	execPathLower := strings.ToLower(execPath)
	for _, suspPath := range suspiciousPaths {
		if strings.Contains(execPathLower, suspPath) {
			return true, fmt.Sprintf("Suspicious installation path: %s", suspPath)
		}
	}

	return false, ""
}
