package common

import (
	"fmt"
	"strings"
)

func AnalyzeExecutablePath(command string) (bool, string) {
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

	execPathLower := strings.ToLower(execPath)

	// Check for suspicious installation paths
	suspiciousPaths := []string{
		"\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
		"\\users\\public\\", "\\programdata\\",
		"\\windows\\temp\\", "\\%temp%\\",
	}

	for _, suspPath := range suspiciousPaths {
		if strings.Contains(execPathLower, suspPath) {
			// Check for trusted publishers/companies
			trustedPublishers := []string{
				"\\microsoft\\",
				"\\adobe\\",
				"\\google\\",
				"\\intel\\",
				"\\nvidia\\",
				"\\oracle\\",
				"\\citrix\\",
				"\\vmware\\",
			}

			isTrusted := false
			for _, publisher := range trustedPublishers {
				if strings.Contains(execPathLower, publisher) {
					isTrusted = true
					break
				}
			}

			if !isTrusted {
				return true, fmt.Sprintf("Suspicious installation path: %s", suspPath)
			}
		}
	}

	return false, ""
}
