package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"
)

var appData = os.Getenv("APPDATA")
var userProfile = os.Getenv("USERPROFILE")

func Detect() []Directory {
	var suspiciousDirectories []Directory
	seen := make(map[string]bool) // Prevent duplicates

	fmt.Printf("[*] Enumerating Suspicious Directories \n")

	// For each known RMM directory, check in all base paths
	for _, rmmDir := range common.KnownRMMDirectories {
		for _, basePath := range common.SearchBasePaths {
			// Replace environment variables
			basePath = replaceEnvVars(basePath)

			// Construct full path
			fullPath := filepath.Join(basePath, rmmDir)

			// Check if this is a prefix pattern (ends with incomplete path like "ScreenConnect Client (")
			if isPrefix(rmmDir) {
				// Find all directories matching this prefix
				matches := findPrefixMatches(fullPath)
				for _, match := range matches {
					if !seen[match] {
						fmt.Printf("   [?] Found %s\n", match)
						suspiciousDirectories = append(suspiciousDirectories, Directory{Path: match})
						seen[match] = true
					}
				}
			} else {
				// Exact match
				if _, err := os.Stat(fullPath); err == nil {
					if !seen[fullPath] {
						fmt.Printf("   [?] Found %s\n", fullPath)
						suspiciousDirectories = append(suspiciousDirectories, Directory{Path: fullPath})
						seen[fullPath] = true
					}
				}
			}
		}
	}

	fmt.Printf("[+] Found %d Suspicious Directories\n", len(suspiciousDirectories))

	return suspiciousDirectories
}

// replaceEnvVars replaces environment variable placeholders with actual paths
func replaceEnvVars(path string) string {
	path = strings.ReplaceAll(path, "{{APPDATA}}", appData)
	path = strings.ReplaceAll(path, "{{USERPROFILE}}", userProfile)
	return path
}

// isPrefix checks if a path is a prefix pattern (incomplete path for matching)
func isPrefix(path string) bool {
	// If path ends with "(" or other incomplete patterns, it's a prefix
	return strings.HasSuffix(path, "(") || strings.HasSuffix(path, "\\")
}

// findPrefixMatches finds all directories that start with the given prefix
func findPrefixMatches(prefix string) []string {
	var matches []string

	// Get the parent directory to search in
	parentDir := filepath.Dir(prefix)

	// Check if parent directory exists
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		return matches
	}

	// Read all entries in the parent directory
	entries, err := os.ReadDir(parentDir)
	if err != nil {
		return matches
	}

	// Get the base name prefix
	basePrefix := filepath.Base(prefix)

	// Check each entry
	for _, entry := range entries {
		if entry.IsDir() {
			// Check if this directory name starts with our prefix
			if strings.HasPrefix(entry.Name(), basePrefix) {
				fullPath := filepath.Join(parentDir, entry.Name())
				matches = append(matches, fullPath)
			}
		}
	}

	return matches
}
