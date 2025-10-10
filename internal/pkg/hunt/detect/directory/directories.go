package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	"strings"
)

var appData = os.Getenv("APPDATA")

func Detect() []string {
	var suspiciousDirectories []string
	seen := make(map[string]bool) // Prevent duplicates

	fmt.Printf("[*] Enumerating Suspicious Directories \n")
	// Check for common directories
	for _, dir := range common.CommonDirectories {
		dir = replaceAppData(dir)

		// Check if this is a prefix pattern (ends with incomplete path such as Screen Connect "C:\Program Files (x86)\ScreenConnect Client (")
		if isPrefix(dir) {
			// Find all directories matching this prefix
			matches := findPrefixMatches(dir)
			for _, match := range matches {
				if !seen[match] {
					fmt.Printf("   [?] Found %s\n", match)
					suspiciousDirectories = append(suspiciousDirectories, match)
					seen[match] = true
				}
			}
		} else {
			// Exact match
			if _, err := os.Stat(dir); err == nil {
				if !seen[dir] {
					fmt.Printf("   [?] Found %s\n", dir)
					suspiciousDirectories = append(suspiciousDirectories, dir)
					seen[dir] = true
				}
			}
		}
	}
	fmt.Printf("[+] Found %d Suspicious Directories\n", len(suspiciousDirectories))

	return suspiciousDirectories
}

// replaceAppData replaces {{APPDATA}} with the actual APPDATA path
func replaceAppData(path string) string {
	if strings.Contains(path, "{{APPDATA}}") {
		p := strings.Replace(path, "{{APPDATA}}", "", -1)
		return filepath.Join(appData, p)
	}
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
