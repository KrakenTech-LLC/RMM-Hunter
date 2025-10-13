package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"
	"sync"
)

var appData = os.Getenv("APPDATA")
var userProfile = os.Getenv("USERPROFILE")

const numWorkers = 5

type searchJob struct {
	basePath string
	rmmDir   string
}

func Detect() []Directory {
	fmt.Printf("[*] Enumerating Suspicious Directories \n")

	// Create channels
	jobs := make(chan searchJob, 100)
	results := make(chan Directory, 100)

	// WaitGroup to track workers
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	// Start result collector goroutine
	var suspiciousDirectories []Directory
	seen := make(map[string]bool)
	var resultWg sync.WaitGroup
	resultWg.Add(1)

	go func() {
		defer resultWg.Done()
		for dir := range results {
			if !seen[dir.Path] {
				fmt.Printf("   [?] Found %s\n", dir.Path)
				suspiciousDirectories = append(suspiciousDirectories, dir)
				seen[dir.Path] = true
			}
		}
	}()

	// Send jobs to workers
	for _, rmmDir := range common.KnownRMMDirectories {
		for _, basePath := range common.SearchBasePaths {
			jobs <- searchJob{
				basePath: basePath,
				rmmDir:   rmmDir,
			}
		}
	}

	// Close jobs channel and wait for workers to finish
	close(jobs)
	wg.Wait()

	// Close results channel and wait for collector to finish
	close(results)
	resultWg.Wait()

	fmt.Printf("[+] Found %d Suspicious Directories\n", len(suspiciousDirectories))

	return suspiciousDirectories
}

// worker processes search jobs from the jobs channel
func worker(jobs <-chan searchJob, results chan<- Directory, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		// Replace environment variables
		basePath := replaceEnvVars(job.basePath)

		// Construct full path
		fullPath := filepath.Join(basePath, job.rmmDir)

		// Check if this is a prefix pattern (ends with incomplete path like "ScreenConnect Client (")
		if isPrefix(job.rmmDir) {
			// Find all directories matching this prefix
			matches := findPrefixMatches(fullPath)
			for _, match := range matches {
				results <- Directory{Path: match}
			}
		} else {
			// Exact match
			if _, err := os.Stat(fullPath); err == nil {
				results <- Directory{Path: fullPath}
			}
		}
	}
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
