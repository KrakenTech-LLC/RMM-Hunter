package binaries

import (
	"fmt"
	"os"
	"path/filepath"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	"strings"
	"sync"
)

func Detect() []string {
	var foundBinaries []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	fmt.Printf("[*] Enumerating Suspicious Binaries\n")

	// Define search directories
	searchDirs := []string{
		os.Getenv("APPDATA"),
		`C:\ProgramData\`,
		`C:\Program Files\`,
		`C:\Program Files (x86)\`,
		`C:\Downloads\`,
	}

	fmt.Printf("   [>] Dispositioning %d Directories\n", len(searchDirs))

	// Channel to collect results
	resultChan := make(chan string, 100)

	// Start goroutines for each directory
	for _, dir := range searchDirs {
		if dir == "" {
			continue // Skip if environment variable is empty
		}

		wg.Add(1)
		go func(searchDir string) {
			defer wg.Done()
			searchDirectory(searchDir, resultChan)
		}(dir)
	}

	// Goroutine to close channel when all searches complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		mu.Lock()
		foundBinaries = append(foundBinaries, result)
		mu.Unlock()
		fmt.Printf("      [?] Found %s\n", result)
	}

	fmt.Printf("[+] Found %d Suspicious Binaries\n", len(foundBinaries))
	return foundBinaries
}

func searchDirectory(dir string, resultChan chan<- string) {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip directories we can't access
			return nil
		}

		// Skip directories, only check files
		if info.IsDir() {
			return nil
		}

		// Check if the file path ends with any CommonImageEnds
		for _, imageEnd := range common.CommonImageEnds {
			// Normalize path separators and make case-insensitive comparison
			normalizedPath := strings.ToLower(filepath.ToSlash(path))
			normalizedImageEnd := strings.ToLower(filepath.ToSlash(imageEnd))

			if strings.HasSuffix(normalizedPath, normalizedImageEnd) {
				resultChan <- path
				break
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("   [-] Error searching %s: %v\n", dir, err)
	}
}
