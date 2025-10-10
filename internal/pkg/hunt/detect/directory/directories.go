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

	fmt.Printf("[*] Enumerating Suspicious Directories \n")
	// Check for common directories
	for _, dir := range common.CommonDirectories {
		dir = replaceAppData(dir)
		if _, err := os.Stat(dir); err == nil {
			fmt.Printf("   [?] Found %s\n", dir)
			suspiciousDirectories = append(suspiciousDirectories, dir)
		}
	}
	fmt.Printf("[+] Found %d Suspicious Directories\n", len(suspiciousDirectories))

	return suspiciousDirectories
}

func replaceAppData(path string) string {
	if strings.Contains(path, "{{APPDATA}}") {
		p := strings.Replace(path, "{{APPDATA}}", "", -1)
		return filepath.Join(appData, p)
	}
	return path
}
