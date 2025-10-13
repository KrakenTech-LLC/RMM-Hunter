package web

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	hostsEntry = "127.0.0.1 rmm-hunter"
	marker     = "# RMM-Hunter entry"
)

// AddHostsEntry adds the rmm-hunter DNS entry to the Windows hosts file
// Requires administrator privileges
func AddHostsEntry() error {
	hostsPath := getHostsPath()

	// Check if entry already exists
	exists, err := hostsEntryExists(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to check hosts file: %w", err)
	}

	if exists {
		fmt.Println("[+] rmm-hunter hosts entry already exists")
		return nil
	}

	// Read existing hosts file
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// Append our entry
	newContent := string(content)
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += fmt.Sprintf("\n%s\n%s\n", marker, hostsEntry)

	// Write back to hosts file
	err = os.WriteFile(hostsPath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	fmt.Println("[+] Added rmm-hunter to hosts file")
	fmt.Println("[+] You can now access the web UI at: http://rmm-hunter:8080")
	return nil
}

// RemoveHostsEntry removes the rmm-hunter DNS entry from the Windows hosts file
func RemoveHostsEntry() error {
	hostsPath := getHostsPath()

	// Read existing hosts file
	file, err := os.Open(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to open hosts file: %w", err)
	}
	defer file.Close()

	var newLines []string
	scanner := bufio.NewScanner(file)
	skipNext := false

	for scanner.Scan() {
		line := scanner.Text()

		// Skip the marker line and the next line (our entry)
		if strings.Contains(line, marker) {
			skipNext = true
			continue
		}

		if skipNext && strings.Contains(line, "rmm-hunter") {
			skipNext = false
			continue
		}

		newLines = append(newLines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read hosts file: %w", err)
	}

	// Write back to hosts file
	newContent := strings.Join(newLines, "\n")
	err = os.WriteFile(hostsPath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	fmt.Println("[+] Removed rmm-hunter from hosts file")
	return nil
}

// hostsEntryExists checks if the rmm-hunter entry already exists in the hosts file
func hostsEntryExists(hostsPath string) (bool, error) {
	file, err := os.Open(hostsPath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "rmm-hunter") && strings.Contains(line, "127.0.0.1") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// getHostsPath returns the path to the Windows hosts file
func getHostsPath() string {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	return filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts")
}
