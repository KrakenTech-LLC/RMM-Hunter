package connections

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"
)

func DetectOutboundConnections() []NetworkConnection {
	var connections []NetworkConnection

	fmt.Printf("[*] Enumerating Outbound Connections...\n")

	// Get active connections via netstat
	netstatConnections := getNetstatConnections()
	connections = append(connections, netstatConnections...)

	// Get DNS cache entries for hostname resolution
	dnsCache := getDNSCache()

	// Resolve hostnames for IP addresses
	for i := range connections {
		if hostname, exists := dnsCache[connections[i].RemoteAddr]; exists {
			connections[i].RemoteHost = hostname
		} else {
			connections[i].RemoteHost = resolveHostname(connections[i].RemoteAddr)
		}
	}

	fmt.Printf("   [>] Dispositioning %d Outbound Connections\n", len(connections))

	return compareConnections(connections)
}

func compareConnections(connections []NetworkConnection) []NetworkConnection {
	var suspiciousConnections []NetworkConnection

	// Get process names for all PIDs
	pidToProcessName := getProcessNamesForPIDs(connections)

	for _, conn := range connections {
		isSuspicious := false
		reason := ""

		// Check 1: DNS pattern match (domain-based detection)
		remote := conn.RemoteHost
		for _, dns := range common.CommonDNS {
			if matchesDNSPattern(remote, dns) {
				isSuspicious = true
				reason = fmt.Sprintf("DNS match: %s", conn.RemoteHost)
				break
			}
		}

		// Check 2: Process name match (catches RMMs using custom relay servers)
		if !isSuspicious && conn.PID != "" {
			if processName, exists := pidToProcessName[conn.PID]; exists {
				processNameLower := strings.ToLower(processName)

				// Check against known RMM names
				for _, rmm := range common.CommonRMMs {
					if strings.Contains(processNameLower, strings.ToLower(rmm)) {
						isSuspicious = true
						reason = fmt.Sprintf("RMM process: %s", processName)
						break
					}
				}

				// Check against known RMM executable patterns
				if !isSuspicious {
					for _, pattern := range common.CommonImageSuffixes {
						patternLower := strings.ToLower(pattern)
						// Remove leading backslash for matching
						patternClean := strings.TrimPrefix(patternLower, "\\")
						if strings.Contains(processNameLower, patternClean) {
							isSuspicious = true
							reason = fmt.Sprintf("RMM executable: %s", processName)
							break
						}
					}
				}
			}
		}

		if isSuspicious {
			fmt.Printf("      [?] Found %s (%s)\n", conn.RemoteHost, reason)
			suspiciousConnections = append(suspiciousConnections, conn)
		}
	}

	fmt.Printf("[+] Found %d Suspicious Outbound Connections\n", len(suspiciousConnections))

	return suspiciousConnections
}

// matchesDNSPattern converts DNS pattern to regex and matches hostname
func matchesDNSPattern(hostname, pattern string) bool {
	// Convert to lowercase for case-insensitive matching
	pattern = strings.ToLower(pattern)

	// Remove leading dot if present
	if strings.HasPrefix(pattern, ".") {
		pattern = pattern[1:]
	}

	// Escape special regex characters except * and .
	pattern = regexp.QuoteMeta(pattern)

	// Convert wildcards back to regex
	pattern = strings.ReplaceAll(pattern, `\*`, `[^.]*`)
	pattern = strings.ReplaceAll(pattern, `\.`, `\.`)

	// Anchor the pattern to match end of hostname
	pattern = `(^|\.)` + pattern + `$`

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}

	return regex.MatchString(hostname)
}

func getNetstatConnections() []NetworkConnection {
	var connections []NetworkConnection

	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return connections
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "TCP") && strings.Contains(line, "ESTABLISHED") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				localAddr := fields[1]
				remoteAddr := fields[2]
				state := fields[3]
				pid := fields[4]

				// Filter for outbound connections (exclude localhost)
				if !strings.HasPrefix(remoteAddr, "127.0.0.1") &&
					!strings.HasPrefix(remoteAddr, "::1") {
					connections = append(connections, NetworkConnection{
						LocalAddr:  localAddr,
						RemoteAddr: extractIP(remoteAddr),
						State:      state,
						PID:        pid,
					})
				}
			}
		}
	}

	return connections
}

func getDNSCache() map[string]string {
	cache := make(map[string]string)

	cmd := exec.Command("ipconfig", "/displaydns")
	output, err := cmd.Output()
	if err != nil {
		return cache
	}

	lines := strings.Split(string(output), "\n")
	var currentHost string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Record Name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentHost = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "A (Host) Record") && currentHost != "" {
			// Look for IP in next few lines
			continue
		}

		if currentHost != "" && net.ParseIP(strings.TrimSpace(line)) != nil {
			cache[strings.TrimSpace(line)] = currentHost
			currentHost = ""
		}
	}

	return cache
}

func extractIP(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return strings.TrimSuffix(names[0], ".")
}

// GetHTTPHostnames extracts unique hostnames from outbound connections
func GetHTTPHostnames() []string {
	connections := DetectOutboundConnections()
	hostnameMap := make(map[string]bool)
	var hostnames []string

	for _, conn := range connections {
		if conn.RemoteHost != "" && conn.RemoteHost != conn.RemoteAddr {
			if !hostnameMap[conn.RemoteHost] {
				hostnameMap[conn.RemoteHost] = true
				hostnames = append(hostnames, conn.RemoteHost)
			}
		}
	}

	return hostnames
}

// getProcessNamesForPIDs returns a map of PID -> process name for all connections
func getProcessNamesForPIDs(connections []NetworkConnection) map[string]string {
	pidMap := make(map[string]string)

	// Collect unique PIDs
	uniquePIDs := make(map[string]bool)
	for _, conn := range connections {
		if conn.PID != "" && conn.PID != "0" {
			uniquePIDs[conn.PID] = true
		}
	}

	// Query process names for each PID
	for pid := range uniquePIDs {
		processName := getProcessNameByPID(pid)
		if processName != "" {
			pidMap[pid] = processName
		}
	}

	return pidMap
}

// getProcessNameByPID returns the process name for a given PID
func getProcessNameByPID(pid string) string {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("(Get-Process -Id %s -ErrorAction SilentlyContinue).ProcessName", pid))
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	processName := strings.TrimSpace(string(output))
	return processName
}
