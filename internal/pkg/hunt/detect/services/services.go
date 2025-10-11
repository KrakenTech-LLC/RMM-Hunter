package services

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"github.com/Kraken-OffSec/Scurvy/core/service"
	"golang.org/x/sys/windows"
)

// Whitelist for our own tool and legitimate system components
var whitelist = []string{
	"rmm-hunter",
}

func isWhitelisted(config service.ServiceConfig) bool {
	allText := strings.ToLower(strings.Join([]string{
		config.DisplayName, config.ServiceStartName, config.BinaryPathName, config.Description,
	}, "|"))
	for _, w := range whitelist {
		if strings.Contains(allText, w) {
			return true
		}
	}
	return false
}

func Detect() []*Service {
	fmt.Printf("[*] Enumerating Services \n")

	scm, err := service.Connect()
	if err != nil {
		fmt.Printf("[-] Error getting Service Manager: %s\n", err.Error())
		return []*Service{}
	}
	defer windows.Close(scm.Handle)

	services, err := scm.ListServices()
	if err != nil {
		fmt.Printf("[-] Error enumerating services: %s\n", err.Error())
		return []*Service{}
	}

	fmt.Printf("   [>] Dispositioning %d Services\n", len(services))

	return compareServices(services, scm)
}

func compareServices(serviceStrings []string, scm *service.Mgr) []*Service {
	var suspiciousServices []*Service

	for _, serviceString := range serviceStrings {
		svc, err := scm.OpenService(serviceString)
		if err != nil {
			fmt.Printf("         [>-] Error opening service %s: %s\n", serviceString, err.Error())
			continue
		}
		config, err := svc.Config()
		if err != nil {
			fmt.Printf("         [>-] Error getting service config %s: %s\n", serviceString, err.Error())
			continue
		}

		// Skip whitelisted services (our own tool)
		if isWhitelisted(config) {
			continue
		}

		if isSuspiciousService(config) {
			fmt.Printf("      [?] Found %s\n", config.DisplayName)
			suspiciousServices = append(suspiciousServices, &Service{
				Name:             serviceString,
				DisplayName:      config.DisplayName,
				ServiceTypeRaw:   config.ServiceType,
				ServiceType:      getServiceType(config.ServiceType),
				StartTypeRaw:     config.StartType,
				StartType:        getStartType(config.StartType),
				ErrorControlRaw:  config.ErrorControl,
				ErrorControl:     getErrorControl(config.ErrorControl),
				BinaryPathName:   config.BinaryPathName,
				LoadOrderGroup:   config.LoadOrderGroup,
				TagId:            config.TagId,
				Dependencies:     config.Dependencies,
				ServiceStartName: config.ServiceStartName,
				Password:         config.Password,
				Description:      config.Description,
				SidType:          config.SidType,
				DelayedAutoStart: config.DelayedAutoStart,
			})
		}
	}

	fmt.Printf("[+] Found %d Suspicious Services\n", len(suspiciousServices))
	return suspiciousServices
}

// isSuspiciousService uses multi-indicator scoring to detect RMM services
// Requires at least 2 independent indicators to flag as suspicious
func isSuspiciousService(config service.ServiceConfig) bool {
	score := 0

	// Build searchable text from all service fields
	allText := strings.ToLower(strings.Join([]string{
		config.DisplayName, config.ServiceStartName, config.BinaryPathName, config.Description,
	}, "|"))

	// Indicator 1: Known RMM vendor name match (CommonRMMs)
	rmmNameHit := false
	for _, rmm := range common.CommonRMMs {
		if strings.Contains(allText, strings.ToLower(rmm)) {
			rmmNameHit = true
			break
		}
	}
	if rmmNameHit {
		score++
	}

	// Indicator 2: Known RMM executable/binary pattern in service binary path (CommonImageSuffixes)
	binaryPatternHit := false
	binaryPathLower := strings.ToLower(config.BinaryPathName)
	for _, pattern := range common.CommonImageSuffixes {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(binaryPathLower, patternLower) {
			binaryPatternHit = true
			break
		}
	}
	if binaryPatternHit {
		score++
	}

	// Indicator 3: Known RMM DNS/domain in binary path or description (CommonDNS)
	dnsHit := false
	for _, dns := range common.CommonDNS {
		dnsLower := strings.ToLower(dns)
		// Handle wildcard patterns: *.example.com should match anything.example.com
		if strings.HasPrefix(dnsLower, "*.") {
			// Match the domain suffix (e.g., ".example.com")
			domainSuffix := dnsLower[1:] // Remove the * but keep the dot
			if strings.Contains(allText, domainSuffix) {
				dnsHit = true
				break
			}
		} else if strings.HasSuffix(dnsLower, ".*") {
			// Handle patterns like example.* - match the prefix
			domainPrefix := dnsLower[:len(dnsLower)-2] // Remove the .*
			if strings.Contains(allText, domainPrefix) {
				dnsHit = true
				break
			}
		} else {
			// Exact domain match (no wildcard)
			if strings.Contains(allText, dnsLower) {
				dnsHit = true
				break
			}
		}
	}
	if dnsHit {
		score++
	}

	// Indicator 4: Suspicious installation path (temp, public, programdata)
	pathSuspicious, _ := common.AnalyzeExecutablePath(config.BinaryPathName)
	if pathSuspicious {
		score++
	}

	// Require at least 2 independent Indicators to reduce false positives
	return score >= 2
}

func getServiceType(raw uint32) string {
	switch raw {
	case 1:
		return "KernelDriver"
	case 2:
		return "FileSystemDriver"
	case 4:
		return "Adapter"
	case 8:
		return "RecognizerDriver"
	case 16:
		return "Win32OwnProcess"
	case 32:
		return "Win32ShareProcess"
	case 256:
		return "InteractiveProcess"
	default:
		return "Unknown"
	}
}

func getStartType(raw uint32) string {
	switch raw {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Automatic"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return "Unknown"
	}
}

func getErrorControl(raw uint32) string {
	switch raw {
	case 0:
		return "Ignore"
	case 1:
		return "Normal"
	case 2:
		return "Severe"
	case 3:
		return "Critical"
	default:
		return fmt.Sprintf("Unknown %d", raw)
	}
}
