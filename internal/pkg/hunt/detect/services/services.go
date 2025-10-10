package services

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"github.com/Kraken-OffSec/Scurvy/core/service"
	"golang.org/x/sys/windows"
)

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
		svcStartName := strings.ToLower(config.ServiceStartName)
		svcDisplayName := strings.ToLower(config.DisplayName)
		svcBinaryPath := strings.ToLower(config.BinaryPathName)

		// Check against known RMMs
		isRMMMatch := false
		for _, rmm := range common.CommonRMMs {
			rmmLower := strings.ToLower(rmm)
			if strings.Contains(svcDisplayName, rmmLower) || strings.Contains(svcStartName, rmmLower) || strings.Contains(svcBinaryPath, rmmLower) {
				isRMMMatch = true
				break
			}
		}

		// Check for suspicious path regardless of RMM match
		isPathSuspicious, pathReason := common.AnalyzeExecutablePath(config.BinaryPathName)

		if isRMMMatch || isPathSuspicious {
			description := config.Description
			if isPathSuspicious {
				description += fmt.Sprintf(" [%s]", pathReason)
			}

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
				Description:      description,
				SidType:          config.SidType,
				DelayedAutoStart: config.DelayedAutoStart,
			})
		}
	}

	fmt.Printf("[+] Found %d Suspicious Services\n", len(suspiciousServices))
	return suspiciousServices
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
