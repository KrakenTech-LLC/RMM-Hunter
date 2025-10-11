package autorun

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"github.com/Kraken-OffSec/Scurvy/core/autoruns"
)

func Detect() []AutoRun {
	var suspiciousAutoRuns []AutoRun

	fmt.Printf("[*] Enumerating AutoRun Applications\n")

	// Use Scurvy to enumerate autoruns from multiple sources
	autoRuns := autoruns.GetAllAutoruns()
	fmt.Printf("   [>] Dispositioning %d AutoRun Entries\n", len(autoRuns))

	for _, ar := range autoRuns {
		// Map Scurvy autorun to our Suspicious.AutoRun struct
		sar := AutoRun{
			Type:         ar.Type,
			Location:     ar.Location,
			ImagePath:    ar.ImagePath,
			ImageName:    ar.ImageName,
			Arguments:    ar.Arguments,
			MD5:          ar.MD5,
			SHA1:         ar.SHA1,
			SHA256:       ar.SHA256,
			Entry:        ar.Entry,
			LaunchString: ar.LaunchString,
		}

		if isSuspiciousAutoRunEntry(sar) {
			fmt.Printf("   [?] Found %s | %s | %s\n", sar.Location, sar.Entry, sar.ImagePath)
			suspiciousAutoRuns = append(suspiciousAutoRuns, sar)
		}
	}

	fmt.Printf("[+] Found %d Suspicious AutoRun Applications\n", len(suspiciousAutoRuns))
	return suspiciousAutoRuns
}

// isSuspiciousAutoRunEntry determines if an autorun looks like an RMM by
// checking image path/name, location, entry and launch string against
// common RMM indicators and suspicious image suffixes. It also flags
// suspicious installation paths.
func isSuspiciousAutoRunEntry(ar AutoRun) bool {
	// Prepare lowercase fields for matching
	fields := []string{
		strings.ToLower(ar.ImageName),
		strings.ToLower(ar.ImagePath),
		strings.ToLower(ar.Location),
		strings.ToLower(ar.LaunchString),
		strings.ToLower(ar.Entry),
	}

	// Match against known RMM names/keywords
	for _, rmm := range common.CommonRMMs {
		r := strings.ToLower(rmm)
		for _, f := range fields {
			if strings.Contains(f, r) {
				return true
			}
		}
	}

	// Match against common suspicious image suffix/patterns (path or name)
	imgPathLower := strings.ToLower(ar.ImagePath)
	imgNameLower := strings.ToLower(ar.ImageName)
	for _, suf := range common.CommonImageSuffixes {
		s := strings.ToLower(suf)
		if strings.Contains(imgPathLower, s) || strings.Contains(imgNameLower, s) {
			return true
		}
	}

	// Suspicious installation paths
	if suspicious, _ := common.AnalyzeExecutablePath(ar.ImagePath); suspicious {
		return true
	}
	// Consider launch string as a command line too
	if ar.LaunchString != "" {
		if suspicious, _ := common.AnalyzeExecutablePath(ar.LaunchString); suspicious {
			return true
		}
	}

	return false
}
