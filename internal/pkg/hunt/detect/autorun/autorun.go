package autorun

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"github.com/Kraken-OffSec/Scurvy/core/autoruns"
)

// Whitelist for our own tool and legitimate system components
var whitelist = []string{
	"rmm-hunter",
}

func isWhitelisted(ar AutoRun) bool {
	allText := strings.ToLower(strings.Join([]string{
		ar.ImageName, ar.ImagePath, ar.Entry, ar.LaunchString,
	}, "|"))
	for _, w := range whitelist {
		if strings.Contains(allText, w) {
			return true
		}
	}
	return false
}

func Detect() []AutoRun {
	var suspiciousAutoRuns []AutoRun

	fmt.Printf("[*] Enumerating AutoRun Applications\n")

	// Enumerate autoruns from Registry and COM Services
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

		// Skip whitelisted entries (our own tool)
		if isWhitelisted(sar) {
			continue
		}

		if isSuspiciousAutoRunEntry(sar) {
			fmt.Printf("   [?] Found %s | %s | %s\n", sar.Location, sar.Entry, sar.ImagePath)
			suspiciousAutoRuns = append(suspiciousAutoRuns, sar)
		}
	}

	fmt.Printf("[+] Found %d Suspicious AutoRun Applications\n", len(suspiciousAutoRuns))
	return suspiciousAutoRuns
}

// isSuspiciousAutoRunEntry uses multi-Indicator scoring to detect RMMs
// Requires at least 2 independent Indicators to flag as suspicious
// Hash match alone is sufficient (high confidence)
func isSuspiciousAutoRunEntry(ar AutoRun) bool {
	score := 0

	// Build searchable text from all fields
	allText := strings.ToLower(strings.Join([]string{
		ar.ImageName, ar.ImagePath, ar.Entry, ar.LaunchString, ar.Location, ar.Arguments,
	}, "|"))

	// Indicator 0: Known RMM hash match (SHA256 or SHA1) - HIGHEST CONFIDENCE
	// A hash match alone is sufficient to flag as suspicious
	if ar.SHA256 != "" {
		sha256Lower := strings.ToLower(ar.SHA256)
		for _, hash := range common.CommonRMMHashes {
			if strings.ToLower(hash) == sha256Lower {
				return true // Hash match is definitive
			}
		}
	}
	if ar.SHA1 != "" {
		sha1Lower := strings.ToLower(ar.SHA1)
		for _, hash := range common.CommonRMMHashesSHA1 {
			if strings.ToLower(hash) == sha1Lower {
				return true // Hash match is definitive
			}
		}
	}

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

	// Indicator 2: Known RMM executable/binary pattern (CommonImageSuffixes)
	binaryPatternHit := false
	imgPathLower := strings.ToLower(ar.ImagePath)
	imgNameLower := strings.ToLower(ar.ImageName)
	launchLower := strings.ToLower(ar.LaunchString)
	for _, pattern := range common.CommonImageSuffixes {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(imgPathLower, patternLower) ||
			strings.Contains(imgNameLower, patternLower) ||
			strings.Contains(launchLower, patternLower) {
			binaryPatternHit = true
			break
		}
	}
	if binaryPatternHit {
		score++
	}

	// Indicator 3: Known RMM DNS/domain in command line or launch string (CommonDNS)
	dnsHit := false
	argsLower := strings.ToLower(ar.Arguments)
	for _, dns := range common.CommonDNS {
		dnsLower := strings.ToLower(dns)
		// Handle wildcard patterns: *.example.com should match anything.example.com
		if strings.HasPrefix(dnsLower, "*.") {
			// Match the domain suffix (e.g., ".example.com")
			domainSuffix := dnsLower[1:] // Remove the * but keep the dot
			if strings.Contains(launchLower, domainSuffix) || strings.Contains(argsLower, domainSuffix) {
				dnsHit = true
				break
			}
		} else if strings.HasSuffix(dnsLower, ".*") {
			// Handle patterns like example.* - match the prefix
			domainPrefix := dnsLower[:len(dnsLower)-2] // Remove the .*
			if strings.Contains(launchLower, domainPrefix) || strings.Contains(argsLower, domainPrefix) {
				dnsHit = true
				break
			}
		} else {
			// Exact domain match (no wildcard)
			if strings.Contains(launchLower, dnsLower) || strings.Contains(argsLower, dnsLower) {
				dnsHit = true
				break
			}
		}
	}
	if dnsHit {
		score++
	}

	// Indicator 4: Suspicious installation path (temp, public, programdata)
	pathSuspicious, _ := common.AnalyzeExecutablePath(ar.ImagePath)
	if !pathSuspicious && ar.LaunchString != "" {
		pathSuspicious, _ = common.AnalyzeExecutablePath(ar.LaunchString)
	}
	if pathSuspicious {
		score++
	}

	// Require at least 2 independent Indicator to reduce false positives
	return score >= 2
}
