package autorun

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"

	"github.com/Kraken-OffSec/Scurvy/core/autoruns"
)

// basic allow/deny helpers kept local to keep changes scoped
var systemDirs = []string{"\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\", "\\program files\\windowsapps\\"}
var safeSystemBinaries = []string{
	"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "explorer.exe",
	"ctfmon.exe", "spoolsv.exe", "dwm.exe", "smss.exe", "csrss.exe",
	"runtimebroker.exe", "shellexperiencehost.exe", "searchui.exe", "sihost.exe",
	"taskhostw.exe", "wininit.exe", "rdpclip.exe",
}
var genericTokens = map[string]struct{}{
	"remote": {}, "control": {}, "support": {}, "assist": {}, "viewer": {},
	"server": {}, "service": {}, "manager": {}, "desktop": {}, "host": {},
	"client": {}, "agent": {}, "connect": {}, "access": {}, "admin": {},
	"vpn": {}, "ssh": {}, "vnc": {}, "rdp": {}, "microsoft": {}, "windows": {},
}

func inSlice(slice []string, v string) bool {
	v = strings.ToLower(v)
	for _, s := range slice {
		if strings.ToLower(s) == v {
			return true
		}
	}
	return false
}
func containsAny(haystack string, needles []string) bool {
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
func isInSystemDir(p string) bool {
	pl := strings.ToLower(p)
	for _, d := range systemDirs {
		if strings.Contains(pl, d) {
			return true
		}
	}
	return false
}
func isNonGenericToken(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	if len(t) < 4 {
		return false
	}
	if _, ok := genericTokens[t]; ok {
		return false
	}
	return true
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

		if isSuspiciousAutoRunEntry(sar) {
			fmt.Printf("   [?] Found %s | %s | %s\n", sar.Location, sar.Entry, sar.ImagePath)
			suspiciousAutoRuns = append(suspiciousAutoRuns, sar)
		}
	}

	fmt.Printf("[+] Found %d Suspicious AutoRun Applications\n", len(suspiciousAutoRuns))
	return suspiciousAutoRuns
}

// isSuspiciousAutoRunEntry determines if an autorun appears to be an RMM by
// checking image path/name, location, entry and launch string against
// common RMM indicators and suspicious image suffixes. It also flags
// suspicious installation paths.
func isSuspiciousAutoRunEntry(ar AutoRun) bool {
	// Build a single string of fields we care about
	joined := strings.ToLower(strings.Join([]string{ar.ImageName, ar.ImagePath, ar.Entry, ar.LaunchString}, "|"))

	// 1) Vendor token hit (filter out generic words)
	vendorHit := false
	for _, tok := range common.CommonRMMs {
		if !isNonGenericToken(tok) {
			continue
		}
		if strings.Contains(joined, strings.ToLower(tok)) {
			vendorHit = true
			break
		}
	}

	// 2) Known image suffix/file pattern hit (robust to registry naming)
	suffixHit := false
	imgPathLower := strings.ToLower(ar.ImagePath)
	imgNameLower := strings.ToLower(ar.ImageName)
	for _, suf := range common.CommonImageSuffixes {
		s := strings.ToLower(suf)
		if strings.Contains(imgPathLower, s) || strings.Contains(imgNameLower, s) {
			suffixHit = true
			break
		}
	}

	// 3) Known vendor DNS in launch string/command
	dnsHit := false
	ls := strings.ToLower(ar.LaunchString)
	for _, d := range common.CommonDNS {
		if strings.Contains(ls, strings.ToLower(d)) {
			dnsHit = true
			break
		}
	}

	// Require two independent signals to reduce false positives
	if (vendorHit && (suffixHit || dnsHit)) || (suffixHit && dnsHit) {
		return true
	}
	return false
}
