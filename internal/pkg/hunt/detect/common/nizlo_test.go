package common

import "testing"

func TestNizloIndicators(t *testing.T) {
	wantNames := []string{
		"Nizlo",
		"Nizlo Agent",
		"NizloAgent",
		"Nizlo RMM",
		"Nizlo RMM Agent",
	}
	for _, want := range wantNames {
		if !contains(CommonRMMs, want) {
			t.Errorf("CommonRMMs does not contain %q", want)
		}
	}

	if !contains(KnownRMMDirectories, `Nizlo\Agent`) {
		t.Error(`KnownRMMDirectories does not contain "Nizlo\Agent"`)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
