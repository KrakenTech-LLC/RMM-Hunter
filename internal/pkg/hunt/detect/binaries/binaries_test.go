package binaries

import "testing"

func TestDetect(t *testing.T) {
	binaries := Detect()
	for _, binary := range binaries {
		t.Logf("-----")
		t.Logf("Binary: %s", binary)
		t.Logf("-----")
	}
}
