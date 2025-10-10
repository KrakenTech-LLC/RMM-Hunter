package directory

import "testing"

func TestDetect(t *testing.T) {
	directories := Detect()
	for _, dir := range directories {
		t.Logf("-----")
		t.Logf("Directory: %s", dir)
		t.Logf("-----")
	}
}
