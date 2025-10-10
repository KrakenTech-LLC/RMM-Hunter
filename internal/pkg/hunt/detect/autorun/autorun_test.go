package autorun

import "testing"

func TestAutoRun(t *testing.T) {
	autoruns := Detect()
	for _, ar := range autoruns {
		t.Logf("-----")
		t.Logf("Name: %s", ar.Name)
		t.Logf("Command: %s", ar.Command)
		t.Logf("Location: %s", ar.Location)
		t.Logf("Enabled: %t", ar.Enabled)
		t.Logf("Description: %s", ar.Description)
		t.Logf("-----")
	}
}
