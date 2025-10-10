package processes

import "testing"

func TestDetect(t *testing.T) {
	processes := Detect()
	for _, proc := range processes {
		t.Logf("-----")
		t.Logf("Name: %s", proc.Name)
		t.Logf("PID: %d", proc.PID)
		t.Logf("PPID: %d", proc.PPID)
		t.Logf("Path: %s", proc.Path)
		t.Logf("-----")
	}
}
