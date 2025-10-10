package connections

import "testing"

func TestDetectOutboundConnections(t *testing.T) {
	conns := DetectOutboundConnections()
	for _, conn := range conns {
		t.Logf("-----")
		t.Logf("PID: %s", conn.PID)
		t.Logf("LocalAddr: %s", conn.LocalAddr)
		t.Logf("RemoteAddr: %s", conn.RemoteAddr)
		t.Logf("RemoteHost: %s", conn.RemoteHost)
		t.Logf("State: %s", conn.State)
		t.Logf("Process: %s", conn.Process)
		t.Logf("-----")
	}
}
