package services

import "testing"

func TestDetect(t *testing.T) {
	services := Detect()
	for _, svc := range services {
		t.Logf("-----")
		t.Logf("Name: %s", svc.Name)
		t.Logf("DisplayName: %s", svc.DisplayName)
		t.Logf("ServiceTypeRaw: %d", svc.ServiceTypeRaw)
		t.Logf("ServiceType: %s", svc.ServiceType)
		t.Logf("StartTypeRaw: %d", svc.StartTypeRaw)
		t.Logf("StartType: %s", svc.StartType)
		t.Logf("ErrorControlRaw: %d", svc.ErrorControlRaw)
		t.Logf("ErrorControl: %s", svc.ErrorControl)
		t.Logf("BinaryPathName: %s", svc.BinaryPathName)
		t.Logf("LoadOrderGroup: %s", svc.LoadOrderGroup)
		t.Logf("TagId: %d", svc.TagId)
		t.Logf("Dependencies: %v", svc.Dependencies)
		t.Logf("ServiceStartName: %s", svc.ServiceStartName)
		t.Logf("Password: %s", svc.Password)
		t.Logf("Description: %s", svc.Description)
		t.Logf("SidType: %d", svc.SidType)
		t.Logf("DelayedAutoStart: %t", svc.DelayedAutoStart)
		t.Logf("-----")
	}
}
