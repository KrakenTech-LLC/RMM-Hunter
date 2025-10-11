package autorun

import "testing"

func TestAutoRun(t *testing.T) {
	autoruns := Detect()
	for _, ar := range autoruns {
		t.Logf("-----")
		t.Logf("Type: %s", ar.Type)
		t.Logf("Entry: %s", ar.Entry)
		t.Logf("Location: %s", ar.Location)
		t.Logf("Image: %s", ar.ImagePath)
		t.Logf("Args: %s", ar.Arguments)
		t.Logf("MD5: %s", ar.MD5)
		t.Logf("SHA1: %s", ar.SHA1)
		t.Logf("SHA256: %s", ar.SHA256)
		t.Logf("-----")
	}
}
