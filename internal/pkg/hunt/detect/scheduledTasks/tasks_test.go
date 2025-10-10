package scheduledTasks

import "testing"

func TestDetect(t *testing.T) {
	tasks := Detect()
	for _, task := range tasks {
		t.Logf("-----")
		t.Logf("Name: %s", task.Name)
		t.Logf("Author: %s", task.Author)
		t.Logf("LastRun: %s", task.LastRun)
		t.Logf("NextRun: %s", task.NextRun)
		t.Logf("LastResult: %s", task.LastResult)
		t.Logf("CreatedDate: %s", task.CreatedDate)
		t.Logf("State: %s", task.State)
		t.Logf("Path: %s", task.Path)
		t.Logf("Description: %s", task.Description)
		t.Logf("ModifiedDate: %s", task.ModifiedDate)
		t.Logf("Enabled: %t", task.Enabled)
		t.Logf("-----")
	}
}
