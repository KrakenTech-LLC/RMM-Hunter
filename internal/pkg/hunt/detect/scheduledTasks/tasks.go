package scheduledTasks

import (
	"fmt"
	"rmm-hunter/internal/pkg/hunt/detect/common"
	. "rmm-hunter/internal/suspicious"
	"strings"
	"time"

	schTasks "github.com/Kraken-OffSec/Scurvy/core/scheduledTasks"
)

func Detect() []*ScheduledTask {
	fmt.Printf("[*] Enumerating Scheduled Tasks \n")
	tasks, err := schTasks.ListTasks()
	if err != nil {
		fmt.Printf("[-] Error enumerating scheduled tasks: %s\n", err.Error())
		return []*ScheduledTask{}
	}
	fmt.Printf("   [>] Dispositioning %d Scheduled Tasks\n", len(tasks))

	return compareTasks(tasks)
}

func compareTasks(tasks []schTasks.TaskInfo) []*ScheduledTask {
	var suspiciousTasks []*ScheduledTask

	for _, task := range tasks {
		for _, rmm := range common.CommonRMMs {
			rmmLower := strings.ToLower(rmm)
			taskNameLower := strings.ToLower(task.Name)
			if strings.Contains(taskNameLower, rmmLower) {
				fmt.Printf("      [?] Found %s\n", task.Name)
				suspiciousTasks = append(suspiciousTasks, &ScheduledTask{
					Name:         task.Name,
					Author:       task.Author,
					LastRun:      task.LastRun.Format(time.RFC3339),
					NextRun:      task.NextRun.Format(time.RFC3339),
					LastResult:   task.LastResult,
					CreatedDate:  task.CreationDate.Format(time.RFC3339),
					State:        task.State,
					Path:         task.Path,
					Description:  task.Description,
					ModifiedDate: "",
					Enabled:      task.Enabled,
				})
				break
			}
		}
	}

	fmt.Printf("[+] Found %d Suspicious Scheduled Tasks\n", len(suspiciousTasks))
	return suspiciousTasks
}
