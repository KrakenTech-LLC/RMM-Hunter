package web

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32         = syscall.NewLazyDLL("shell32.dll")
	shellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

const (
	SEE_MASK_NOCLOSEPROCESS = 0x00000040
	SW_SHOW                 = 5
)

// SHELLEXECUTEINFO structure for ShellExecuteEx
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       windows.Handle
}

// BrowserHandle represents a handle to the opened browser process
type BrowserHandle struct {
	ProcessID uint32
	Handle    windows.Handle
}

// OpenBrowser opens the default browser to the specified URL using Windows ShellExecute API
// Returns a handle to the browser process that can be used to close it later
func OpenBrowser(url string) (*BrowserHandle, error) {
	// Convert strings to UTF16 pointers
	operation, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return nil, fmt.Errorf("failed to convert operation string: %w", err)
	}

	urlPtr, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return nil, fmt.Errorf("failed to convert URL string: %w", err)
	}

	// Initialize SHELLEXECUTEINFO structure
	sei := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        SEE_MASK_NOCLOSEPROCESS, // Request process handle
		hwnd:         0,
		lpVerb:       operation,
		lpFile:       urlPtr,
		lpParameters: nil,
		lpDirectory:  nil,
		nShow:        SW_SHOW,
		hInstApp:     0,
	}

	// Call ShellExecuteExW
	ret, _, err := shellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		return nil, fmt.Errorf("ShellExecuteExW failed: %w", err)
	}

	if sei.hInstApp <= 32 {
		return nil, fmt.Errorf("ShellExecuteExW failed with code: %d", sei.hInstApp)
	}

	// Get process ID from handle
	var processID uint32
	if sei.hProcess != 0 {
		processID, err = windows.GetProcessId(sei.hProcess)
		if err != nil {
			// If we can't get PID, still return the handle
			processID = 0
		}
	}

	fmt.Printf("[web] Browser opened successfully (PID: %d)\n", processID)

	return &BrowserHandle{
		ProcessID: processID,
		Handle:    sei.hProcess,
	}, nil
}

// Close terminates the browser process and all child processes
func (bh *BrowserHandle) Close() error {
	if bh == nil {
		return nil
	}

	// First try to kill the direct process if we have a handle
	if bh.Handle != 0 {
		windows.CloseHandle(bh.Handle)
	}

	// Kill all browser processes that might have our URL open
	// This is more reliable than trying to track the exact process tree
	killed := killBrowserProcesses()

	fmt.Printf("[web] Terminated %d browser process(es)\n", killed)
	return nil
}

// killBrowserProcesses finds and kills common browser processes
func killBrowserProcesses() int {
	browserExes := []string{
		"chrome.exe",
		"msedge.exe",
		"firefox.exe",
		"brave.exe",
		"opera.exe",
		"iexplore.exe",
	}

	killed := 0
	for _, exeName := range browserExes {
		count := killProcessByName(exeName)
		killed += count
	}

	return killed
}

// killProcessByName kills all processes with the given executable name
func killProcessByName(exeName string) int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return 0
	}

	killed := 0
	for {
		// Convert the process name from [260]uint16 to string
		processName := syscall.UTF16ToString(procEntry.ExeFile[:])

		if processName == exeName {
			// Open process with terminate rights
			handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, procEntry.ProcessID)
			if err == nil {
				err = windows.TerminateProcess(handle, 0)
				if err == nil {
					killed++
					fmt.Printf("[web] Killed %s (PID: %d)\n", exeName, procEntry.ProcessID)
				}
				windows.CloseHandle(handle)
			}
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}

	return killed
}
