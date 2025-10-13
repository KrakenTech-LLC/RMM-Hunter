package web

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	shell32       = syscall.NewLazyDLL("shell32.dll")
	shellExecuteW = shell32.NewProc("ShellExecuteW")
)

// OpenBrowser opens the default browser to the specified URL using Windows ShellExecute API
func OpenBrowser(url string) error {
	// Convert strings to UTF16 pointers
	operation, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return fmt.Errorf("failed to convert operation string: %w", err)
	}

	urlPtr, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return fmt.Errorf("failed to convert URL string: %w", err)
	}

	// ShellExecuteW(hwnd, operation, file, parameters, directory, showCmd)
	// SW_SHOWNORMAL = 1, SW_SHOW = 5
	ret, _, callErr := shellExecuteW.Call(
		0,                                  // hwnd (NULL)
		uintptr(unsafe.Pointer(operation)), // operation ("open")
		uintptr(unsafe.Pointer(urlPtr)),    // file (URL)
		0,                                  // parameters (NULL)
		0,                                  // directory (NULL)
		5,                                  // showCmd (SW_SHOW)
	)

	// ShellExecute returns a value > 32 on success
	if ret <= 32 {
		return fmt.Errorf("ShellExecute failed with code: %d (error: %v)", ret, callErr)
	}

	fmt.Printf("[web] Browser opened successfully (return code: %d)\n", ret)
	return nil
}
