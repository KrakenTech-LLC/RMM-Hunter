package eliminate

import "os"

// EliminateBinary removes a binary from the system
func EliminateBinary(path string) error {
	return os.Remove(path)
}
