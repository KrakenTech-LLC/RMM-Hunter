package eliminate

import "os"

func EliminateDirectory(path string) error {
	return os.RemoveAll(path)
}
