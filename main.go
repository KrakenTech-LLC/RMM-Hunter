package main

import (
	"fmt"
	"os"
	"rmm-hunter/cmd"
	"rmm-hunter/internal/web"

	scurvy "github.com/Kraken-OffSec/Scurvy"
)

func main() {
	if len(os.Args) == 1 {
		escErr := scurvy.CheckAndEscalateBinary()
		if escErr != nil {
			fmt.Printf("Failed to elevate: %v\n", escErr)
			os.Exit(1)
		}
		web.StartWebServer()
		return
	}
	cmd.Execute()
}
