package main

import "rmm-hunter/internal/tui"

func main() {
	err := tui.RunEliminateUI()
	if err != nil {
		panic(err)
	}
}
