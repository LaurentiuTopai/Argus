package main

import (
	"argus/ui"
	"fmt"
	"os"
)

func main() {
	port := 8080
	if err := ui.StartServer(port); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		os.Exit(1)
	}
}
