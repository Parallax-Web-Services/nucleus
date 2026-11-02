package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Parallax-Web-Services/nucleus/internal/nucleusapp"
)

func main() {
	if err := nucleusapp.Run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(nucleusapp.Help)
			return
		}
		fmt.Fprintln(os.Stderr, "nucleus:", err)
		os.Exit(1)
	}
}
