package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Parallax-Web-Services/nucleus/internal/nucleusapp"
)

func main() {
	if err := nucleusapp.RunNebula(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(nucleusapp.NebulaHelp)
			return
		}
		fmt.Fprintln(os.Stderr, "nebula:", err)
		os.Exit(1)
	}
}
