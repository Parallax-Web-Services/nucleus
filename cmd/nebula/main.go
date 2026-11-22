package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Parallax-Web-Services/nucleus/cli/nebula"
)

func main() {
	if err := nebula.Run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(nebula.Help)
			return
		}
		fmt.Fprintln(os.Stderr, "nebula:", err)
		os.Exit(1)
	}
}
