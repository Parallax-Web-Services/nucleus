// Package nebula exposes the NUCLEUS runtime used by the standalone NEBULA CLI.
package nebula

import "github.com/Parallax-Web-Services/nucleus/internal/nucleusapp"

// Help describes the commands supported by this runtime version.
const Help = nucleusapp.NebulaHelp

// Run executes a NEBULA invocation using the caller's explicit machine state.
func Run(args []string) error {
	return nucleusapp.RunNebula(args)
}
