package nucleusapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Parallax-Web-Services/nucleus/cloud"
)

const NebulaVersion = "0.6.1-dev"
const NebulaHelp = `NEBULA 0.6 — Private fabric across your machines

  nebula login [--url https://nebula.parallax.link] [--no-open] [--loopback]
  nebula logout
  nebula org list | use ORGANIZATION_ID
  nebula cluster list | show CLUSTER_ID
  nebula machine init --name NAME
  nebula machine identity
  nebula machine enroll [--url URL] [--no-open]
  nebula machine run [--once] [--inference FILE] [--model-root DIR --allow-model-installs]
  nebula machine status
  nebula machine disconnect [--local]
  nebula fabric invite --endpoint https://PRIVATE_IP:9461 --out invite.json
  nebula fabric inspect request.json
  nebula fabric join invite.json --out request.json
  nebula fabric accept request.json --out grant.json
  nebula fabric join --accept grant.json
  nebula fabric members
  nebula fabric revoke NODE_ID
  nebula network connect [--ui 127.0.0.1:0] [--no-open]
  nebula relay serve --issuer-public-key-file /absolute/public-key [--listen 127.0.0.1:8743]
  nebula version

Hosted login shows a short code to approve in the NEBULA dashboard.
Use --loopback only to explicitly select the older localhost callback flow.

Network connect always uses the authenticated NEBULA relay and inner mTLS.
Pair the fabric, enroll each machine in the same organization, and enable its
relay access in the hosted panel before connecting. Machine run sends telemetry;
model work remains an explicit operator opt-in. Pairing files contain capabilities
and must travel through an independent trusted channel.

NEBULA_HOME selects an absolute private state directory. Otherwise NEBULA reuses
NUCLEUS_HOME or the existing Nucleus configuration directory and machine identity.
`

const nebulaMachineHelp = `NEBULA machines

  nebula machine init --name NAME
  nebula machine identity
  nebula machine enroll [--url URL] [--name NAME] [--no-open]
  nebula machine run [--once] [--inference FILE] [--model-root DIR --allow-model-installs]
  nebula machine status
  nebula machine disconnect [--local]

Enroll proves the existing machine key and waits for owner/admin approval.
Status describes the saved local binding, not proof of current connectivity.
Machine run sends telemetry; inference/model management requires explicit opt-in.
`
const nebulaFabricHelp = `NEBULA fabric

  nebula fabric invite --endpoint https://PRIVATE_IP:9461 --out invite.json [--ttl 10m]
  nebula fabric inspect request.json
  nebula fabric join invite.json --out request.json
  nebula fabric accept request.json --out grant.json
  nebula fabric join --accept grant.json
  nebula fabric members
  nebula fabric revoke NODE_ID

The owner explicitly accepts a signed join request, and the member accepts its
grant. Transfer pairing documents through an independent trusted channel.
`
const nebulaNetworkHelp = `NEBULA network

  nebula network connect [--ui 127.0.0.1:0] [--no-open]

Uses the authenticated NEBULA relay for an already paired fabric. Each machine
must be enrolled in the same organization and have relay access enabled.
The resource map binds loopback. No public machine listener is opened.
`
const nebulaRelayHelp = `NEBULA relay

  nebula relay serve --issuer-public-key-file /absolute/public-key [--listen 127.0.0.1:8743]

Runs the existing capability-authorized opaque relay behind owned HTTPS ingress.
The listener must be 127.0.0.1:PORT. Supply the public issuer key, never a private key.
`

// RunNebula is the standalone NEBULA entry point. It calls the shared runtime
// in process; it does not spawn or depend on an installed nucleus executable.
func RunNebula(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Print(NebulaHelp)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) != 1 {
			return errors.New("usage: nebula version")
		}
		fmt.Println("nebula " + NebulaVersion)
		return nil
	}
	if args[0] == "login" || args[0] == "logout" || args[0] == "org" || args[0] == "cluster" {
		return hostedCommand(args)
	}
	translated, help, err := nebulaInvocation(args)
	if err != nil {
		return err
	}
	if help != "" {
		fmt.Print(help)
		return nil
	}
	if translated[0] == "nebula" {
		return nebulaCommand(translated[1:])
	}
	home, err := nebulaHomePath()
	if err != nil {
		return err
	}
	err = runAtHome(home, translated, "nebula")
	if errors.Is(err, cloud.ErrNotRegistered) {
		return &nebulaEnrollmentError{cause: err}
	}
	return err
}

func isHelp(value string) bool { return value == "help" || value == "--help" || value == "-h" }
func nebulaHomePath() (string, error) {
	if home := os.Getenv("NEBULA_HOME"); home != "" {
		if !filepath.IsAbs(home) {
			return "", errors.New("NEBULA_HOME must be absolute")
		}
		return home, nil
	}
	return homePath()
}

func nebulaInvocation(args []string) ([]string, string, error) {
	helps := map[string]string{"machine": nebulaMachineHelp, "fabric": nebulaFabricHelp, "network": nebulaNetworkHelp, "relay": nebulaRelayHelp}
	help, known := helps[args[0]]
	if !known {
		return nil, "", fmt.Errorf("unknown command %q; see nebula help", args[0])
	}
	if len(args) == 1 || isHelp(args[1]) {
		return nil, help, nil
	}
	var command []string
	switch args[0] {
	case "machine":
		switch args[1] {
		case "init", "identity":
			command = []string{args[1]}
		case "enroll":
			command = []string{"cloud", "connect"}
		case "run", "status", "disconnect":
			command = []string{"cloud", args[1]}
		}
	case "fabric":
		switch args[1] {
		case "invite", "inspect", "join", "accept", "members", "revoke":
			command = []string{args[1]}
		}
	case "network":
		if args[1] == "connect" {
			for _, arg := range args[2:] {
				if strings.HasPrefix(arg, "-") && strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-") == "nebula" {
					return nil, "", errors.New("nebula network connect always uses NEBULA transport; --nebula cannot be overridden")
				}
			}
			command = []string{"run", "--nebula"}
		}
	case "relay":
		if args[1] == "serve" {
			command = []string{"nebula", "relay"}
		}
	}
	if command == nil {
		return nil, "", fmt.Errorf("unknown %s command %q; see nebula %s help", args[0], args[1], args[0])
	}
	for _, arg := range args[2:] {
		if isHelp(arg) {
			return nil, help, nil
		}
	}
	return append(command, args[2:]...), "", nil
}

func commandName(product, command string) string {
	if product != "nebula" {
		return "nucleus " + command
	}
	switch command {
	case "init", "identity":
		return "nebula machine " + command
	case "cloud connect":
		return "nebula machine enroll"
	case "cloud run", "cloud status", "cloud disconnect":
		return "nebula machine " + strings.TrimPrefix(command, "cloud ")
	case "run":
		return "nebula network connect"
	default:
		return "nebula fabric " + command
	}
}

// Keep the existing sentinel available to callers while showing this product's command.
type nebulaEnrollmentError struct{ cause error }

func (e *nebulaEnrollmentError) Error() string {
	return "no hosted registration; run nebula machine enroll"
}
func (e *nebulaEnrollmentError) Unwrap() error { return e.cause }
