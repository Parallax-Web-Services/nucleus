package nucleusapp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/internal/dashboard"
	"github.com/Parallax-Web-Services/nucleus/inventory"
	"github.com/Parallax-Web-Services/nucleus/positronic"
)

const Help = `Nucleus Alpha 0.5 — Private Fabric, NEBULA WAN and Opt-in Hosted Model Work

  nucleus init --name NAME
  nucleus identity
  nucleus invite --endpoint https://PRIVATE_IP:9461 --out invite.json [--ttl 10m]
  nucleus join invite.json --out request.json
  nucleus inspect request.json
  nucleus accept request.json --out grant.json
  nucleus join --accept grant.json
  nucleus members
  nucleus revoke NODE_ID
  nucleus snapshot
  nucleus cloud connect [--url https://nucleus.parallax.link/dashboard] [--no-open]
  nucleus cloud run [--once] [--inference FILE] [--model-root DIR --allow-model-installs]
  nucleus cloud status
  nucleus cloud disconnect [--local]
  nucleus run [--nebula] [--listen PRIVATE_IP:9461] [--ui 127.0.0.1:0] [--no-open]
  nucleus nebula relay --issuer-public-key-file /absolute/public-key [--listen 127.0.0.1:8743]

The owner invites and explicitly accepts. The joining node explicitly joins and
accepts its grant. Transfer pairing files over an independent trusted channel.
Only the owner runs a private-LAN listener. Members make outbound mTLS connections.
Typed CPU inference is opt-in with --inference CONFIG (no arbitrary remote commands).
  nucleus benchmark --config CONFIG --model ID [--prompt TEXT] [--max-tokens 32]
  nucleus validate-models --config CONFIG
Nodes need no public listener. --nebula uses outbound HTTPS relay; no direct NAT traversal.
NUCLEUS_HOME selects an absolute private state directory.
`

func homePath() (string, error) {
	if value := os.Getenv("NUCLEUS_HOME"); value != "" {
		if !filepath.IsAbs(value) {
			return "", errors.New("NUCLEUS_HOME must be absolute")
		}
		return value, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "nucleus"), nil
}
func options(name string, args []string, build func(*flag.FlagSet)) ([]string, error) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	build(f)
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		value := args[i]
		if strings.HasPrefix(value, "-") {
			flags = append(flags, value)
			key := strings.TrimLeft(strings.SplitN(value, "=", 2)[0], "-")
			known := f.Lookup(key)
			if known != nil && !strings.Contains(value, "=") {
				isBool := false
				if b, ok := known.Value.(interface{ IsBoolFlag() bool }); ok {
					isBool = b.IsBoolFlag()
				}
				if !isBool {
					i++
					if i >= len(args) {
						return nil, fmt.Errorf("%s needs a value", value)
					}
					flags = append(flags, args[i])
				}
			}
		} else {
			positionals = append(positionals, value)
		}
	}
	if err := f.Parse(append(flags, positionals...)); err != nil {
		return nil, err
	}
	return f.Args(), nil
}
func Run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(Help)
		return nil
	}
	if args[0] == "--version" {
		fmt.Println("nucleus 0.5.0-alpha")
		return nil
	}
	home, err := homePath()
	if err != nil {
		return err
	}
	return runAtHome(home, args, "nucleus")
}

func runAtHome(home string, args []string, product string) error {
	var err error
	switch args[0] {
	case "nebula":
		return nebulaCommand(args[1:])
	case "cloud":
		return cloudCommandNamed(home, args[1:], product)
	case "validate-models":
		return validateModelsCommand(args[1:])
	case "benchmark":
		return benchmarkCommand(home, args[1:])
	case "init":
		var name string
		rest, err := options("init", args[1:], func(f *flag.FlagSet) { f.StringVar(&name, "name", "", "node label") })
		if err != nil {
			return err
		}
		if len(rest) > 0 {
			return errors.New("unexpected init arguments")
		}
		if name == "" {
			name, _ = os.Hostname()
		}
		state, err := fabric.Init(home, name)
		if err != nil {
			return err
		}
		fmt.Printf("Node %s\nIdentity %s\nState %s\n", state.Name, state.NodeID, home)
	case "identity":
		if len(args) != 1 {
			return fmt.Errorf("usage: %s", commandName(product, "identity"))
		}
		state, err := fabric.Load(home)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"schema_version": 1, "name": state.Name, "node_id": state.NodeID, "fabric_id": state.FabricID, "owner_id": state.OwnerID})
	case "invite":
		var endpoint, out string
		var ttl time.Duration
		rest, err := options("invite", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&endpoint, "endpoint", "", "private HTTPS endpoint")
			f.StringVar(&out, "out", "", "output invitation file")
			f.DurationVar(&ttl, "ttl", 10*time.Minute, "invitation lifetime")
		})
		if err != nil {
			return err
		}
		if len(rest) > 0 || out == "" || endpoint == "" {
			return fmt.Errorf("usage: %s --endpoint https://PRIVATE_IP:PORT --out invite.json", commandName(product, "invite"))
		}
		data, err := fabric.Invite(home, endpoint, ttl)
		if err != nil {
			return err
		}
		if err = privateOutput(out, data); err != nil {
			return err
		}
		fmt.Println("Invitation saved. It contains a one-use secret; transfer it through a trusted channel.")
	case "join":
		var out, accept string
		rest, err := options("join", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&out, "out", "", "output request")
			f.StringVar(&accept, "accept", "", "accepted membership grant")
		})
		if err != nil {
			return err
		}
		if accept != "" {
			if len(rest) > 0 || out != "" {
				return fmt.Errorf("usage: %s --accept grant.json", commandName(product, "join"))
			}
			data, err := readDocument(accept)
			if err != nil {
				return err
			}
			if err = fabric.FinishJoin(home, data); err != nil {
				return err
			}
			fmt.Printf("Membership accepted. Start %s to send authenticated heartbeats.\n", commandName(product, "run"))
			return nil
		}
		if len(rest) != 1 || out == "" {
			return fmt.Errorf("usage: %s invite.json --out request.json", commandName(product, "join"))
		}
		data, err := readDocument(rest[0])
		if err != nil {
			return err
		}
		request, err := fabric.Join(home, data)
		if err != nil {
			return err
		}
		if err = privateOutput(out, request); err != nil {
			return err
		}
		fmt.Println("Join request saved. Compare this node identity independently before the owner accepts it.")
	case "inspect":
		if len(args) != 2 {
			return fmt.Errorf("usage: %s request.json", commandName(product, "inspect"))
		}
		data, err := readDocument(args[1])
		if err != nil {
			return err
		}
		member, err := fabric.InspectRequest(data)
		if err != nil {
			return err
		}
		return printJSON(member)
	case "accept":
		var out string
		rest, err := options("accept", args[1:], func(f *flag.FlagSet) { f.StringVar(&out, "out", "", "membership grant output") })
		if err != nil {
			return err
		}
		if len(rest) != 1 || out == "" {
			return fmt.Errorf("usage: %s request.json --out grant.json", commandName(product, "accept"))
		}
		data, err := readDocument(rest[0])
		if err != nil {
			return err
		}
		grant, err := fabric.Accept(home, data)
		if err != nil {
			return err
		}
		if err = privateOutput(out, grant); err != nil {
			return err
		}
		fmt.Println("Node explicitly authorized. Return the grant through a trusted channel; the node must accept it.")
	case "members":
		if len(args) != 1 {
			return fmt.Errorf("usage: %s", commandName(product, "members"))
		}
		state, err := fabric.Load(home)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"schema_version": 1, "fabric_id": state.FabricID, "members": state.Members})
	case "revoke":
		if len(args) != 2 {
			return fmt.Errorf("usage: %s NODE_ID", commandName(product, "revoke"))
		}
		if err = fabric.Revoke(home, args[1]); err != nil {
			return err
		}
		fmt.Println("Membership revoked. The node no longer contributes available capacity.")
	case "snapshot":
		if len(args) != 1 {
			return fmt.Errorf("usage: %s", commandName(product, "snapshot"))
		}
		state, err := fabric.Load(home)
		if err != nil {
			return err
		}
		snapshot, err := new(inventory.Monitor).Snapshot()
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"schema_version": 1, "node_id": state.NodeID, "fabric_id": state.FabricID, "resources": snapshot})
	case "run":
		return serve(home, args[1:])
	default:
		return fmt.Errorf("unknown command %q; see nucleus help", args[0])
	}
	return nil
}
func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
func readDocument(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	bytes, err := io.ReadAll(io.LimitReader(file, 1_048_577))
	if err != nil {
		return nil, err
	}
	if len(bytes) > 1_048_576 {
		return nil, errors.New("pairing document too large")
	}
	return bytes, nil
}
func privateOutput(path string, data []byte) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w; choose a new output path", path, err)
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
func serve(home string, args []string) error {
	var listen, ui, inferenceConfig, inferenceAPI string
	var noOpen, nebulaEnabled bool
	rest, err := options("run", args, func(f *flag.FlagSet) {
		f.StringVar(&listen, "listen", "", "explicit owner private-LAN address")
		f.StringVar(&ui, "ui", "127.0.0.1:0", "loopback browser address")
		f.BoolVar(&noOpen, "no-open", false, "print URL only")
		f.BoolVar(&nebulaEnabled, "nebula", false, "use opt-in authenticated NEBULA relay for this paired fabric")
		f.StringVar(&inferenceConfig, "inference", "", "explicit private inference config")
		f.StringVar(&inferenceAPI, "inference-api", "127.0.0.1:9462", "owner loopback inference API")
	})
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errors.New("unexpected run arguments")
	}
	state, err := fabric.Load(home)
	if err != nil {
		return err
	}
	if state.FabricID == "" {
		return errors.New("create an invitation or accept a membership grant first")
	}
	owner := state.NodeID == state.OwnerID
	if owner {
		endpoint, parseErr := url.Parse(state.Endpoint)
		if parseErr != nil {
			return parseErr
		}
		if listen == "" {
			listen = endpoint.Host
		}
		if err = fabric.ValidateEndpoint("https://" + listen); err != nil {
			return err
		}
		if listen != endpoint.Host {
			return errors.New("listen address must match the invitation endpoint")
		}
	}
	if !owner && listen != "" {
		return errors.New("a joined node uses outbound connections; only the owner accepts a listener")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	network, err := prepareNebula(ctx, home, nebulaEnabled)
	if err != nil {
		return err
	}
	if network != nil {
		defer network.Close()
	}

	inferenceService, stopInference, err := prepareInference(ctx, home, state, inferenceConfig, inferenceAPI)
	if err != nil {
		return err
	}
	defer stopInference()
	monitor := new(inventory.Monitor)
	sample, err := monitor.Snapshot()
	if err != nil {
		return err
	}
	var mu sync.RWMutex
	var view positronic.View
	var viewErr error = errors.New("awaiting authenticated connection")
	var coordinator *positronic.Coordinator
	serverErrors := make(chan error, 1)
	if owner {
		coordinator, err = positronic.New(home, sample, 10*time.Second)
		if err != nil {
			return err
		}
		if inferenceService != nil {
			coordinator.SetWorkloadHandler(inferenceService.WorkerHandler)
		}
		config, err := fabric.ServerTLS(home)
		if err != nil {
			return err
		}
		var listener net.Listener
		if network != nil {
			listener, err = network.Listen(ctx)
		} else {
			listener, err = net.Listen("tcp", listen)
		}
		if err != nil {
			return err
		}
		server := &http.Server{Handler: coordinator.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16384}
		server.SetKeepAlivesEnabled(false)
		go func() {
			err := server.Serve(tls.NewListener(listener, config))
			if !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				serverErrors <- err
			}
		}()
		go func() {
			<-ctx.Done()
			closeCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			_ = server.Shutdown(closeCtx)
		}()
		if network != nil {
			fmt.Println("Positronic: authenticated TLS 1.3 through NEBULA")
		} else {
			fmt.Printf("Positronic: authenticated TLS 1.3 on %s\n", listen)
		}
	}
	// View writes and reads share the same lock; network IO occurs before publishing.
	updateSafe := func() {
		sample, err := monitor.Snapshot()
		var next positronic.View
		if err == nil {
			if owner {
				coordinator.UpdateLocal(sample)
				next, err = coordinator.View(state.NodeID)
			} else {
				next, err = positronic.ExchangeWithDialer(home, sample, nebulaDialer(network, state))
			}
		}
		mu.Lock()
		if err == nil {
			view = next
		}
		viewErr = err
		mu.Unlock()
	}
	updateSafe()
	if _, err = dashboard.Start(ctx, ui, noOpen, func() (positronic.View, error) { mu.RLock(); defer mu.RUnlock(); return view, viewErr }); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateSafe()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-serverErrors:
		return err
	}
}
