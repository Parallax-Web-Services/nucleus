package nucleusapp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/hostedworker"
)

const cloudHelp = `Hosted Nucleus — existing node identity, approved in your NEXUS organization

  nucleus cloud connect [--url https://nucleus.parallax.link/dashboard] [--name NAME] [--no-open]
  nucleus cloud run [--once] [--inference /absolute/private/fleet.json]
                    [--model-root /absolute/private/models --allow-model-installs]
  nucleus cloud status
  nucleus cloud disconnect [--local]

Connect proves this node's existing key and waits for an organization owner/admin.
Run sends resource measurements over outbound HTTPS. It opens no public listener.
--inference opts this node into leased generation using an operator-pinned local runtime.
Model install/remove additionally require --model-root and --allow-model-installs.
Only exact locally approved model hashes/provenance can be installed; no remote commands run.
--once with inference sends telemetry, handles at most one available job, and exits.
Status shows local registration and the last acknowledged heartbeat, not current online status.
Disconnect revokes the hosted node and removes its local binding.
--local forgets only the local binding; it does not revoke the hosted registration.
`

func cloudCommand(home string, args []string) error {
	return cloudCommandNamed(home, args, "nucleus")
}

func cloudCommandNamed(home string, args []string, product string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(cloudHelp)
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "connect":
		var endpoint, name string
		var noOpen bool
		rest, err := options("cloud connect", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&endpoint, "url", cloud.DefaultURL, "hosted Nucleus dashboard URL")
			f.StringVar(&name, "name", "", "initial node label; existing identity is preserved")
			f.BoolVar(&noOpen, "no-open", false, "print the approval URL without opening a browser")
		})
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return errors.New("unexpected cloud connect arguments")
		}
		if _, err = fabric.Init(home, name); err != nil {
			return err
		}
		client, err := cloud.New(home, endpoint)
		if err != nil {
			return err
		}
		binding, err := client.Connect(ctx, func(notice cloud.EnrollmentNotice) {
			fmt.Printf("Approve this node: %s\nVerification code: %s\nNode fingerprint: %s\n", notice.VerificationURI, notice.UserCode, notice.NodeID)
			if !noOpen {
				openCloudBrowser(notice.VerificationURI)
			}
		})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("Hosted registration approved.\nNode: %s\nOrganization: %s\n", binding.NodeID, binding.OrganizationID)
		fmt.Printf("Telemetry has not started. Run %s, or enable the documented user service.\n", commandName(product, "cloud run"))
		return nil
	case "run":
		var once bool
		var inferenceFile, modelRoot string
		var allowInstalls bool
		rest, err := options("cloud run", args[1:], func(f *flag.FlagSet) {
			f.BoolVar(&once, "once", false, "send telemetry, handle at most one available job, and exit")
			f.StringVar(&inferenceFile, "inference", "", "private local FleetConfig; opt in to hosted generation")
			f.StringVar(&modelRoot, "model-root", "", "dedicated private directory for approved hosted model artifacts")
			f.BoolVar(&allowInstalls, "allow-model-installs", false, "allow exact locally approved model install/remove jobs")
		})
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return errors.New("unexpected cloud run arguments")
		}
		client, err := cloud.FromBinding(home)
		if err != nil {
			return err
		}
		if inferenceFile == "" {
			if modelRoot != "" || allowInstalls {
				return errors.New("model management flags require --inference")
			}
			return client.Run(ctx, once, func(message string) { fmt.Println(message) })
		}
		manager, err := hostedworker.NewManager(ctx, inferenceFile, modelRoot, allowInstalls)
		if err != nil {
			return err
		}
		defer manager.Close()
		worker, err := hostedworker.New(home, client, manager, func(message string) { fmt.Println(message) })
		if err != nil {
			return err
		}
		if err = client.Heartbeat(ctx); err != nil {
			return err
		}
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		telemetryDone := make(chan error, 1)
		workDone := make(chan error, 1)
		go func() { telemetryDone <- client.Run(runCtx, false, func(message string) { fmt.Println(message) }) }()
		go func() { workDone <- worker.Run(runCtx, once) }()
		select {
		case err = <-workDone:
			cancel()
			<-telemetryDone
			return err
		case err = <-telemetryDone:
			cancel()
			<-workDone
			return err
		}
	case "status":
		if len(args) != 1 {
			return fmt.Errorf("usage: %s", commandName(product, "cloud status"))
		}
		binding, err := cloud.LoadBinding(home)
		if errors.Is(err, cloud.ErrNotRegistered) {
			return printJSON(map[string]any{"schema_version": 1, "registered": false})
		}
		if err != nil {
			return err
		}
		return printJSON(map[string]any{
			"schema_version": 1, "registered": true, "revoked": binding.Revoked,
			"origin": binding.Origin, "node_id": binding.NodeID, "organization_id": binding.OrganizationID,
			"registered_at": binding.RegisteredAt, "last_acknowledged_heartbeat_at": binding.LastHeartbeatAt,
			"note": "Saved local registration is not proof of current connectivity. The hosted dashboard uses server receipt time.",
		})
	case "disconnect":
		var localOnly bool
		rest, err := options("cloud disconnect", args[1:], func(f *flag.FlagSet) {
			f.BoolVar(&localOnly, "local", false, "forget local binding without revoking the hosted registration")
		})
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return errors.New("unexpected cloud disconnect arguments")
		}
		client, err := cloud.FromBinding(home)
		if err != nil {
			return err
		}
		if err = client.Disconnect(ctx, localOnly); err != nil {
			return err
		}
		if localOnly {
			fmt.Println("Local hosted binding removed. The hosted registration was not revoked.")
		} else {
			fmt.Println("Hosted registration revoked or already revoked. Local binding removed.")
		}
		return nil
	default:
		return errors.New("unknown cloud command; see nucleus cloud help")
	}
}

func openCloudBrowser(uri string) {
	for _, name := range []string{"wslview", "xdg-open", "chromium", "chromium-browser", "google-chrome"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		command := exec.Command(path, uri)
		if command.Start() == nil {
			go command.Wait()
			return
		}
	}
}
