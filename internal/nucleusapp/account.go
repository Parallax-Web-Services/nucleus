package nucleusapp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/positronic"
)

const accountHelp = `Connect an existing Nucleus cluster to your Parallax account

  nucleus account connect --url https://YOUR_PARALLAX --code CONNECTION_CODE
  nucleus account status
  nucleus account report [--once]
  nucleus account disconnect

Create a connection code under Clusters in your signed-in Parallax account.
Run connect on the existing fabric owner/coordinator using the same NUCLEUS_HOME.
Compare and approve the printed fingerprint in Parallax. No private keys leave
this machine. Account reports contain inventory, never workload execution rights.
Run account report alongside the existing coordinator, or restart nucleus run
with its existing options to report automatically. Disconnect removes the local
binding only; disconnect in Parallax to revoke reports on the account side.
`

func accountCommand(home string, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Print(accountHelp)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "connect":
		var origin, code string
		rest, err := options("account connect", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&origin, "url", "", "signed-in Parallax origin")
			f.StringVar(&code, "code", "", "short-lived account connection code")
		})
		if err != nil {
			return err
		}
		if len(rest) != 0 || origin == "" || code == "" {
			return errors.New("usage: nucleus account connect --url ORIGIN --code CODE")
		}
		bounded, stop := context.WithTimeout(ctx, 5*time.Minute)
		defer stop()
		return cloud.ConnectAccount(bounded, home, origin, code, os.Stdout)
	case "status":
		if len(args) != 1 {
			return errors.New("usage: nucleus account status")
		}
		binding, err := cloud.LoadAccountBinding(home)
		if err != nil {
			return err
		}
		return printJSON(binding)
	case "disconnect":
		if len(args) != 1 {
			return errors.New("usage: nucleus account disconnect")
		}
		if err := cloud.DisconnectAccount(home); err != nil {
			return err
		}
		fmt.Println("Local account binding removed. Machines and workloads were not stopped.")
		return nil
	case "report":
		var once bool
		rest, err := options("account report", args[1:], func(f *flag.FlagSet) { f.BoolVar(&once, "once", false, "send one inventory report") })
		if err != nil {
			return err
		}
		if len(rest) != 0 {
			return errors.New("usage: nucleus account report [--once]")
		}
		if _, err := cloud.LoadAccountBinding(home); err != nil {
			return err
		}
		for {
			view, err := positronic.ReadView(ctx, home)
			if err == nil {
				err = cloud.ReportAccount(ctx, home, view)
			}
			if once {
				return err
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "Parallax inventory:", err)
			} else {
				fmt.Println("Parallax inventory reported.")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(15 * time.Second):
			}
		}
	default:
		return errors.New("unknown account command; see nucleus account help")
	}
}

func startAccountReporting(ctx context.Context, home string, view func() (positronic.View, error)) {
	if _, err := cloud.LoadAccountBinding(home); err != nil {
		if !errors.Is(err, cloud.ErrAccountNotConnected) {
			fmt.Fprintln(os.Stderr, "Parallax account binding:", err)
		}
		return
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			snapshot, err := view()
			if err == nil {
				err = cloud.ReportAccount(ctx, home, snapshot)
			}
			if errors.Is(err, cloud.ErrAccountNotConnected) {
				return
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "Parallax inventory report:", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
