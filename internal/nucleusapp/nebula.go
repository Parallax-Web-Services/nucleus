package nucleusapp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	"strconv"
	"syscall"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/nebula"
)

func prepareNebula(ctx context.Context, home string, enabled bool) (*nebula.Client, error) {
	if !enabled {
		return nil, nil
	}
	source, err := nebula.HostedCapabilitySource(home)
	if err != nil {
		return nil, err
	}
	return nebula.NewClient(ctx, nebula.ClientConfig{Home: home, Authorize: source})
}
func nebulaDialer(client *nebula.Client, state *fabric.State) func(context.Context, string, string) (net.Conn, error) {
	if client == nil {
		return nil
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		expected, err := url.Parse(state.Endpoint)
		if err != nil || network != "tcp" || address != expected.Host {
			return nil, errors.New("NEBULA transport target differs from the paired owner")
		}
		return client.DialPeer(ctx, state.OwnerID)
	}
}
func nebulaCommand(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("nucleus nebula relay --issuer-public-key-file /absolute/public-key --listen 127.0.0.1:8743")
		fmt.Println("Paired owners and members opt in with: nucleus run --nebula")
		return nil
	}
	if args[0] != "relay" {
		return errors.New("unknown NEBULA command")
	}
	var listen, publicKeyFile string
	rest, err := options("nebula relay", args[1:], func(f *flag.FlagSet) {
		f.StringVar(&listen, "listen", "127.0.0.1:8743", "relay loopback listener, behind owned HTTPS ingress")
		f.StringVar(&publicKeyFile, "issuer-public-key-file", "", "absolute public issuer key file (raw32 or base64url)")
	})
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("unexpected NEBULA relay arguments")
	}
	host, port, err := net.SplitHostPort(listen)
	number, portErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || portErr != nil || number < 1 || number > 65535 {
		return errors.New("NEBULA relay requires explicit 127.0.0.1:PORT")
	}
	key, err := readNebulaPublicKey(publicKeyFile)
	if err != nil {
		return err
	}
	relay, err := nebula.NewRelay(nebula.RelayConfig{IssuerPublicKey: key})
	if err != nil {
		return err
	}
	defer relay.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: listen, Handler: relay, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		_ = relay.Close()
		timeout, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = server.Shutdown(timeout)
	}()
	fmt.Println("NEBULA relay: loopback listener " + listen + "; capability authorization and opaque inner TLS")
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
func readNebulaPublicKey(path string) (ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute NEBULA public key file required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("NEBULA public key unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 512 {
		return nil, errors.New("NEBULA public key file must be a protected regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil {
		return nil, errors.New("NEBULA public key unavailable")
	}
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(bytesTrim(data)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("NEBULA public key must contain32rawbytes or unpadded base64url")
	}
	return ed25519.PublicKey(decoded), nil
}
func bytesTrim(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	return data
}
