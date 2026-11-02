// Package cloud connects a local node to the hosted Nucleus service.
// It does not expose the local dashboard or change private-fabric membership.
package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
)

var ErrNotRegistered = errors.New("no hosted registration; run nucleus cloud connect")

type Binding struct {
	SchemaVersion            int        `json:"schema_version"`
	Origin                   string     `json:"origin"`
	BasePath                 string     `json:"base_path"`
	NodeID                   string     `json:"node_id"`
	OrganizationID           string     `json:"organization_id"`
	HeartbeatIntervalSeconds int        `json:"heartbeat_interval_seconds"`
	RegisteredAt             time.Time  `json:"registered_at"`
	LastHeartbeatAt          *time.Time `json:"last_heartbeat_at,omitempty"`
	Revoked                  bool       `json:"revoked"`
}

// LoadBinding describes saved registration, not current server-side liveness.
func LoadBinding(home string) (*Binding, error) {
	var binding *Binding
	err := withStateLock(home, func() error {
		var err error
		binding, err = readBinding(home)
		return err
	})
	return binding, err
}

func withStateLock(home string, fn func() error) error {
	if _, _, err := fabric.CloudIdentity(home); err != nil {
		return err
	}
	fd, err := syscall.Open(filepath.Join(home, "cloud.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("cannot open private cloud state lock")
	}
	file := os.NewFile(uintptr(fd), "cloud.lock")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("cloud state lock must be a regular file")
	}
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}

func readBinding(home string) (*Binding, error) {
	fd, err := syscall.Open(filepath.Join(home, "cloud.json"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, ErrNotRegistered
	}
	if err != nil {
		return nil, errors.New("cannot read private cloud registration")
	}
	file := os.NewFile(uintptr(fd), "cloud.json")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("cloud registration must be a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(data) > 16384 {
		return nil, errors.New("cloud registration exceeds its size limit")
	}
	var binding Binding
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&binding); err != nil {
		return nil, errors.New("invalid cloud registration")
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("unexpected cloud registration data")
	}
	state, _, err := fabric.CloudIdentity(home)
	if err != nil {
		return nil, err
	}
	if binding.SchemaVersion != 1 || binding.NodeID != state.NodeID || binding.OrganizationID == "" ||
		binding.BasePath != "/dashboard" || binding.HeartbeatIntervalSeconds < 5 || binding.HeartbeatIntervalSeconds > 3600 {
		return nil, errors.New("cloud registration does not match this node")
	}
	base, err := parseBase(binding.Origin + binding.BasePath)
	if err != nil || base.origin != binding.Origin {
		return nil, errors.New("invalid cloud service origin")
	}
	return &binding, nil
}

func saveBinding(home string, binding *Binding, newOnly bool) error {
	return withStateLock(home, func() error {
		existing, err := readBinding(home)
		if newOnly {
			if err == nil {
				return errors.New("hosted registration already exists; disconnect it before enrolling again")
			}
			if !errors.Is(err, ErrNotRegistered) {
				return err
			}
		} else if err != nil {
			return err
		} else if existing.NodeID != binding.NodeID || existing.Origin != binding.Origin || existing.OrganizationID != binding.OrganizationID {
			return errors.New("hosted registration changed while the request was running")
		}
		data, err := json.MarshalIndent(binding, "", "  ")
		if err != nil {
			return err
		}
		file, err := os.CreateTemp(home, ".cloud-state-")
		if err != nil {
			return errors.New("cannot create private cloud registration")
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(append(data, '\n'))
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return errors.New("cannot save private cloud registration")
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.Rename(temporary, filepath.Join(home, "cloud.json")); err != nil {
			return err
		}
		return syncDirectory(home)
	})
}

func forgetBinding(home string, expected *Binding) error {
	return withStateLock(home, func() error {
		current, err := readBinding(home)
		if errors.Is(err, ErrNotRegistered) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Origin != expected.Origin || current.NodeID != expected.NodeID || current.OrganizationID != expected.OrganizationID {
			return fmt.Errorf("hosted registration changed; local state was preserved")
		}
		if err = os.Remove(filepath.Join(home, "cloud.json")); err != nil {
			return err
		}
		return syncDirectory(home)
	})
}

func syncDirectory(home string) error {
	dir, err := os.Open(home)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
