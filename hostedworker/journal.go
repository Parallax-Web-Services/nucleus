// Package hostedworker executes explicitly opted-in, leased outbound cloud work.
// It exposes no node listener and accepts no remotely supplied command or binary.
package hostedworker

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type journal struct {
	file *os.File
	lock *os.File
	seen map[string]bool
}
type journalEntry struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

func openJournal(home, namespace string) (*journal, error) {
	descriptor, err := syscall.Open(filepath.Join(home, "hosted-worker.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open private worker lock")
	}
	lock := os.NewFile(uintptr(descriptor), "hosted-worker.lock")
	cleanup := func() { lock.Close() }
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		cleanup()
		return nil, errors.New("worker lock must be regular")
	}
	if err = lock.Chmod(0600); err != nil {
		cleanup()
		return nil, err
	}
	if err = syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		cleanup()
		return nil, errors.New("another hosted worker is already running for this node")
	}
	hash := sha256.Sum256([]byte(namespace))
	name := "hosted-work-" + hex.EncodeToString(hash[:]) + ".jsonl"
	fd, err := syscall.Open(filepath.Join(home, name), syscall.O_RDWR|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		cleanup()
		return nil, errors.New("cannot open private work journal")
	}
	file := os.NewFile(uintptr(fd), name)
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16<<20 {
		file.Close()
		cleanup()
		return nil, errors.New("worker journal must be private, regular, and at most16MiB")
	}
	j := &journal{file: file, lock: lock, seen: map[string]bool{}}
	scanner := bufio.NewScanner(io.LimitReader(file, 16<<20+1))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		var entry journalEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.ID == "" {
			j.Close()
			return nil, errors.New("worker journal is malformed; automatic replay is disabled")
		}
		j.seen[entry.ID] = true
	}
	if scanner.Err() != nil {
		j.Close()
		return nil, errors.New("cannot read worker replay journal")
	}
	return j, nil
}
func (j *journal) record(id, state string) error {
	info, err := j.file.Stat()
	if err != nil || info.Size() > 16<<20-4096 {
		return errors.New("worker journal is full; refusing unjournaled execution")
	}
	raw, err := json.Marshal(journalEntry{id, state})
	if err != nil {
		return err
	}
	if _, err = j.file.Write(append(raw, '\n')); err != nil {
		return errors.New("cannot persist worker replay guard")
	}
	if err = j.file.Sync(); err != nil {
		return errors.New("cannot sync worker replay guard")
	}
	j.seen[id] = true
	return nil
}
func (j *journal) begin(id string) error {
	if j.seen[id] {
		return ErrJobReplay
	}
	return j.record(id, "started")
}
func (j *journal) Close() error {
	if j.file != nil {
		j.file.Close()
	}
	if j.lock != nil {
		syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN)
		return j.lock.Close()
	}
	return nil
}
