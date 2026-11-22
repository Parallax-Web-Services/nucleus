// Package inventory collects read-only Linux/WSL measurements, not scheduled capacity.
package inventory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Node struct {
	Name            string  `json:"name"`
	OperatingSystem string  `json:"operating_system"`
	IsWSL           bool    `json:"is_wsl"`
	UptimeSeconds   *uint64 `json:"uptime_seconds"`
}
type CPU struct {
	LogicalCores   int      `json:"logical_cores"`
	UsagePercent   *float64 `json:"usage_percent"`
	LoadOneMinute  *float64 `json:"load_one_minute"`
	Architecture   string   `json:"architecture,omitempty"`
	Model          string   `json:"model,omitempty"`
	PhysicalCores  int      `json:"physical_cores,omitempty"`
	Instructions   []string `json:"instructions,omitempty"`
	EffectiveCores float64  `json:"effective_cores,omitempty"`
}
type Memory struct {
	TotalBytes              uint64 `json:"total_bytes"`
	AvailableBytes          uint64 `json:"available_bytes"`
	UsedBytes               uint64 `json:"used_bytes"`
	EffectiveTotalBytes     uint64 `json:"effective_total_bytes,omitempty"`
	EffectiveAvailableBytes uint64 `json:"effective_available_bytes,omitempty"`
}
type Storage struct {
	Mount          string `json:"mount"`
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
}
type NetworkInterface struct {
	Name      string `json:"name"`
	LinkState string `json:"link_state"`
}
type GPU struct {
	Status  string        `json:"status"`
	Note    string        `json:"note"`
	Devices []Accelerator `json:"devices,omitempty"`
}
type Snapshot struct {
	SchemaVersion int                `json:"schema_version"`
	CollectedAtMS int64              `json:"collected_at_ms"`
	Node          Node               `json:"node"`
	CPU           CPU                `json:"cpu"`
	Memory        Memory             `json:"memory"`
	Storage       *Storage           `json:"storage"`
	Network       []NetworkInterface `json:"network"`
	GPU           GPU                `json:"gpu"`
}
type Monitor struct {
	mu          sync.Mutex
	total, idle uint64
	sampled     bool
}

func (m *Monitor) Snapshot() (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return Snapshot{}, errors.New("resource measurements require Linux, WSL2, or Android")
	}
	host, err := os.Hostname()
	if err != nil {
		return Snapshot{}, err
	}
	result := Snapshot{SchemaVersion: 1, CollectedAtMS: time.Now().UnixMilli(), Node: Node{Name: host, OperatingSystem: runtime.GOOS}, CPU: CPU{LogicalCores: runtime.NumCPU(), Architecture: runtime.GOARCH}, Network: []NetworkInterface{}}
	if text, e := os.ReadFile("/proc/cpuinfo"); e == nil {
		result.CPU.Model, result.CPU.PhysicalCores, result.CPU.Instructions = parseCPUInfo(string(text))
		if result.CPU.PhysicalCores > result.CPU.LogicalCores {
			result.CPU.PhysicalCores = result.CPU.LogicalCores
		}
	}
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	result.Node.IsWSL = strings.Contains(strings.ToLower(string(kernel)), "microsoft")
	if text, e := os.ReadFile("/proc/uptime"); e == nil {
		fields := strings.Fields(string(text))
		if len(fields) > 0 {
			if n, e := strconv.ParseFloat(fields[0], 64); e == nil && n >= 0 {
				v := uint64(n)
				result.Node.UptimeSeconds = &v
			}
		}
	}
	if text, e := os.ReadFile("/proc/loadavg"); e == nil {
		fields := strings.Fields(string(text))
		if len(fields) > 0 {
			if n, e := strconv.ParseFloat(fields[0], 64); e == nil {
				result.CPU.LoadOneMinute = &n
			}
		}
	}
	text, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return Snapshot{}, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(text)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		n, e := strconv.ParseUint(fields[1], 10, 64)
		if e != nil || n > math.MaxUint64/1024 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			result.Memory.TotalBytes = n * 1024
		case "MemAvailable:":
			result.Memory.AvailableBytes = n * 1024
		}
	}
	if result.Memory.AvailableBytes > result.Memory.TotalBytes {
		return Snapshot{}, errors.New("inconsistent local memory counters")
	}
	result.Memory.UsedBytes = result.Memory.TotalBytes - result.Memory.AvailableBytes
	result.CPU.EffectiveCores = float64(result.CPU.LogicalCores)
	result.Memory.EffectiveTotalBytes = result.Memory.TotalBytes
	result.Memory.EffectiveAvailableBytes = result.Memory.AvailableBytes
	if membership, e := os.ReadFile("/proc/self/cgroup"); e == nil {
		applyCgroupLimits(&result, "/sys/fs/cgroup", string(membership))
	}
	result.GPU = discoverAccelerators("/sys/bus/pci/devices", "/dev/dxg")
	if text, e := os.ReadFile("/proc/stat"); e == nil {
		fields := strings.Fields(strings.SplitN(string(text), "\n", 2)[0])
		if len(fields) >= 5 {
			var total, idle uint64
			for i, f := range fields[1:] {
				if i >= 8 {
					break
				}
				v, e := strconv.ParseUint(f, 10, 64)
				if e == nil {
					total += v
					if i == 3 || i == 4 {
						idle += v
					}
				}
			}
			if m.sampled && total > m.total && idle >= m.idle {
				dt, di := total-m.total, idle-m.idle
				if di <= dt {
					p := 100 * float64(dt-di) / float64(dt)
					result.CPU.UsagePercent = &p
				}
			}
			m.total, m.idle, m.sampled = total, idle, true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	mount := "/"
	if runtime.GOOS == "android" {
		// Models and application data reside on the writable data volume.
		mount = "/data"
	}
	command := exec.CommandContext(ctx, "df", "-Pk", mount)
	command.Env = append(os.Environ(), "LC_ALL=C")
	if out, e := command.Output(); e == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[len(lines)-1])
			if len(fields) >= 6 {
				total, e1 := strconv.ParseUint(fields[1], 10, 64)
				available, e2 := strconv.ParseUint(fields[3], 10, 64)
				if e1 == nil && e2 == nil && total >= available && total <= math.MaxUint64/1024 {
					result.Storage = &Storage{Mount: mount, TotalBytes: total * 1024, AvailableBytes: available * 1024, UsedBytes: (total - available) * 1024}
				}
			}
		}
	}
	if entries, e := os.ReadDir("/sys/class/net"); e == nil {
		for _, entry := range entries {
			if entry.Name() == "lo" {
				continue
			}
			state, _ := os.ReadFile(filepath.Join("/sys/class/net", entry.Name(), "operstate"))
			result.Network = append(result.Network, NetworkInterface{Name: entry.Name(), LinkState: strings.TrimSpace(string(state))})
		}
	}
	return result, Validate(result)
}
func Validate(s Snapshot) error {
	if s.SchemaVersion != 1 || s.CollectedAtMS <= 0 {
		return errors.New("unsupported resource schema")
	}
	if s.CPU.LogicalCores < 1 || s.CPU.LogicalCores > 1_048_576 {
		return errors.New("invalid CPU count")
	}
	if s.CPU.UsagePercent != nil && (math.IsNaN(*s.CPU.UsagePercent) || math.IsInf(*s.CPU.UsagePercent, 0) || *s.CPU.UsagePercent < 0 || *s.CPU.UsagePercent > 100) {
		return errors.New("invalid CPU utilization")
	}
	if s.CPU.LoadOneMinute != nil && (math.IsNaN(*s.CPU.LoadOneMinute) || math.IsInf(*s.CPU.LoadOneMinute, 0) || *s.CPU.LoadOneMinute < 0) {
		return errors.New("invalid load")
	}
	if s.Memory.TotalBytes == 0 || s.Memory.AvailableBytes > s.Memory.TotalBytes || s.Memory.UsedBytes != s.Memory.TotalBytes-s.Memory.AvailableBytes {
		return errors.New("inconsistent memory inventory")
	}
	if s.Storage != nil && (s.Storage.TotalBytes == 0 || s.Storage.AvailableBytes > s.Storage.TotalBytes || s.Storage.UsedBytes != s.Storage.TotalBytes-s.Storage.AvailableBytes) {
		return errors.New("inconsistent storage inventory")
	}
	if len(s.Node.Name) < 1 || len(s.Node.Name) > 128 || strings.ContainsAny(s.Node.Name, "\r\n\x00") || len(s.Node.OperatingSystem) > 32 {
		return errors.New("invalid node metadata")
	}
	if len(s.Network) > 128 {
		return errors.New("too many network interfaces")
	}
	for _, iface := range s.Network {
		if len(iface.Name) > 64 || len(iface.LinkState) > 32 || strings.ContainsAny(iface.Name+iface.LinkState, "\r\n\x00") {
			return fmt.Errorf("invalid interface metadata")
		}
	}
	if len(s.GPU.Status) > 64 || len(s.GPU.Note) > 256 {
		return errors.New("invalid GPU metadata")
	}
	return validateHardware(s)
}
