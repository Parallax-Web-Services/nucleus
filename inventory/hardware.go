package inventory

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Accelerator reports discovered devices only; visibility does not prove that a runtime can use them.
type Accelerator struct {
	Kind     string `json:"kind"`
	Address  string `json:"address"`
	VendorID string `json:"vendor_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Class    string `json:"class,omitempty"`
}

func parseCPUInfo(text string) (string, int, []string) {
	model := ""
	physical := map[string]bool{}
	var common map[string]bool
	for _, block := range strings.Split(strings.TrimSpace(text), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, found := strings.Cut(line, ":")
			if found {
				fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
		if model == "" {
			for _, name := range []string{"model name", "Hardware", "Processor"} {
				if fields[name] != "" {
					model = fields[name]
					break
				}
			}
		}
		if core, found := fields["core id"]; found {
			physical[fields["physical id"]+":"+core] = true
		}
		flags, found := fields["flags"]
		if !found {
			flags, found = fields["Features"]
		}
		if found {
			current := map[string]bool{}
			for _, flag := range strings.Fields(flags) {
				current[flag] = true
			}
			if common == nil {
				common = current
			} else {
				for flag := range common {
					if !current[flag] {
						delete(common, flag)
					}
				}
			}
		}
	}
	instructions := make([]string, 0, len(common))
	for flag := range common {
		instructions = append(instructions, flag)
	}
	sort.Strings(instructions)
	return model, len(physical), instructions
}

// applyCgroupLimits preserves host measurements and adds conservative usable capacity.
// Ancestor constraints matter: a worker may share its parent's memory and CPU quota.
func applyCgroupLimits(s *Snapshot, root, membership string) {
	for _, line := range strings.Split(membership, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		relative := strings.TrimPrefix(filepath.Clean("/"+parts[2]), "/")
		if parts[0] == "0" && parts[1] == "" {
			for _, dir := range cgroupAncestors(root, relative) {
				applyMemoryLimit(s, readText(filepath.Join(dir, "memory.max")), readText(filepath.Join(dir, "memory.current")))
				quota := strings.Fields(readText(filepath.Join(dir, "cpu.max")))
				if len(quota) == 2 {
					applyCPUQuota(s, quota[0], quota[1])
				}
				applyCPUSet(s, readText(filepath.Join(dir, "cpuset.cpus.effective")))
			}
			continue
		}
		for _, controller := range strings.Split(parts[1], ",") {
			base := filepath.Join(root, controller)
			if controller == "cpu" && !directoryExists(base) {
				base = filepath.Join(root, "cpu,cpuacct")
			}
			for _, dir := range cgroupAncestors(base, relative) {
				switch controller {
				case "memory":
					applyMemoryLimit(s, readText(filepath.Join(dir, "memory.limit_in_bytes")), readText(filepath.Join(dir, "memory.usage_in_bytes")))
				case "cpu":
					applyCPUQuota(s, readText(filepath.Join(dir, "cpu.cfs_quota_us")), readText(filepath.Join(dir, "cpu.cfs_period_us")))
				case "cpuset":
					set := readText(filepath.Join(dir, "cpuset.effective_cpus"))
					if set == "" {
						set = readText(filepath.Join(dir, "cpuset.cpus"))
					}
					applyCPUSet(s, set)
				}
			}
		}
	}
}

func cgroupAncestors(root, relative string) []string {
	root = filepath.Clean(root)
	dir := filepath.Join(root, relative)
	var result []string
	for {
		result = append(result, dir)
		if dir == root {
			return result
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return result
		}
		dir = parent
	}
}

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func applyMemoryLimit(s *Snapshot, rawLimit, rawUsage string) {
	limit, err := strconv.ParseUint(rawLimit, 10, 64)
	if err != nil || limit == 0 {
		return
	}
	if limit < s.Memory.EffectiveTotalBytes {
		s.Memory.EffectiveTotalBytes = limit
	}
	remaining := limit
	if usage, err := strconv.ParseUint(rawUsage, 10, 64); err == nil {
		if usage >= limit {
			remaining = 0
		} else {
			remaining = limit - usage
		}
	}
	if remaining < s.Memory.EffectiveAvailableBytes {
		s.Memory.EffectiveAvailableBytes = remaining
	}
	if s.Memory.EffectiveAvailableBytes > s.Memory.EffectiveTotalBytes {
		s.Memory.EffectiveAvailableBytes = s.Memory.EffectiveTotalBytes
	}
}

func applyCPUQuota(s *Snapshot, rawQuota, rawPeriod string) {
	quota, e1 := strconv.ParseUint(rawQuota, 10, 64)
	period, e2 := strconv.ParseUint(rawPeriod, 10, 64)
	if e1 != nil || e2 != nil || quota == 0 || period == 0 {
		return
	}
	cores := float64(quota) / float64(period)
	if cores < s.CPU.EffectiveCores {
		s.CPU.EffectiveCores = cores
	}
}

func applyCPUSet(s *Snapshot, text string) {
	if text == "" {
		return
	}
	cores := 0
	for _, part := range strings.Split(text, ",") {
		span := strings.Split(part, "-")
		if len(span) > 2 {
			return
		}
		first, err := strconv.Atoi(span[0])
		if err != nil || first < 0 || first > 1_048_575 {
			return
		}
		last := first
		if len(span) == 2 {
			last, err = strconv.Atoi(span[1])
			if err != nil || last < first || last > 1_048_575 {
				return
			}
		}
		cores += last - first + 1
	}
	if cores > 0 && float64(cores) < s.CPU.EffectiveCores {
		s.CPU.EffectiveCores = float64(cores)
	}
}

func discoverAccelerators(pciRoot, dxgPath string) GPU {
	result := GPU{Status: "none_detected", Note: "No PCI accelerator or WSL GPU interface detected; runtime support is unverified."}
	entries, err := os.ReadDir(pciRoot)
	if err == nil {
		for _, entry := range entries {
			dir := filepath.Join(pciRoot, entry.Name())
			class := readText(filepath.Join(dir, "class"))
			if !strings.HasPrefix(class, "0x03") && !strings.HasPrefix(class, "0x12") {
				continue
			}
			result.Devices = append(result.Devices, Accelerator{
				Kind: "pci", Address: entry.Name(), Class: class,
				VendorID: readText(filepath.Join(dir, "vendor")),
				DeviceID: readText(filepath.Join(dir, "device")),
			})
			if len(result.Devices) >= 128 {
				break
			}
		}
	}
	if _, err := os.Stat(dxgPath); err == nil && len(result.Devices) < 128 {
		result.Devices = append(result.Devices, Accelerator{Kind: "wsl_dxg", Address: dxgPath})
	}
	if len(result.Devices) > 0 {
		result.Status = "detected"
		result.Note = "Device visibility detected; driver support, usable memory, and inference compatibility are unverified."
	}
	return result
}

func validateHardware(s Snapshot) error {
	validText := func(value string, limit int) bool {
		return len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
	}
	if !validText(s.CPU.Architecture, 32) || !validText(s.CPU.Model, 256) ||
		s.CPU.PhysicalCores < 0 || s.CPU.PhysicalCores > s.CPU.LogicalCores ||
		math.IsNaN(s.CPU.EffectiveCores) || math.IsInf(s.CPU.EffectiveCores, 0) ||
		s.CPU.EffectiveCores < 0 || s.CPU.EffectiveCores > float64(s.CPU.LogicalCores) ||
		len(s.CPU.Instructions) > 512 {
		return errors.New("invalid CPU capability metadata")
	}
	for _, instruction := range s.CPU.Instructions {
		if instruction == "" || !validText(instruction, 64) || strings.ContainsAny(instruction, " \t") {
			return errors.New("invalid CPU instruction metadata")
		}
	}
	if s.Memory.EffectiveTotalBytes > s.Memory.TotalBytes ||
		s.Memory.EffectiveAvailableBytes > s.Memory.EffectiveTotalBytes ||
		s.Memory.EffectiveAvailableBytes > s.Memory.AvailableBytes {
		return errors.New("inconsistent effective memory inventory")
	}
	if len(s.GPU.Devices) > 128 {
		return errors.New("too many accelerator devices")
	}
	for _, device := range s.GPU.Devices {
		if !validText(device.Kind, 32) || !validText(device.Address, 256) ||
			!validText(device.VendorID, 32) || !validText(device.DeviceID, 32) || !validText(device.Class, 32) {
			return errors.New("invalid accelerator metadata")
		}
	}
	return nil
}
