package inventory

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCPUDetailsUseCommonInstructionsAndPhysicalTopology(t *testing.T) {
	text := "processor: 0\nphysical id: 0\ncore id: 0\nmodel name: Example CPU\nflags: sse avx avx2\n\n" +
		"processor: 1\nphysical id: 0\ncore id: 0\nflags: sse avx\n\n" +
		"processor: 2\nphysical id: 1\ncore id: 0\nflags: sse avx avx512f\n"
	model, physical, instructions := parseCPUInfo(text)
	if model != "Example CPU" || physical != 2 || !reflect.DeepEqual(instructions, []string{"avx", "sse"}) {
		t.Fatalf("unsafe or incomplete CPU capabilities: %q %d %v", model, physical, instructions)
	}
	model, physical, instructions = parseCPUInfo("Processor: ARMv8\nFeatures: fp asimd aes\n")
	if model != "ARMv8" || physical != 0 || !reflect.DeepEqual(instructions, []string{"aes", "asimd", "fp"}) {
		t.Fatalf("ARM discovery failed: %q %d %v", model, physical, instructions)
	}
}

func putHardwareFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func resourceFixture() Snapshot {
	return Snapshot{
		CPU:    CPU{LogicalCores: 8, EffectiveCores: 8},
		Memory: Memory{TotalBytes: 10000, AvailableBytes: 8000, UsedBytes: 2000, EffectiveTotalBytes: 10000, EffectiveAvailableBytes: 8000},
	}
}

func TestCgroupV2BoundsMemoryAndCPUByAllAncestors(t *testing.T) {
	root := t.TempDir()
	putHardwareFile(t, root, "memory.max", "max")
	putHardwareFile(t, root, "fleet/memory.max", "6000")
	putHardwareFile(t, root, "fleet/memory.current", "5500")
	putHardwareFile(t, root, "fleet/cpu.max", "150000 100000")
	putHardwareFile(t, root, "fleet/worker/memory.max", "4000")
	putHardwareFile(t, root, "fleet/worker/memory.current", "1000")
	putHardwareFile(t, root, "fleet/worker/cpu.max", "max 100000")
	putHardwareFile(t, root, "fleet/worker/cpuset.cpus.effective", "0-1,4")
	sample := resourceFixture()
	applyCgroupLimits(&sample, root, "0::/fleet/worker\n")
	if sample.CPU.EffectiveCores != 1.5 || sample.Memory.EffectiveTotalBytes != 4000 || sample.Memory.EffectiveAvailableBytes != 500 {
		t.Fatalf("constraints escaped: %+v %+v", sample.CPU, sample.Memory)
	}
	if sample.CPU.LogicalCores != 8 || sample.Memory.TotalBytes != 10000 || sample.Memory.AvailableBytes != 8000 {
		t.Fatal("host measurements changed")
	}
	putHardwareFile(t, root, "fleet/memory.current", "7000")
	sample = resourceFixture()
	applyCgroupLimits(&sample, root, "0::/fleet/worker\n")
	if sample.Memory.EffectiveAvailableBytes != 0 {
		t.Fatal("exhausted parent memory advertised as available")
	}
}

func TestCgroupV1AndMissingCounters(t *testing.T) {
	root := t.TempDir()
	putHardwareFile(t, root, "memory/work/memory.limit_in_bytes", "3500")
	putHardwareFile(t, root, "memory/work/memory.usage_in_bytes", "1000")
	putHardwareFile(t, root, "cpu,cpuacct/work/cpu.cfs_quota_us", "50000")
	putHardwareFile(t, root, "cpu,cpuacct/work/cpu.cfs_period_us", "100000")
	putHardwareFile(t, root, "cpuset/work/cpuset.cpus", "2-3")
	sample := resourceFixture()
	applyCgroupLimits(&sample, root, "3:memory:/work\n2:cpu,cpuacct:/work\n1:cpuset:/work\n")
	if sample.CPU.EffectiveCores != .5 || sample.Memory.EffectiveTotalBytes != 3500 || sample.Memory.EffectiveAvailableBytes != 2500 {
		t.Fatalf("v1 constraints missing: %+v %+v", sample.CPU, sample.Memory)
	}
	sample = resourceFixture()
	applyCgroupLimits(&sample, t.TempDir(), "0::/missing\nmalformed\n")
	if sample.CPU.EffectiveCores != 8 || sample.Memory.EffectiveAvailableBytes != 8000 {
		t.Fatal("missing constraints damaged host inventory")
	}
}

func TestPCIAcceleratorDiscoveryDoesNotClaimRuntimeSupport(t *testing.T) {
	root := t.TempDir()
	putHardwareFile(t, root, "0000:01:00.0/class", "0x030200")
	putHardwareFile(t, root, "0000:01:00.0/vendor", "0x10de")
	putHardwareFile(t, root, "0000:01:00.0/device", "0x1234")
	putHardwareFile(t, root, "0000:02:00.0/class", "0x120000")
	putHardwareFile(t, root, "0000:03:00.0/class", "0x020000")
	gpu := discoverAccelerators(root, filepath.Join(root, "absent"))
	if gpu.Status != "detected" || len(gpu.Devices) != 2 || gpu.Devices[0].VendorID != "0x10de" {
		t.Fatalf("discovered wrong devices: %+v", gpu)
	}
}

func TestHardwareValidationRejectsInvalidLimitsAndMetadata(t *testing.T) {
	cases := []func(*Snapshot){
		func(s *Snapshot) { s.CPU.EffectiveCores = math.NaN() },
		func(s *Snapshot) { s.CPU.EffectiveCores = 9 },
		func(s *Snapshot) { s.CPU.PhysicalCores = 9 },
		func(s *Snapshot) { s.CPU.Instructions = []string{"avx\nforged"} },
		func(s *Snapshot) { s.Memory.EffectiveAvailableBytes = 9000 },
		func(s *Snapshot) { s.Memory.EffectiveTotalBytes = 11000 },
		func(s *Snapshot) { s.GPU.Devices = []Accelerator{{Address: "pci\x00forged"}} },
	}
	for _, mutate := range cases {
		sample := resourceFixture()
		mutate(&sample)
		if validateHardware(sample) == nil {
			t.Fatal("unsafe capability metadata accepted")
		}
	}
	// Schema v1 peers need not send optional inference capabilities.
	if err := validateHardware(Snapshot{CPU: CPU{LogicalCores: 2}, Memory: Memory{TotalBytes: 1000, AvailableBytes: 500}}); err != nil {
		t.Fatalf("legacy schema rejected: %v", err)
	}
}
