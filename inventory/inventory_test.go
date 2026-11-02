package inventory

import (
	"math"
	"testing"
)

func TestSnapshotAndValidation(t *testing.T) {
	sample, err := new(Monitor).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if sample.CPU.LogicalCores == 0 || sample.Memory.TotalBytes == 0 {
		t.Fatal("measurements missing")
	}
	original := sample.Memory
	sample.Memory = Memory{TotalBytes: math.MaxUint64, AvailableBytes: math.MaxUint64, UsedBytes: math.MaxUint64}
	if Validate(sample) == nil {
		t.Fatal("overflowing inconsistent memory accepted")
	}
	sample.Memory = original
	invalid := 101.0
	sample.CPU.UsagePercent = &invalid
	if Validate(sample) == nil {
		t.Fatal("invalid CPU utilization accepted")
	}
}
