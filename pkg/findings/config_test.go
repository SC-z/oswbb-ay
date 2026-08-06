package findings

import (
	"oswbb-analyse/internal/config"
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
	"testing"
	"time"
)

func TestBuildIOStatFindingsWithConfigCanRaiseCPUWaitThreshold(t *testing.T) {
	start := time.Date(2026, 4, 21, 3, 0, 0, 0, time.UTC)
	log := &iostat.IOStatLog{Data: []iostat.IOStatData{
		{Timestamp: start, CPU: iostat.CPUStats{IOWait: 12}, Devices: []iostat.DeviceStats{{Device: "nvme0n1", WriteReqPerSec: 20, WriteAwait: 1}}},
		{Timestamp: start.Add(5 * time.Second), CPU: iostat.CPUStats{IOWait: 12}, Devices: []iostat.DeviceStats{{Device: "nvme0n1", WriteReqPerSec: 20, WriteAwait: 1}}},
	}}

	if !hasRule(BuildIOStatFindings(log, start, start.Add(5*time.Second)), "iostat-cpu-iowait") {
		t.Fatalf("default thresholds should report iowait")
	}
	cfg := config.Default().Iostat
	cfg.CPUWaitSoftPct = 50
	cfg.CPUWaitHardPct = 80
	if hasRule(BuildIOStatFindingsWithConfig(log, start, start.Add(5*time.Second), cfg), "iostat-cpu-iowait") {
		t.Fatalf("custom iowait thresholds should suppress finding")
	}
}

func TestBuildMemInfoFindingsWithConfigCanRaiseAvailableThreshold(t *testing.T) {
	start := time.Date(2026, 4, 21, 3, 0, 0, 0, time.UTC)
	log := &meminfo.MemInfoLog{Data: []meminfo.MemStatData{{
		Timestamp: start,
		MemStats: meminfo.MemStats{
			MemTotal:     100 * 1024 * 1024,
			MemAvailable: 35 * 1024 * 1024,
		},
	}}}

	if hasRule(BuildMemInfoFindings(log, start, start), "meminfo-available") {
		t.Fatalf("default thresholds should not report 35%% available")
	}
	cfg := config.Default().Meminfo
	cfg.AvailableSoftPct = 40
	cfg.AvailableWarnPct = 35
	cfg.AvailableSeverePct = 10
	if !hasRule(BuildMemInfoFindingsWithConfig(log, start, start, cfg), "meminfo-available") {
		t.Fatalf("custom available threshold should report finding")
	}
}

func TestBuildTopFindingsWithConfigCanRaiseLoadThreshold(t *testing.T) {
	start := time.Date(2026, 4, 21, 3, 0, 0, 0, time.UTC)
	log := &top.TopLog{Snapshots: []top.TopSnapshot{
		{Timestamp: start, Load1: 8, CPUCount: 8, TaskRunning: 8, CpuIdle: 10},
		{Timestamp: start.Add(5 * time.Second), Load1: 8, CPUCount: 8, TaskRunning: 8, CpuIdle: 10},
	}}

	if !hasRule(BuildTopFindings(log, start, start.Add(5*time.Second)), "top-load-high") {
		t.Fatalf("default thresholds should report load")
	}
	cfg := config.Default().Top
	cfg.LoadPerCPUSoft = 2
	cfg.LoadPerCPUHard = 3
	if hasRule(BuildTopFindingsWithConfig(log, start, start.Add(5*time.Second), cfg), "top-load-high") {
		t.Fatalf("custom load thresholds should suppress finding")
	}
}

func hasRule(items []Finding, ruleID string) bool {
	for _, item := range items {
		if item.RuleID == ruleID {
			return true
		}
	}
	return false
}
