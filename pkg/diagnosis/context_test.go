package diagnosis

import (
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildContextCreatesHardSoftAndCrossEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2025, time.January, 1, 10, 0, 0, 0, loc)
	end := start.Add(20 * time.Minute)

	iostatLog := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				CPU:       iostat.CPUStats{IOWait: 12},
				Devices: []iostat.DeviceStats{
					{Device: "sda", ReadAwait: 20, WriteAwait: 25, AvgQueueSize: 0.6, ReadReqPerSec: 120, WriteReqPerSec: 80},
				},
			},
			{
				Timestamp: end,
				CPU:       iostat.CPUStats{IOWait: 28},
				Devices: []iostat.DeviceStats{
					{Device: "sda", ReadAwait: 120, WriteAwait: 140, AvgQueueSize: 1.5, ReadReqPerSec: 180, WriteReqPerSec: 90},
				},
			},
		},
	}
	memLog := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 32 * 1024 * 1024, SwapTotal: 32 * 1024 * 1024, SwapFree: 32 * 1024 * 1024, AnonPages: 12 * 1024 * 1024}},
			{Timestamp: end, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 18 * 1024 * 1024, SwapTotal: 32 * 1024 * 1024, SwapFree: 28 * 1024 * 1024, AnonPages: 13 * 1024 * 1024}},
		},
	}
	topLog := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 5.5, CpuIdle: 18, CpuWait: 15, TaskRunning: 12},
			{Timestamp: end, Load1: 9.2, CpuIdle: 8, CpuWait: 26, TaskRunning: 24},
		},
	}

	context := BuildContext(BuildInput{
		Hostname: "db01",
		Start:    start,
		End:      end,
		IOStat:   iostatLog,
		MemInfo:  memLog,
		Top:      topLog,
	})

	if len(context.Evidence) == 0 {
		t.Fatalf("期望生成 evidence")
	}

	expected := []string{
		"iostat-read-latency-sda",
		"iostat-queue-sda",
		"meminfo-swap-usage",
		"top-cpu-wait",
		"cross-io-contention",
	}
	for _, id := range expected {
		if _, exists := context.EvidenceIDs()[id]; !exists {
			t.Fatalf("缺少预期 evidence: %s", id)
		}
	}
}

func TestTrimEvidencePreservesCrossAndModuleCoverage(t *testing.T) {
	var evidence []Evidence
	for i := 0; i < 24; i++ {
		evidence = append(evidence, Evidence{
			ID:     "iostat-" + strconv.Itoa(i),
			Source: "iostat",
			Level:  SignalLevelHard,
		})
	}
	evidence = append(evidence,
		Evidence{ID: "meminfo-available", Source: "meminfo", Level: SignalLevelHard},
		Evidence{ID: "top-cpu-wait", Source: "top", Level: SignalLevelHard},
		Evidence{ID: "cross-memory-pressure", Source: "cross", Level: SignalLevelHard},
	)

	sortEvidence(evidence)
	trimmed := trimEvidence(evidence, 18)

	if len(trimmed) != 18 {
		t.Fatalf("期望截断后保留 18 条 evidence, got=%d", len(trimmed))
	}

	ids := make(map[string]struct{}, len(trimmed))
	for _, item := range trimmed {
		ids[item.ID] = struct{}{}
	}

	expected := []string{"cross-memory-pressure", "meminfo-available", "top-cpu-wait"}
	for _, id := range expected {
		if _, exists := ids[id]; !exists {
			t.Fatalf("截断后缺少关键 evidence: %s", id)
		}
	}
}

func TestBuildContextAddsMemInfoCommitPressureEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: start,
			MemStats: meminfo.MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemAvailable: 64 * 1024 * 1024,
				CommitLimit:  100 * 1024 * 1024,
				Committed:    105 * 1024 * 1024,
			},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "db01",
		Start:    start,
		End:      start,
		MemInfo:  log,
	})

	evidence, exists := findEvidence(context.Evidence, "meminfo-commit-pressure")
	if !exists {
		t.Fatalf("缺少 Committed_AS 风险 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelHard {
		t.Fatalf("Committed_AS 超过 CommitLimit 应为 hard, got=%s", evidence.Level)
	}
}

func TestBuildContextUsesMemInfoWorstPointEvidenceTime(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024}},
		},
	}

	context := BuildContext(BuildInput{
		Hostname: "db01",
		Start:    start,
		End:      start.Add(10 * time.Second),
		MemInfo:  log,
	})

	evidence, exists := findEvidence(context.Evidence, "meminfo-available")
	if !exists {
		t.Fatalf("缺少 MemAvailable 最差点 evidence: %+v", context.Evidence)
	}
	if evidence.Time != "2026-06-13 10:00:05" {
		t.Fatalf("evidence time 应指向窗口最差点, got=%q", evidence.Time)
	}
	if evidence.ObservedValue != 6.25 {
		t.Fatalf("observed_value 应使用窗口最低可用内存百分比, got=%.2f", evidence.ObservedValue)
	}
}

func TestBuildContextAddsTopCPUStealEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, CpuSteal: 12, CpuIdle: 70},
		},
	}

	context := BuildContext(BuildInput{
		Hostname: "vm01",
		Start:    start,
		End:      start,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-cpu-steal")
	if !exists {
		t.Fatalf("缺少 CPU steal evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelHard {
		t.Fatalf("CPU steal 12%% 应为 hard, got=%s", evidence.Level)
	}
}

func TestBuildContextAddsTopProcessRowsEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:  at,
			CpuIdle:    80,
			TaskZombie: 1,
			Processes: []top.ProcessStats{{
				PID:        3666962,
				User:       "root",
				State:      "D",
				CPUPercent: 0,
				MemPercent: 0,
				VirtKB:     123456,
				ResKB:      4096,
				ShrKB:      2048,
				Command:    "sshd",
			}, {
				PID:        19518,
				User:       "oracle",
				State:      "R",
				CPUPercent: 88.5,
				MemPercent: 3.2,
				VirtKB:     987654,
				ResKB:      131072,
				ShrKB:      8192,
				Command:    "oracle",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Source != "top" || evidence.Category != "process_rows" {
		t.Fatalf("top process evidence 分类不一致: %+v", evidence)
	}
	for _, want := range []string{"3666962/root/D/sshd", "19518/oracle/R/oracle"} {
		if !strings.Contains(evidence.Summary, want) {
			t.Fatalf("top process evidence 未包含代表进程 %q: %s", want, evidence.Summary)
		}
	}
	if evidence.Metrics["d_state_process_count"] != 1 {
		t.Fatalf("D 状态进程计数缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["selected_process_rows"] != 2 {
		t.Fatalf("代表进程行数缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["max_process_cpu_percent"] != 88.5 {
		t.Fatalf("最大进程 CPU 占用缺失: %+v", evidence.Metrics)
	}
}

func TestBuildContextMarksHighCPUProcessRowsAsCandidateWithoutCPUPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			Load1:     1.0,
			CpuIdle:   85,
			CpuWait:   0,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "R",
				CPUPercent: 88.5,
				MemPercent: 3.2,
				ResKB:      131072,
				Command:    "oracle",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("无 CPU 系统压力佐证时 high CPU 进程行应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
	}
	for _, want := range []string{"候选进程", "候选线索", "是否异常需结合 CPU idle/load"} {
		if !strings.Contains(evidence.Summary, want) {
			t.Fatalf("summary 应说明 high CPU 行只是候选: want %q in %s", want, evidence.Summary)
		}
	}
	assertNoCausalDiagnosisWords(t, evidence.Summary)
	if evidence.Metrics["high_cpu_process_count"] != 1 {
		t.Fatalf("high CPU 候选计数缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["cpu_pressure_corroborated"] != 0 {
		t.Fatalf("无 CPU 压力时不应标记佐证: %+v", evidence.Metrics)
	}
}

func TestBuildContextMarksHighMemProcessRowsAsCandidateWithoutMemPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			Load1:     1.0,
			CpuIdle:   85,
			CpuWait:   0,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "S",
				CPUPercent: 1.5,
				MemPercent: 12.5,
				ResKB:      16 * 1024 * 1024,
				Command:    "oracle",
			}},
		}},
	}
	memLog := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 96 * 1024 * 1024,
				SwapTotal:    swapTotal,
				SwapFree:     swapTotal,
				CommitLimit:  100 * 1024 * 1024,
				Committed:    50 * 1024 * 1024,
			},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		MemInfo:  memLog,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("无内存压力佐证时 high MEM 进程行应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
	}
	for _, want := range []string{"候选进程", "候选线索", "是否异常需结合 MemAvailable、swap、commit"} {
		if !strings.Contains(evidence.Summary, want) {
			t.Fatalf("summary 应说明 high MEM 行只是候选: want %q in %s", want, evidence.Summary)
		}
	}
	assertNoCausalDiagnosisWords(t, evidence.Summary)
	if evidence.Metrics["high_mem_process_count"] != 1 {
		t.Fatalf("high MEM 候选计数缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["mem_pressure_corroborated"] != 0 {
		t.Fatalf("无内存压力时不应标记佐证: %+v", evidence.Metrics)
	}
	for _, id := range []string{"meminfo-available", "meminfo-swap-usage", "meminfo-commit-pressure", "cross-memory-pressure"} {
		if item, exists := findEvidence(context.Evidence, id); exists {
			t.Fatalf("健康 meminfo 不应生成 %s: %+v", id, item)
		}
	}
}

func TestBuildContextCorroboratesHighCPURowsWithCPUPressureEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			Load1:     9.0,
			CpuIdle:   8,
			CpuWait:   0,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "R",
				CPUPercent: 88.5,
				MemPercent: 3.2,
				ResKB:      131072,
				Command:    "oracle",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("CPU 压力由独立 evidence 承载，进程行仍应为 soft 候选, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["cpu_pressure_corroborated"] != 1 {
		t.Fatalf("CPU 压力佐证缺失: %+v", evidence.Metrics)
	}
	if _, exists := findEvidence(context.Evidence, "top-cpu-idle"); !exists {
		t.Fatalf("缺少 CPU idle 压力 evidence: %+v", context.Evidence)
	}
	if _, exists := findEvidence(context.Evidence, "top-load-high"); !exists {
		t.Fatalf("缺少 load 压力 evidence: %+v", context.Evidence)
	}
	if _, exists := findEvidence(context.Evidence, "cross-cpu-saturation"); !exists {
		t.Fatalf("缺少 CPU 饱和交叉 evidence: %+v", context.Evidence)
	}
	for _, want := range []string{"已有 top CPU 压力佐证", "可作为 CPU 排查的进程线索"} {
		if !strings.Contains(evidence.Summary, want) {
			t.Fatalf("summary 应说明 high CPU 行已有 CPU 压力佐证: want %q in %s", want, evidence.Summary)
		}
	}
	assertNoCausalDiagnosisWords(t, evidence.Summary)
}

func TestBuildContextCorroboratesHighMemRowsWithMemInfoPressureEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	topLog := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			Load1:     1.0,
			CpuIdle:   85,
			CpuWait:   0,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "S",
				CPUPercent: 1.5,
				MemPercent: 12.5,
				ResKB:      16 * 1024 * 1024,
				Command:    "oracle",
			}},
		}},
	}
	memLog := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 8 * 1024 * 1024,
				SwapTotal:    swapTotal,
				SwapFree:     28 * 1024 * 1024,
			},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		MemInfo:  memLog,
		Top:      topLog,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("内存压力由 meminfo/cross evidence 承载，进程行仍应为 soft 候选, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["mem_pressure_corroborated"] != 1 {
		t.Fatalf("内存压力佐证缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["mem_available_pct"] != 6.25 || evidence.Metrics["swap_used_pct"] != 12.5 {
		t.Fatalf("内存压力指标未同步到 process rows evidence: %+v", evidence.Metrics)
	}
	for _, want := range []string{"已有 meminfo 内存压力佐证", "可作为内存排查的进程线索"} {
		if !strings.Contains(evidence.Summary, want) {
			t.Fatalf("summary 应说明 high MEM 行已有内存压力佐证: want %q in %s", want, evidence.Summary)
		}
	}
	if _, exists := findEvidence(context.Evidence, "cross-memory-pressure"); !exists {
		t.Fatalf("缺少内存压力交叉 evidence: %+v", context.Evidence)
	}
	assertNoCausalDiagnosisWords(t, evidence.Summary)
}

func TestBuildContextKeepsSingleDStateProcessRowsSoftWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 1.0, CpuIdle: 90, CpuWait: 0},
			{
				Timestamp: start.Add(5 * time.Second),
				Load1:     1.2,
				CpuIdle:   88,
				CpuWait:   0,
				Processes: []top.ProcessStats{{
					PID:        3666962,
					User:       "root",
					State:      "D",
					CPUPercent: 0,
					MemPercent: 0,
					ResKB:      4096,
					Command:    "sshd",
				}},
			},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.1, CpuIdle: 92, CpuWait: 0},
		},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    start,
		End:      start.Add(10 * time.Second),
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("单个瞬时 D 状态且无 iowait/load/低 idle 压力时应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["d_state_process_count"] != 1 {
		t.Fatalf("D 状态进程计数缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["d_state_pressure_corroborated"] != 0 {
		t.Fatalf("无压力场景不应标记压力佐证: %+v", evidence.Metrics)
	}
}

func TestBuildContextKeepsSingleDStateSoftWhenOnlyLoadIsHigh(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       6.2,
			CpuIdle:     84.2,
			CpuWait:     0.1,
			TaskRunning: 1,
			Processes: []top.ProcessStats{{
				PID:        3666962,
				User:       "root",
				State:      "D",
				CPUPercent: 0,
				MemPercent: 0,
				ResKB:      4096,
				Command:    "sshd",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("单个 D 状态只有 load 高、无运行队列/iowait/低 idle 佐证时应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["d_state_pressure_corroborated"] != 0 ||
		evidence.Metrics["load1_max"] != 6.2 ||
		evidence.Metrics["task_running_max"] != 1 {
		t.Fatalf("AI evidence 应同时携带 load 和 running 队列上下文，且不标记压力佐证: %+v", evidence.Metrics)
	}
}

func TestBuildContextKeepsDStateProcessRowsHardWithIOWaitPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			Load1:     1.5,
			CpuIdle:   70,
			CpuWait:   15,
			Processes: []top.ProcessStats{{
				PID:        3666962,
				User:       "root",
				State:      "D",
				CPUPercent: 0,
				MemPercent: 0,
				ResKB:      4096,
				Command:    "sshd",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    at,
		End:      at,
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelHard {
		t.Fatalf("D 状态伴随 iowait 压力时应为 hard, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["d_state_pressure_corroborated"] != 1 {
		t.Fatalf("压力佐证计数缺失: %+v", evidence.Metrics)
	}
	if evidence.Metrics["cpu_wait_max"] != 15 {
		t.Fatalf("iowait 指标未同步到 process rows evidence: %+v", evidence.Metrics)
	}
}

func TestBuildContextKeepsUnpressuredMediumDStateProcessRowsSoft(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	tests := []struct {
		name            string
		snapshots       []top.TopSnapshot
		wantConcurrent  float64
		wantUnique      float64
		wantRows        float64
		wantPersistent  float64
		wantSnapshotCnt float64
	}{
		{
			name: "multiple_d_without_pressure",
			snapshots: []top.TopSnapshot{{
				Timestamp: start,
				Load1:     1.0,
				CpuIdle:   90,
				CpuWait:   0,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}, {
					PID:     19518,
					User:    "oracle",
					State:   "D",
					Command: "node_ex+",
				}},
			}},
			wantConcurrent:  2,
			wantUnique:      2,
			wantRows:        2,
			wantPersistent:  0,
			wantSnapshotCnt: 1,
		},
		{
			name: "persistent_d_without_pressure",
			snapshots: []top.TopSnapshot{{
				Timestamp: start,
				Load1:     1.0,
				CpuIdle:   90,
				CpuWait:   0,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			}, {
				Timestamp: start.Add(5 * time.Second),
				Load1:     1.2,
				CpuIdle:   88,
				CpuWait:   0,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			}},
			wantConcurrent:  1,
			wantUnique:      1,
			wantRows:        1,
			wantPersistent:  1,
			wantSnapshotCnt: 2,
		},
		{
			name: "spread_d_without_pressure",
			snapshots: []top.TopSnapshot{{
				Timestamp: start,
				Load1:     1.0,
				CpuIdle:   90,
				CpuWait:   0,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			}, {
				Timestamp: start.Add(5 * time.Second),
				Load1:     1.2,
				CpuIdle:   88,
				CpuWait:   0,
				Processes: []top.ProcessStats{{
					PID:     19518,
					User:    "oracle",
					State:   "D",
					Command: "node_ex+",
				}},
			}},
			wantConcurrent:  1,
			wantUnique:      2,
			wantRows:        2,
			wantPersistent:  0,
			wantSnapshotCnt: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := BuildContext(BuildInput{
				Hostname: "rdsmaster1",
				Start:    start,
				End:      start.Add(10 * time.Second),
				Top:      &top.TopLog{Snapshots: tt.snapshots},
			})

			evidence, exists := findEvidence(context.Evidence, "top-process-rows")
			if !exists {
				t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
			}
			if evidence.Level != SignalLevelSoft {
				t.Fatalf("无压力的多 D/持续 D 只应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
			}
			if evidence.Metrics["d_state_process_count"] != tt.wantConcurrent ||
				evidence.Metrics["d_state_max_concurrent_process_count"] != tt.wantConcurrent {
				t.Fatalf("D 状态并发进程峰值不符: %+v", evidence.Metrics)
			}
			if evidence.Metrics["d_state_unique_process_count"] != tt.wantUnique {
				t.Fatalf("D 状态唯一 PID 计数不符: %+v", evidence.Metrics)
			}
			if evidence.Metrics["selected_process_rows"] != tt.wantRows {
				t.Fatalf("代表进程行数不符: %+v", evidence.Metrics)
			}
			if evidence.Metrics["d_state_persistent_process_count"] != tt.wantPersistent {
				t.Fatalf("持续 D 状态计数不符: %+v", evidence.Metrics)
			}
			if evidence.Metrics["d_state_snapshot_count"] != tt.wantSnapshotCnt {
				t.Fatalf("D 状态采样数不符: %+v", evidence.Metrics)
			}
			if evidence.Metrics["d_state_pressure_corroborated"] != 0 {
				t.Fatalf("无压力场景不应标记压力佐证: %+v", evidence.Metrics)
			}
		})
	}
}

func TestBuildContextKeepsSingleZombieProcessRowsSoft(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, CpuIdle: 90, TaskZombie: 0},
			{
				Timestamp:  start.Add(5 * time.Second),
				CpuIdle:    90,
				TaskZombie: 1,
				Processes: []top.ProcessStats{{
					PID:        777,
					User:       "oracle",
					State:      "Z",
					CPUPercent: 0,
					MemPercent: 0,
					ResKB:      4096,
					Command:    "oracle",
				}},
			},
			{Timestamp: start.Add(10 * time.Second), CpuIdle: 90, TaskZombie: 0},
		},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    start,
		End:      start.Add(10 * time.Second),
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("单个瞬时 Z 状态进程应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["z_state_process_count"] != 1 || evidence.Metrics["d_state_process_count"] != 0 {
		t.Fatalf("Z/D 状态计数不符: %+v", evidence.Metrics)
	}
}

func TestBuildContextKeepsPersistentSingleZombieProcessRowsSoft(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:  start,
			CpuIdle:    90,
			TaskZombie: 1,
			Processes: []top.ProcessStats{{
				PID:        777,
				User:       "oracle",
				State:      "Z",
				CPUPercent: 0,
				MemPercent: 0,
				ResKB:      4096,
				Command:    "oracle",
			}},
		}, {
			Timestamp:  start.Add(5 * time.Second),
			CpuIdle:    90,
			TaskZombie: 1,
			Processes: []top.ProcessStats{{
				PID:        777,
				User:       "oracle",
				State:      "Z",
				CPUPercent: 0,
				MemPercent: 0,
				ResKB:      4096,
				Command:    "oracle",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    start,
		End:      start.Add(5 * time.Second),
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Level != SignalLevelSoft {
		t.Fatalf("持续单个 Z 状态进程应为 soft, got=%s evidence=%+v", evidence.Level, evidence)
	}
	if evidence.Metrics["z_state_process_count"] != 1 || evidence.Metrics["task_zombie_sample_count"] != 2 {
		t.Fatalf("Z 状态计数不符: %+v", evidence.Metrics)
	}
}

func TestBuildContextDeduplicatesTopProcessRowsAcrossSnapshots(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: start,
			CpuIdle:   80,
			Processes: []top.ProcessStats{{
				PID:        3666962,
				User:       "root",
				State:      "D",
				CPUPercent: 0,
				MemPercent: 0,
				ResKB:      4096,
				Command:    "sshd",
			}},
		}, {
			Timestamp: start.Add(5 * time.Second),
			CpuIdle:   80,
			Processes: []top.ProcessStats{{
				PID:        3666962,
				User:       "root",
				State:      "D",
				CPUPercent: 0,
				MemPercent: 0,
				ResKB:      4096,
				Command:    "sshd",
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    start,
		End:      start.Add(5 * time.Second),
		Top:      log,
	})

	evidence, exists := findEvidence(context.Evidence, "top-process-rows")
	if !exists {
		t.Fatalf("缺少 top 代表进程 evidence: %+v", context.Evidence)
	}
	if evidence.Metrics["selected_process_rows"] != 1 {
		t.Fatalf("同一进程跨快照应去重, got=%+v summary=%s", evidence.Metrics, evidence.Summary)
	}
	if strings.Count(evidence.Summary, "3666962/root/D/sshd") != 1 {
		t.Fatalf("summary 不应重复同一进程: %s", evidence.Summary)
	}
}

func TestBuildContextMapsIOStatFindingFieldsToEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: start,
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteAwait:     300.11,
			}},
		}},
	}

	context := BuildContext(BuildInput{
		Hostname: "rdsmaster1",
		Start:    start,
		End:      start,
		IOStat:   log,
	})

	evidence, exists := findEvidence(context.Evidence, "iostat-write-latency-nvme11n1")
	if !exists {
		t.Fatalf("缺少 iostat 写延迟 evidence: %+v", context.Evidence)
	}
	if evidence.Target != "nvme11n1" {
		t.Fatalf("target 未从 finding 映射: got=%q", evidence.Target)
	}
	if evidence.Metric != "write_await_ms" {
		t.Fatalf("metric 未从 finding 映射: got=%q", evidence.Metric)
	}
	if evidence.Threshold != 8 {
		t.Fatalf("threshold 未从 finding 映射: got=%.2f", evidence.Threshold)
	}
	if evidence.ObservedValue != 300.11 {
		t.Fatalf("observed_value 未从 finding 映射: got=%.2f", evidence.ObservedValue)
	}
	if evidence.EvidenceRef == "" {
		t.Fatalf("evidence_ref 未从 finding 映射")
	}
}

func findEvidence(evidence []Evidence, id string) (Evidence, bool) {
	for _, item := range evidence {
		if item.ID == id {
			return item, true
		}
	}
	return Evidence{}, false
}

func assertNoCausalDiagnosisWords(t *testing.T, summary string) {
	t.Helper()
	for _, word := range []string{"根因", "导致", "造成", "引发", "确定为", "异常进程"} {
		if strings.Contains(summary, word) {
			t.Fatalf("summary 不应使用因果定性词 %q: %s", word, summary)
		}
	}
}
