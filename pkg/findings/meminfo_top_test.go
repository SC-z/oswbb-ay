package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oswbb-analyse/internal/config"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
)

func TestBuildMemInfoFindingsReportsCommitPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemAvailable: 64 * 1024 * 1024,
				CommitLimit:  100 * 1024 * 1024,
				Committed:    105 * 1024 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, at, at)
	finding, ok := findByRuleID(got, "meminfo-commit-pressure")
	if !ok {
		t.Fatalf("expected commit pressure finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity mismatch: got=%q", finding.Severity)
	}
	if finding.Metric != "committed_pct" {
		t.Fatalf("metric mismatch: got=%q", finding.Metric)
	}
	if finding.Threshold != 100 {
		t.Fatalf("threshold mismatch: got=%.2f", finding.Threshold)
	}
	if finding.ObservedValue != 105 {
		t.Fatalf("observed value mismatch: got=%.2f", finding.ObservedValue)
	}
	if finding.Time != "2026-06-13 10:00:00" {
		t.Fatalf("time mismatch: got=%q", finding.Time)
	}
}

func TestBuildMemInfoFindingsReportsCommitPressureWithoutAvailableFields(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:    128 * 1024 * 1024,
				CommitLimit: 100 * 1024 * 1024,
				Committed:   105 * 1024 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, at, at)
	finding, ok := findByRuleID(got, "meminfo-commit-pressure")
	if !ok {
		t.Fatalf("缺少 MemAvailable/fallback 字段但有 Committed_AS 压力时仍应报告 commit finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh || finding.ObservedValue != 105 {
		t.Fatalf("commit finding 字段不完整: %+v", finding)
	}
	if available, ok := findByRuleID(got, "meminfo-available"); ok {
		t.Fatalf("缺少可用内存字段时不应把可用内存按 0 误报: %+v", available)
	}
}

func TestBuildMemInfoFindingsCommitCurrentUsesLatestValidCommitSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 64 * 1024 * 1024,
					CommitLimit:  100 * 1024 * 1024,
					Committed:    105 * 1024 * 1024,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 63 * 1024 * 1024,
				},
			},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "meminfo-commit-pressure")
	if !ok {
		t.Fatalf("尾部缺少 CommitLimit 的样本不应掩盖已有 commit pressure, got=%+v", got)
	}
	if finding.Metrics["committed_current_pct"] != 105 {
		t.Fatalf("current commit pct 应使用最近有效 commit 样本而不是尾部截断样本: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsReportsWorstAvailablePointAfterRecovery(t *testing.T) {
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

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-available")
	if !ok {
		t.Fatalf("expected worst available finding after recovery, got=%+v", got)
	}
	if finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("time should point to worst available sample, got=%q", finding.Time)
	}
	if finding.WindowStart != "2026-06-13 10:00:00" || finding.WindowEnd != "2026-06-13 10:00:10" {
		t.Fatalf("window should cover filtered samples, got=%q~%q", finding.WindowStart, finding.WindowEnd)
	}
	if finding.ObservedValue != 6.25 {
		t.Fatalf("observed pct should use worst available sample, got=%.2f", finding.ObservedValue)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("单点低可用内存且当前已恢复时应降为 medium, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Nature != FindingNatureCandidate {
		t.Fatalf("单点低可用内存且当前已恢复时应作为候选线索, got=%q finding=%+v", finding.Nature, finding)
	}
	for _, want := range []string{"短时低水位", "当前已恢复"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("单点恢复 summary 应明确不是持续压力 %q: %s", want, finding.Summary)
		}
	}
	if finding.Metrics["mem_available_current_pct"] != 71.875 {
		t.Fatalf("current available pct missing, got=%+v", finding.Metrics)
	}
	if finding.Metrics["mem_available_warn_sample_count"] != 1 ||
		finding.Metrics["mem_available_recovered"] != 1 {
		t.Fatalf("available finding 应记录低水位样本数和恢复状态: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsMarksSingleRecoveredSoftAvailableAsCandidate(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 32 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-available")
	if !ok {
		t.Fatalf("single recovered soft available sample should still be kept as clue, got=%+v", got)
	}
	if finding.Severity != SeverityMedium || finding.Nature != FindingNatureCandidate {
		t.Fatalf("single recovered soft available sample should be medium candidate, got=%+v", finding)
	}
	if finding.ObservedValue != 25 {
		t.Fatalf("observed pct should use soft low-water sample, got=%.2f", finding.ObservedValue)
	}
	if finding.Metrics["mem_available_soft_sample_count"] != 1 ||
		finding.Metrics["mem_available_warn_sample_count"] != 0 ||
		finding.Metrics["mem_available_recovered"] != 1 {
		t.Fatalf("soft recovered metrics mismatch: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsIgnoresLastIncompleteSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemAvailable: 4 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-available")
	if !ok {
		t.Fatalf("expected finding from valid sample before incomplete tail, got=%+v", got)
	}
	if finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("bad tail sample should not become finding time, got=%q", finding.Time)
	}
}

func TestBuildMemInfoFindingsDoesNotReportHealthySmallHostByAbsoluteAvailableMB(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 4 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 3 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-available"); ok {
		t.Fatalf("小内存主机可用比例健康时不应只因绝对 MB 低就报内存压力: %+v", finding)
	}
}

func TestBuildMemInfoFindingsUsesFallbackWhenMemAvailableMissing(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: start,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemFree:      4 * 1024 * 1024,
				Buffers:      2 * 1024 * 1024,
				Cached:       60 * 1024 * 1024,
				SReclaimable: 4 * 1024 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, start, start)
	if finding, ok := findByRuleID(got, "meminfo-available"); ok {
		t.Fatalf("缺 MemAvailable 但可回收内存充足时不应按 0 误报: %+v", finding)
	}
}

func TestBuildMemInfoFindingsIgnoresSampleWithoutAvailableFields(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 96 * 1024 * 1024,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal: memTotal,
				},
			},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-available"); ok {
		t.Fatalf("只有 MemTotal 而缺少 MemAvailable/fallback 字段的截断样本不应按 0 可用内存误报: %+v", finding)
	}
	for _, finding := range got {
		if finding.WindowEnd == "2026-06-13 10:00:05" {
			t.Fatalf("截断样本不应参与 findings 时间窗口: %+v", finding)
		}
	}
}

func TestBuildMemInfoFindingsIgnoresPartialFallbackAvailableSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 96 * 1024 * 1024,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal: memTotal,
					MemFree:  2 * 1024 * 1024,
				},
			},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-available"); ok {
		t.Fatalf("只有 MemFree 的尾部半截样本不应按 fallback 可用内存低水位误报: %+v", finding)
	}
	for _, finding := range got {
		if finding.WindowEnd == "2026-06-13 10:00:05" {
			t.Fatalf("只有 MemFree 的尾部半截样本不应参与 findings 时间窗口: %+v", finding)
		}
	}
}

func TestBuildMemInfoFindingsDoesNotReportStableHistoricalSwapWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: 28 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 95 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: 28 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: 28 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-swap-usage"); ok {
		t.Fatalf("Swap 历史占用稳定且无内存压力时不应报当前 swap 压力: %+v", finding)
	}
}

func TestBuildMemInfoFindingsDoesNotCombineRecoveredSwapWithLaterLowAvailable(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: 28 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: swapTotal}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-swap-usage"); ok {
		t.Fatalf("历史 swap 占用已恢复时，不应借用后续低可用内存误报 swap 压力: %+v", finding)
	}
	if _, ok := findByRuleID(got, "meminfo-available"); !ok {
		t.Fatalf("后续低可用内存本身仍应报告，got=%+v", got)
	}
}

func TestBuildMemInfoFindingsDoesNotTreatMissingSwapFreeAsFullyUsedSwap(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: swapTotal}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024, SwapTotal: swapTotal}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-swap-usage"); ok {
		t.Fatalf("缺失 SwapFree 的截断样本不应按 Swap 已满误报: %+v", finding)
	}
	if _, ok := findByRuleID(got, "meminfo-available"); !ok {
		t.Fatalf("低可用内存本身仍应报告，got=%+v", got)
	}
}

func TestBuildMemInfoFindingsSwapCurrentUsesLatestValidSwapSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: swapTotal}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 90 * 1024 * 1024, SwapTotal: swapTotal, SwapFree: 16 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 88 * 1024 * 1024, SwapTotal: swapTotal}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-swap-usage")
	if !ok {
		t.Fatalf("已有有效 swap 压力样本时尾部缺 SwapFree 不应掩盖 finding, got=%+v", got)
	}
	if finding.Metrics["swap_used_current_pct"] != 50 ||
		finding.Metrics["swap_recovered"] != 0 ||
		finding.Nature != FindingNatureRisk {
		t.Fatalf("swap current 应使用最近有效 SwapFree 样本，而不是把尾部缺字段当恢复: %+v", finding)
	}
}

func TestBuildMemInfoFindingsKeepsCurrentLowAvailableAsHigh(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "meminfo-available")
	if !ok {
		t.Fatalf("当前仍低可用内存应报告, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("当前仍处于低可用内存时应保持 high, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Nature != FindingNatureRisk {
		t.Fatalf("当前仍处于低可用内存时应保持风险信号, got=%q finding=%+v", finding.Nature, finding)
	}
	if finding.Metrics["mem_available_recovered"] != 0 {
		t.Fatalf("当前仍低可用内存不应标记 recovered: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsKeepsRepeatedLowAvailableAfterRecoveryAsRisk(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 12 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 10 * 1024 * 1024}},
			{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "meminfo-available")
	if !ok {
		t.Fatalf("repeated low available samples should still report finding, got=%+v", got)
	}
	if finding.Nature != FindingNatureRisk {
		t.Fatalf("repeated low available samples should remain risk even after recovery, got=%q finding=%+v", finding.Nature, finding)
	}
	if finding.Metrics["mem_available_warn_sample_count"] != 2 ||
		finding.Metrics["mem_available_recovered"] != 1 {
		t.Fatalf("test fixture should record repeated low samples and recovery: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsReportsWorstSwapCommitAndSlabAfterRecovery(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	commitLimit := int64(100 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 96 * 1024 * 1024,
					SwapTotal:    swapTotal,
					SwapFree:     swapTotal,
					CommitLimit:  commitLimit,
					Committed:    50 * 1024 * 1024,
					Slab:         2 * 1024 * 1024,
					SUnreclaim:   1 * 1024 * 1024,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 90 * 1024 * 1024,
					SwapTotal:    swapTotal,
					SwapFree:     16 * 1024 * 1024,
					CommitLimit:  commitLimit,
					Committed:    105 * 1024 * 1024,
					Slab:         22 * 1024 * 1024,
					SUnreclaim:   4 * 1024 * 1024,
				},
			},
			{
				Timestamp: start.Add(10 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 95 * 1024 * 1024,
					SwapTotal:    swapTotal,
					SwapFree:     swapTotal,
					CommitLimit:  commitLimit,
					Committed:    50 * 1024 * 1024,
					Slab:         2 * 1024 * 1024,
					SUnreclaim:   1 * 1024 * 1024,
				},
			},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	for _, ruleID := range []string{"meminfo-swap-usage", "meminfo-commit-pressure", "meminfo-slab"} {
		finding, ok := findByRuleID(got, ruleID)
		if !ok {
			t.Fatalf("expected %s finding after recovery, got=%+v", ruleID, got)
		}
		if finding.Time != "2026-06-13 10:00:05" {
			t.Fatalf("%s should point to worst sample, got=%q", ruleID, finding.Time)
		}
		if finding.Nature != FindingNatureCandidate {
			t.Fatalf("%s 历史压力当前已恢复时应作为候选线索, got=%q finding=%+v", ruleID, finding.Nature, finding)
		}
	}
	swapFinding, _ := findByRuleID(got, "meminfo-swap-usage")
	if _, ok := swapFinding.Metrics["swap_used_current_pct"]; !ok || swapFinding.Metrics["swap_used_current_pct"] != 0 {
		t.Fatalf("swap current pct should show recovery, got=%+v", swapFinding.Metrics)
	}
	if swapFinding.Metrics["swap_recovered"] != 1 || !strings.Contains(swapFinding.Summary, "当前已恢复") {
		t.Fatalf("swap 历史压力应记录并说明当前已恢复: %+v summary=%s", swapFinding.Metrics, swapFinding.Summary)
	}
	commitFinding, _ := findByRuleID(got, "meminfo-commit-pressure")
	if commitFinding.Metrics["committed_current_pct"] != 50 {
		t.Fatalf("commit current pct should show recovery, got=%+v", commitFinding.Metrics)
	}
	if commitFinding.Metrics["committed_recovered"] != 1 || !strings.Contains(commitFinding.Summary, "当前已恢复") {
		t.Fatalf("commit 历史压力应记录并说明当前已恢复: %+v summary=%s", commitFinding.Metrics, commitFinding.Summary)
	}
	slabFinding, _ := findByRuleID(got, "meminfo-slab")
	if slabFinding.Metrics["slab_current_pct"] != 1.5625 {
		t.Fatalf("slab current pct should show recovery, got=%+v", slabFinding.Metrics)
	}
	if slabFinding.Metrics["slab_recovered"] != 1 || !strings.Contains(slabFinding.Summary, "当前已恢复") {
		t.Fatalf("slab 历史压力应记录并说明当前已恢复: %+v summary=%s", slabFinding.Metrics, slabFinding.Summary)
	}
}

func TestBuildMemInfoFindingsReportsWritebackPressureAfterRecovery(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, Dirty: 512 * 1024, Writeback: 0}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 90 * 1024 * 1024, Dirty: 8 * 1024 * 1024, Writeback: 2 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 95 * 1024 * 1024, Dirty: 256 * 1024, Writeback: 0}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-writeback-pressure")
	if !ok {
		t.Fatalf("Dirty/Writeback 回写积压应生成 finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("回写积压达到硬阈值应为 high, got=%q", finding.Severity)
	}
	if finding.Metric != "writeback_pct" {
		t.Fatalf("metric 应指向 Writeback 占比, got=%q", finding.Metric)
	}
	if finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("finding 应指向回写积压峰值时间, got=%q", finding.Time)
	}
	if finding.Metrics["dirty_pct"] != 6.25 ||
		finding.Metrics["writeback_pct"] != 1.5625 ||
		finding.Metrics["dirty_current_mb"] != 256 ||
		finding.Metrics["writeback_current_mb"] != 0 {
		t.Fatalf("回写积压 metrics 不完整: %+v", finding.Metrics)
	}
	if finding.Nature != FindingNatureCandidate {
		t.Fatalf("回写积压当前已恢复时应作为候选线索, got=%q finding=%+v", finding.Nature, finding)
	}
	if finding.Metrics["writeback_recovered"] != 1 || !strings.Contains(finding.Summary, "当前已恢复") {
		t.Fatalf("回写积压历史压力应记录并说明当前已恢复: %+v summary=%s", finding.Metrics, finding.Summary)
	}
}

func TestBuildMemInfoFindingsKeepsCurrentSwapCommitSlabWritebackAsRisk(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	commitLimit := int64(100 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 96 * 1024 * 1024,
					SwapTotal:    swapTotal,
					SwapFree:     swapTotal,
					CommitLimit:  commitLimit,
					Committed:    50 * 1024 * 1024,
					Slab:         2 * 1024 * 1024,
					SUnreclaim:   1 * 1024 * 1024,
					Dirty:        256 * 1024,
					Writeback:    0,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 8 * 1024 * 1024,
					SwapTotal:    swapTotal,
					SwapFree:     16 * 1024 * 1024,
					CommitLimit:  commitLimit,
					Committed:    105 * 1024 * 1024,
					Slab:         22 * 1024 * 1024,
					SUnreclaim:   4 * 1024 * 1024,
					Dirty:        8 * 1024 * 1024,
					Writeback:    2 * 1024 * 1024,
				},
			},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	for _, ruleID := range []string{"meminfo-swap-usage", "meminfo-commit-pressure", "meminfo-slab", "meminfo-writeback-pressure"} {
		finding, ok := findByRuleID(got, ruleID)
		if !ok {
			t.Fatalf("当前仍有压力时应报告 %s, got=%+v", ruleID, got)
		}
		if finding.Nature != FindingNatureRisk {
			t.Fatalf("当前仍有压力的 %s 应保持风险信号, got=%q finding=%+v", ruleID, finding.Nature, finding)
		}
		if strings.Contains(finding.Summary, "当前已恢复") {
			t.Fatalf("当前仍有压力的 %s 摘要不应说明已恢复: %s", ruleID, finding.Summary)
		}
	}
	for ruleID, metric := range map[string]string{
		"meminfo-swap-usage":         "swap_recovered",
		"meminfo-commit-pressure":    "committed_recovered",
		"meminfo-slab":               "slab_recovered",
		"meminfo-writeback-pressure": "writeback_recovered",
	} {
		finding, _ := findByRuleID(got, ruleID)
		if finding.Metrics[metric] != 0 {
			t.Fatalf("当前仍有压力的 %s 应记录 %s=0, metrics=%+v", ruleID, metric, finding.Metrics)
		}
	}
}

func TestBuildMemInfoFindingsWritebackCurrentUsesLatestValidWritebackSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, Dirty: 8 * 1024 * 1024, Writeback: 2 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 94 * 1024 * 1024, Dirty: 7 * 1024 * 1024, Writeback: 1 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 93 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-writeback-pressure")
	if !ok {
		t.Fatalf("尾部缺少 Dirty/Writeback 字段不应掩盖已有回写积压, got=%+v", got)
	}
	if finding.Metrics["dirty_current_mb"] != 7168 || finding.Metrics["writeback_current_mb"] != 1024 {
		t.Fatalf("current Dirty/Writeback 应使用最近有效回写样本而不是尾部截断样本: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsDoesNotReportDirtyCacheWithoutWriteback(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, Dirty: 8 * 1024 * 1024, Writeback: 0}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 95 * 1024 * 1024, Dirty: 9 * 1024 * 1024, Writeback: 0}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-writeback-pressure"); ok {
		t.Fatalf("Dirty 高但没有 Writeback 积压时不应单独报告回写压力: %+v", finding)
	}
}

func TestBuildMemInfoFindingsDoesNotReportTinyWritebackRatioOnLargeMemoryHost(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(1024 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 900 * 1024 * 1024,
				Dirty:        1024 * 1024,
				Writeback:    512 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, at, at)
	if finding, ok := findByRuleID(got, "meminfo-writeback-pressure"); ok {
		t.Fatalf("大内存主机上 Dirty/Writeback 占比很低时不应只凭绝对 MB 报回写积压: %+v", finding)
	}
}

func TestBuildMemInfoFindingsReportsSUnreclaimAsTriggerMetric(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 96 * 1024 * 1024,
				Slab:         4 * 1024 * 1024,
				SUnreclaim:   3 * 1024 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, at, at)
	finding, ok := findByRuleID(got, "meminfo-slab")
	if !ok {
		t.Fatalf("expected SUnreclaim finding, got=%+v", got)
	}
	if finding.Metric != "sunreclaim_pct" {
		t.Fatalf("metric should identify SUnreclaim trigger, got=%q", finding.Metric)
	}
	if finding.Threshold != 2 {
		t.Fatalf("threshold should match SUnreclaim high threshold, got=%.2f", finding.Threshold)
	}
	if finding.ObservedValue != 2.34375 {
		t.Fatalf("observed value should be SUnreclaim pct, got=%.5f", finding.ObservedValue)
	}
	if finding.EvidenceRef != "meminfo:memory:sunreclaim_pct:2026-06-13 10:00:00" {
		t.Fatalf("evidence ref should identify SUnreclaim metric, got=%q", finding.EvidenceRef)
	}
	if finding.Metrics["slab_pct"] != 3.125 || finding.Metrics["sunreclaim_pct"] != 2.34375 {
		t.Fatalf("metrics should retain slab and SUnreclaim values, got=%+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsReportsSlabPctAsTriggerMetric(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 96 * 1024 * 1024,
				Slab:         22 * 1024 * 1024,
				SUnreclaim:   1 * 1024 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, at, at)
	finding, ok := findByRuleID(got, "meminfo-slab")
	if !ok {
		t.Fatalf("expected Slab finding, got=%+v", got)
	}
	if finding.Metric != "slab_pct" {
		t.Fatalf("metric should identify Slab pct trigger, got=%q", finding.Metric)
	}
	if finding.Threshold != 8 {
		t.Fatalf("threshold should match Slab pct high threshold, got=%.2f", finding.Threshold)
	}
	if finding.ObservedValue != 17.1875 {
		t.Fatalf("observed value should be Slab pct, got=%.5f", finding.ObservedValue)
	}
	if finding.EvidenceRef != "meminfo:memory:slab_pct:2026-06-13 10:00:00" {
		t.Fatalf("evidence ref should identify Slab pct metric, got=%q", finding.EvidenceRef)
	}
}

func TestBuildMemInfoFindingsDoesNotReportLargeReclaimableSlabOnLargeMemoryHost(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(1024 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 900 * 1024 * 1024,
				Slab:         12 * 1024 * 1024,
				SReclaimable: 11 * 1024 * 1024,
				SUnreclaim:   512 * 1024,
			},
		}},
	}

	got := BuildMemInfoFindings(log, at, at)
	if finding, ok := findByRuleID(got, "meminfo-slab"); ok {
		t.Fatalf("大内存主机上可回收 Slab 绝对值较大但占比/不可回收占比都低时不应报告 slab 异常: %+v", finding)
	}
}

func TestBuildMemInfoFindingsSlabCurrentUsesLatestValidSlabSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, Slab: 22 * 1024 * 1024, SUnreclaim: 3 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 94 * 1024 * 1024, Slab: 20 * 1024 * 1024, SUnreclaim: 2 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 93 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-slab")
	if !ok {
		t.Fatalf("尾部缺少 Slab/SUnreclaim 字段不应掩盖已有 slab pressure, got=%+v", got)
	}
	if finding.Metrics["slab_current_pct"] != 15.625 || finding.Metrics["sunreclaim_current_pct"] != 1.5625 {
		t.Fatalf("current Slab/SUnreclaim 应使用最近有效 slab 样本而不是尾部截断样本: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsDoesNotLetNonTriggerSlabMaskSUnreclaim(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 96 * 1024 * 1024,
					Slab:         9 * 1024 * 1024,
					SUnreclaim:   512 * 1024,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     memTotal,
					MemAvailable: 96 * 1024 * 1024,
					Slab:         3 * 1024 * 1024,
					SUnreclaim:   3 * 1024 * 1024,
				},
			},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "meminfo-slab")
	if !ok {
		t.Fatalf("expected later SUnreclaim trigger not to be masked by earlier non-trigger slab sample, got=%+v", got)
	}
	if finding.Metric != "sunreclaim_pct" {
		t.Fatalf("metric should identify later SUnreclaim trigger, got=%q", finding.Metric)
	}
	if finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("time should point to later SUnreclaim trigger, got=%q", finding.Time)
	}
}

func TestBuildMemInfoFindingsDoesNotReportHealthyBaseline(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	swapTotal := int64(32 * 1024 * 1024)
	commitLimit := int64(100 * 1024 * 1024)
	log := &meminfo.MemInfoLog{}
	for i := 0; i < 6; i++ {
		log.Data = append(log.Data, meminfo.MemStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 64 * 1024 * 1024,
				SwapTotal:    swapTotal,
				SwapFree:     swapTotal,
				CommitLimit:  commitLimit,
				Committed:    60 * 1024 * 1024,
				Slab:         2 * 1024 * 1024,
				SUnreclaim:   1 * 1024 * 1024,
				AnonPages:    8 * 1024 * 1024,
			},
		})
	}

	got := BuildMemInfoFindings(log, start, start.Add(25*time.Second))
	if len(got) != 0 {
		t.Fatalf("healthy meminfo baseline should not report findings: %+v", got)
	}
}

func TestBuildMemInfoFindingsReportsWorstAnonGrowthBeforeRecovery(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024, AnonPages: baselineAnon + 256*1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 91 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
			{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("expected middle-window anon growth finding after recovery, got=%+v", got)
	}
	if finding.Time != "2026-06-13 10:00:10" {
		t.Fatalf("time should point to anon growth peak, got=%q", finding.Time)
	}
	if finding.WindowStart != "2026-06-13 10:00:00" || finding.WindowEnd != "2026-06-13 10:00:10" {
		t.Fatalf("window should cover the growth segment, got=%q~%q", finding.WindowStart, finding.WindowEnd)
	}
	if finding.ObservedValue != 512 {
		t.Fatalf("observed anon delta should use worst growth segment, got=%.2f", finding.ObservedValue)
	}
	if finding.Metrics["anon_current_mb"] != 8192 {
		t.Fatalf("current anon pages should show recovery, got=%+v", finding.Metrics)
	}
	if finding.Metrics["anon_growth_window_mb"] != 512 || finding.Metrics["anon_growth_rate_mb_per_sample"] != 256 {
		t.Fatalf("anon growth compatibility metrics missing: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsDoesNotReportSingleSampleAnonSpikeWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "meminfo-anon-growth"); ok {
		t.Fatalf("single-sample anon spike without memory pressure should not report finding: %+v", finding)
	}
}

func TestBuildMemInfoFindingsDoesNotReportSparseSlowAnonGrowthWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: start.Add(30 * time.Minute), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon + 256*1024}},
			{Timestamp: start.Add(60 * time.Minute), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(60*time.Minute))
	if finding, ok := findByRuleID(got, "meminfo-anon-growth"); ok {
		t.Fatalf("稀疏采样下 512MB/小时且无内存压力的匿名页增长不应误报 leak: %+v", finding)
	}
}

func TestBuildMemInfoFindingsReportsTailAnonGrowth(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 94 * 1024 * 1024, AnonPages: baselineAnon + 128*1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024, AnonPages: baselineAnon + 256*1024}},
			{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 90 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("expected tail anon growth finding, got=%+v", got)
	}
	if finding.Time != "2026-06-13 10:00:15" {
		t.Fatalf("tail growth should point to latest peak, got=%q", finding.Time)
	}
	if finding.WindowStart != "2026-06-13 10:00:00" || finding.WindowEnd != "2026-06-13 10:00:15" {
		t.Fatalf("tail growth window mismatch: got=%q~%q", finding.WindowStart, finding.WindowEnd)
	}
	if finding.ObservedValue != 512 {
		t.Fatalf("tail growth delta mismatch: got=%.2f", finding.ObservedValue)
	}
}

func TestBuildMemInfoFindingsReportsAnonGrowthWithoutAvailableFields(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, AnonPages: baselineAnon}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, AnonPages: baselineAnon + 256*1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, AnonPages: baselineAnon + 512*1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("AnonPages 本身就是有效内存信号，缺 MemAvailable 时仍应发现匿名页增长, got=%+v", got)
	}
	if finding.ObservedValue != 512 {
		t.Fatalf("observed anon delta should be preserved without available fields, got=%.2f finding=%+v", finding.ObservedValue, finding)
	}
	if finding.Time != "2026-06-13 10:00:10" {
		t.Fatalf("time should point to anon growth peak, got=%q", finding.Time)
	}
	if finding.Metrics["anon_pressure_corroborated"] != 0 {
		t.Fatalf("missing available/swap/commit fields should not invent pressure corroboration: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsDoesNotMarkSmallRelativeAnonGrowthHighOnLargeHost(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 23, 5, 4, 0, 0, loc)
	memTotal := int64(1506 * 1024 * 1024)
	available := int64(1470 * 1024 * 1024)
	baselineAnon := int64(1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon + 4*1024*1024, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon + 9*1024*1024, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
			{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon + 14*1024*1024, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("expected anon growth to remain a low-priority clue, got=%+v", got)
	}
	if finding.Severity == SeverityHigh {
		t.Fatalf("small relative anon growth without memory pressure should not be high severity: %+v", finding)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("small relative anon growth without memory pressure should stay low severity: %+v", finding)
	}
	if finding.Nature != FindingNatureCandidate {
		t.Fatalf("small relative anon growth without memory pressure should be a candidate clue, got=%q finding=%+v", finding.Nature, finding)
	}
	for _, want := range []string{"占总内存", "无可用内存/Swap/Commit 压力佐证"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("anon growth summary should explain relative size and pressure context %q: %s", want, finding.Summary)
		}
	}
}

func TestBuildMemInfoFindingsKeepsPressureBackedAnonGrowthAsRisk(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 64 * 1024 * 1024, AnonPages: baselineAnon + 128*1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 32 * 1024 * 1024, AnonPages: baselineAnon + 256*1024}},
			{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 20 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("expected pressure-backed anon growth finding, got=%+v", got)
	}
	if finding.Nature != FindingNatureRisk {
		t.Fatalf("anon growth with available-memory pressure should remain risk, got=%q finding=%+v", finding.Nature, finding)
	}
	if finding.Metrics["anon_pressure_corroborated"] != 1 {
		t.Fatalf("pressure-backed anon growth should record corroboration: %+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsDoesNotElevateHealthyAnonGrowthOnlyBecausePeakCrossesSoftPct(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 23, 5, 4, 0, 0, loc)
	memTotal := int64(1506 * 1024 * 1024)
	available := int64(1470 * 1024 * 1024)
	baselineAnon := int64(1536 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon + 5*1024*1024, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon + 10*1024*1024, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
			{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: available, AnonPages: baselineAnon + 14500*1024, CommitLimit: 753 * 1024 * 1024, Committed: 66 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("expected anon growth to remain as a low-priority clue, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("healthy anon growth with delta below soft pct should stay low even if peak crosses soft pct: %+v", finding)
	}
	if finding.Metrics["anon_growth_pct_of_memtotal"] >= config.Default().Meminfo.AnonLeakSoftPct {
		t.Fatalf("test fixture should keep anon delta below soft pct, metrics=%+v", finding.Metrics)
	}
	if finding.Metrics["anon_peak_pct_of_memtotal"] < config.Default().Meminfo.AnonLeakSoftPct {
		t.Fatalf("test fixture should cross anon peak soft pct, metrics=%+v", finding.Metrics)
	}
}

func TestBuildMemInfoFindingsDoesNotUseAnonGrowthOutsideRequestedWindow(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	windowStart := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	windowEnd := windowStart.Add(10 * time.Second)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: windowStart.Add(-5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: windowStart, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
			{Timestamp: windowStart.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
			{Timestamp: windowEnd, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
		},
	}

	got := BuildMemInfoFindings(log, windowStart, windowEnd)
	if finding, ok := findByRuleID(got, "meminfo-anon-growth"); ok {
		t.Fatalf("anon growth outside requested window should not affect window finding: %+v", finding)
	}
}

func TestBuildMemInfoFindingsOnlyUsesRequestedWindow(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	windowStart := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	windowEnd := windowStart.Add(10 * time.Second)
	memTotal := int64(128 * 1024 * 1024)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: windowStart.Add(-5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024}},
			{Timestamp: windowStart, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024}},
			{Timestamp: windowStart.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024}},
			{Timestamp: windowEnd, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 90 * 1024 * 1024}},
			{Timestamp: windowEnd.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 8 * 1024 * 1024}},
		},
	}

	got := BuildMemInfoFindings(log, windowStart, windowEnd)
	if finding, ok := findByRuleID(got, "meminfo-available"); ok {
		t.Fatalf("window外低可用内存不应影响指定窗口: %+v", finding)
	}
}

func TestBuildTopFindingsReportsCPUSteal(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp: at,
				CpuSteal:  1,
				CpuIdle:   70,
			},
			{
				Timestamp: at.Add(5 * time.Second),
				CpuSteal:  12,
				CpuIdle:   65,
			},
		},
	}

	got := BuildTopFindings(log, at, at.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-cpu-steal")
	if !ok {
		t.Fatalf("expected CPU steal finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity mismatch: got=%q", finding.Severity)
	}
	if finding.Metric != "cpu_steal_max_pct" {
		t.Fatalf("metric mismatch: got=%q", finding.Metric)
	}
	if finding.Threshold != 10 {
		t.Fatalf("threshold mismatch: got=%.2f", finding.Threshold)
	}
	if finding.ObservedValue != 12 {
		t.Fatalf("observed value mismatch: got=%.2f", finding.ObservedValue)
	}
	if finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("time mismatch: got=%q", finding.Time)
	}
}

func TestBuildTopFindingsDowngradesIsolatedCPUStealSpike(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{}
	for i, steal := range []float64{0, 0, 12, 0, 0} {
		log.Snapshots = append(log.Snapshots, top.TopSnapshot{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CpuSteal:  steal,
			CpuIdle:   70,
		})
	}

	got := BuildTopFindings(log, start, start.Add(20*time.Second))
	finding, ok := findByRuleID(got, "top-cpu-steal")
	if !ok {
		t.Fatalf("单点 CPU steal 尖峰仍应保留为虚拟化争抢线索, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("单点 CPU steal 尖峰不应直接作为高风险窗口问题, got=%q", finding.Severity)
	}
	if finding.Nature != FindingNatureCandidate {
		t.Fatalf("单点 CPU steal 尖峰应作为候选线索, got=%q finding=%+v", finding.Nature, finding)
	}
	if finding.Metrics["cpu_steal_hard_sample_count"] != 1 || finding.Metrics["cpu_steal_soft_sample_count"] != 1 {
		t.Fatalf("CPU steal finding 应记录超过阈值的样本数: %+v", finding.Metrics)
	}
}

func TestBuildTopFindingsKeepsPersistentCPUStealAsRisk(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{}
	for i, steal := range []float64{0, 12, 11, 0} {
		log.Snapshots = append(log.Snapshots, top.TopSnapshot{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CpuSteal:  steal,
			CpuIdle:   70,
		})
	}

	got := BuildTopFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "top-cpu-steal")
	if !ok {
		t.Fatalf("持续 CPU steal 应保留 finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh || finding.Nature != FindingNatureRisk {
		t.Fatalf("持续 CPU steal 应保持风险信号, got=%+v", finding)
	}
	if finding.Metrics["cpu_steal_hard_sample_count"] != 2 {
		t.Fatalf("持续 CPU steal 应记录 hard 样本数: %+v", finding.Metrics)
	}
}

func TestBuildTopFindingsFromParsedProcessTableReportsHighCPUProcess(t *testing.T) {
	content := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:09 CST 2026

top - 03:00:10 up  9:50,  0 users,  load average: 9.27, 6.64, 5.26
Tasks: 2191 total,   8 running, 2183 sleeping,   0 stopped,   0 zombie
%Cpu(s): 80.0 us, 10.0 sy,  0.0 ni,  5.0 id,  0.0 wa,  2.0 hi,  3.0 si,  0.0 st

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
  26075 root      20   0  247.3g   2.3g 936060 R 292.5   0.2 457:28.08 prometh+
`
	filename := filepath.Join(t.TempDir(), "top.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 top 文件失败: %v", err)
	}

	log, err := top.NewTopParser().ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	start, end := log.GetTimeRange()
	got := BuildTopFindings(log, start, end)

	cpuFinding, ok := findByRuleID(got, "top-cpu-idle")
	if !ok {
		t.Fatalf("解析后的低 idle + 高 CPU 进程应生成 top-cpu-idle finding, got=%+v", got)
	}
	if cpuFinding.Metrics["cpu_idle_high_process_corroborated"] != 1 {
		t.Fatalf("top-cpu-idle 应被同一快照高 CPU 进程佐证: %+v", cpuFinding.Metrics)
	}

	processFinding, ok := findByRuleID(got, "top-process-high-cpu")
	if !ok {
		t.Fatalf("解析后的高 CPU 进程行应生成 top-process-high-cpu finding, got=%+v", got)
	}
	if processFinding.Target != "process" ||
		processFinding.Metric != "process_cpu_pct" ||
		processFinding.ObservedValue != 292.5 ||
		processFinding.Time != "2026-04-21 03:00:09" {
		t.Fatalf("top-process-high-cpu finding 关键字段不正确: %+v", processFinding)
	}
	if processFinding.Metrics["cpu_idle_at_peak"] != 5 ||
		processFinding.Metrics["process_cpu_peak"] != 292.5 {
		t.Fatalf("top-process-high-cpu metrics 不完整: %+v", processFinding.Metrics)
	}
	if processFinding.Nature != FindingNatureCandidate {
		t.Fatalf("top-process-high-cpu 只是进程线索，应标记为候选线索, got=%q finding=%+v", processFinding.Nature, processFinding)
	}
}

func TestBuildTopFindingsRealArchiveKeepsHighCPUProcessCandidateWhenSystemIdle(t *testing.T) {
	filename := filepath.Join("..", "..", "other", "archive", "oswtop", "rdsmaster1_top_26.04.21.0300.dat")
	log, err := top.NewTopParser().ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 0, 9, 0, loc)
	end := time.Date(2026, time.April, 21, 3, 0, 19, 0, loc)

	foundHighCPUProcessInIdleSnapshot := false
	for _, snapshot := range log.Snapshots {
		if !snapshot.Timestamp.Equal(start) {
			continue
		}
		for _, process := range snapshot.Processes {
			if process.PID == 26075 && process.CPUPercent > 200 && snapshot.CpuIdle > 90 && snapshot.CpuWait == 0 && snapshot.TaskRunning <= 1 {
				foundHighCPUProcessInIdleSnapshot = true
				break
			}
		}
	}
	if !foundHighCPUProcessInIdleSnapshot {
		t.Fatalf("真实 archive 测试前提不成立：未找到高 CPU 进程但系统 idle 很高的快照")
	}

	got := BuildTopFindings(log, start, end)
	for _, ruleID := range []string{"top-process-high-cpu", "top-cpu-idle", "top-cpu-wait", "top-load-high"} {
		if finding, ok := findByRuleID(got, ruleID); ok {
			t.Fatalf("高 CPU 进程处于高 idle/低 wait/低 running 窗口时不应生成 %s finding: %+v", ruleID, finding)
		}
	}
}

func TestBuildTopFindingsReportsShortCPUSaturationWithProcessEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, CpuIdle: 90, TaskRunning: 1},
			{
				Timestamp:   start.Add(5 * time.Second),
				CpuIdle:     5,
				TaskRunning: 2,
				Processes: []top.ProcessStats{{
					PID:        19518,
					User:       "oracle",
					State:      "R",
					CPUPercent: 95,
					Command:    "oracle",
				}},
			},
			{Timestamp: start.Add(10 * time.Second), CpuIdle: 90, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-cpu-idle")
	if !ok {
		t.Fatalf("短时 CPU 饱和且有高 CPU 进程佐证时应生成 finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("单点 CPU 饱和应作为中风险线索而不是窗口级高风险, got=%q", finding.Severity)
	}
	if finding.Metric != "cpu_idle_min_pct" || finding.ObservedValue != 5 || finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("finding 应指向最低 idle 峰值点: %+v", finding)
	}
	if finding.Metrics["cpu_idle_min"] != 5 || finding.Metrics["cpu_idle_hard_sample_count"] != 1 || finding.Metrics["cpu_idle_high_process_corroborated"] != 1 {
		t.Fatalf("CPU 饱和佐证 metrics 不完整: %+v", finding.Metrics)
	}
	processFinding, ok := findByRuleID(got, "top-process-high-cpu")
	if !ok {
		t.Fatalf("CPU 饱和时应输出高 CPU 进程线索, got=%+v", got)
	}
	if processFinding.Target != "process" || processFinding.Metric != "process_cpu_pct" || processFinding.ObservedValue != 95 {
		t.Fatalf("高 CPU 进程 finding 关键字段不正确: %+v", processFinding)
	}
	if processFinding.Metrics["high_cpu_process_count"] != 1 ||
		processFinding.Metrics["process_cpu_peak"] != 95 ||
		processFinding.Metrics["cpu_idle_at_peak"] != 5 {
		t.Fatalf("高 CPU 进程 metrics 不完整: %+v", processFinding.Metrics)
	}
	if !strings.Contains(processFinding.Summary, "PID=19518") || !strings.Contains(processFinding.Summary, "oracle") {
		t.Fatalf("高 CPU 进程 summary 应包含 PID 和命令: %s", processFinding.Summary)
	}
}

func TestBuildTopFindingsDoesNotReportHighCPUProcessWithoutSystemPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   start,
			CpuIdle:     80,
			TaskRunning: 1,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "R",
				CPUPercent: 95,
				Command:    "oracle",
			}},
		}},
	}

	got := BuildTopFindings(log, start, start)
	if finding, ok := findByRuleID(got, "top-process-high-cpu"); ok {
		t.Fatalf("系统 CPU 无压力时，高 CPU 进程只应作为候选上下文，不应生成 finding: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseRunnableQueueAtDifferentTimeToCorroborateLowIdle(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, CpuIdle: 5, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), CpuIdle: 90, TaskRunning: 12},
			{Timestamp: start.Add(10 * time.Second), CpuIdle: 90, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-cpu-idle"); ok {
		t.Fatalf("不同时间点的 runnable 队列不应佐证单点低 idle: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotReportLoadWithoutCPUOrIOPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 80, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 7.0, CpuIdle: 85, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 6.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("CPU 空闲且无 iowait 佐证时不应报告 load 异常: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotReportLoadForSmallRunnableQueueWithHighIdle(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 85, CpuWait: 0, TaskRunning: 4},
			{Timestamp: start.Add(5 * time.Second), Load1: 8.5, CpuIdle: 88, CpuWait: 0, TaskRunning: 4},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("多核机器上少量 running 且 CPU idle 充足时不应仅凭 load/running 报压力: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseRunnableQueueAtDifferentTimeToCorroborateLoad(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 95, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 95, CpuWait: 0, TaskRunning: 12},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("不同时间点的 runnable 队列不应佐证 load 峰值: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseIOWaitAtDifferentTimeToCorroborateLoad(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 95, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 80, CpuWait: 12, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 80, CpuWait: 12, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("不同时间点的 iowait 不应佐证 load 峰值: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseLowIdleAtDifferentTimeToCorroborateLoad(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 95, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 0, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 0, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(15 * time.Second), Load1: 1.0, CpuIdle: 0, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(20 * time.Second), Load1: 1.0, CpuIdle: 0, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(20*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("不同时间点的低 idle 不应佐证 load 峰值: %+v", finding)
	}
}

func TestBuildTopFindingsLoadRunningQueueMetricUsesHighLoadSamples(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 10, CpuWait: 0, TaskRunning: 2},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 95, CpuWait: 0, TaskRunning: 40},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("高负载且同一时刻低 idle 时应报告 load finding, got=%+v", got)
	}
	if finding.Metrics["task_running_max"] != 2 {
		t.Fatalf("load finding 的 running 队列峰值应来自高负载样本，got=%+v", finding.Metrics)
	}
	if strings.Contains(finding.Summary, "运行队列峰值 40") {
		t.Fatalf("load finding 摘要不应引用低负载时刻的 running 队列峰值: %s", finding.Summary)
	}
}

func TestBuildTopFindingsLoadLowIdleCorroborationMetric(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 5, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("高 load 且同一时刻低 idle 时应报告 load finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh || finding.Metric != "load1" || finding.ObservedValue != 9 {
		t.Fatalf("load low-idle finding 关键字段不正确: %+v", finding)
	}
	if finding.Time != "2026-06-13 10:00:00" {
		t.Fatalf("finding 应指向高 load 峰值时间, got=%q", finding.Time)
	}
	if finding.Metrics["load_idle_low_corroborated"] != 1 {
		t.Fatalf("load finding 应显式记录低 idle 佐证，metrics=%+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "CPU idle 偏低") {
		t.Fatalf("summary 应说明低 idle 佐证: %s", finding.Summary)
	}
}

func TestBuildTopFindingsLoadIOWaitCorroborationMetric(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 75, CpuWait: 12, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 8.5, CpuIdle: 76, CpuWait: 11, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("高 load 且同窗口 iowait 偏高时应报告 load finding, got=%+v", got)
	}
	if finding.Metrics["load_iowait_corroborated"] != 1 {
		t.Fatalf("load finding 应显式记录 iowait 佐证，metrics=%+v", finding.Metrics)
	}
	if finding.Metrics["load_idle_low_corroborated"] != 0 {
		t.Fatalf("iowait 佐证场景不应伪造低 idle 佐证，metrics=%+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "iowait 偏高") {
		t.Fatalf("summary 应说明 iowait 佐证: %s", finding.Summary)
	}
}

func TestBuildTopFindingsReportsLoadWithRunnableQueuePressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 5.0, CpuIdle: 70, CpuWait: 0, TaskRunning: 8},
			{Timestamp: start.Add(5 * time.Second), Load1: 9.0, CpuIdle: 65, CpuWait: 0, TaskRunning: 14},
			{Timestamp: start.Add(10 * time.Second), Load1: 7.0, CpuIdle: 68, CpuWait: 0, TaskRunning: 10},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("load 高且 running 队列明显偏高时应报告 runnable pressure, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("load 硬阈值且 running 队列偏高应为 high, got=%q", finding.Severity)
	}
	if finding.Metrics["task_running_max"] != 14 ||
		finding.Metrics["load_running_queue_corroborated"] != 1 ||
		finding.Metrics["cpu_wait_max"] != 0 ||
		finding.Metrics["cpu_idle_avg"] != 67.66666666666667 {
		t.Fatalf("runnable queue metrics 不完整: %+v", finding.Metrics)
	}
	for _, want := range []string{"运行队列偏高", "CPU 排队压力"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("load finding summary 应说明 runnable 队列佐证 %q: %s", want, finding.Summary)
		}
	}
}

func TestBuildTopFindingsDoesNotReportLoadQueuePressureWhenCPUCountShowsPlentyCapacity(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 18.0, CpuIdle: 65, CpuWait: 0, TaskRunning: 9, CPUCount: 192},
			{Timestamp: start.Add(5 * time.Second), Load1: 21.0, CpuIdle: 67, CpuWait: 0, TaskRunning: 14, CPUCount: 192},
			{Timestamp: start.Add(10 * time.Second), Load1: 17.0, CpuIdle: 66, CpuWait: 0, TaskRunning: 8, CPUCount: 192},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("192 CPU 主机上 load/running 都远低于核数时不应报告 load CPU 队列压力: %+v", finding)
	}
}

func TestBuildTopFindingsUsesLaterNonZeroCPUCount(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 18.0, CpuIdle: 65, CpuWait: 0, TaskRunning: 9},
			{Timestamp: start.Add(5 * time.Second), Load1: 21.0, CpuIdle: 67, CpuWait: 0, TaskRunning: 14, CPUCount: 192},
			{Timestamp: start.Add(10 * time.Second), Load1: 17.0, CpuIdle: 66, CpuWait: 0, TaskRunning: 8, CPUCount: 192},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("CPUCount 只在后续样本出现时也应按 192 核阈值抑制 load/running 误报: %+v", finding)
	}
}

func TestBuildTopFindingsReportsLoadWhenLoadExceedsKnownCPUCount(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 4.5, CpuIdle: 12, CpuWait: 0, TaskRunning: 4, CPUCount: 4},
			{Timestamp: start.Add(5 * time.Second), Load1: 5.2, CpuIdle: 9, CpuWait: 0, TaskRunning: 5, CPUCount: 4},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("load 超过已知 CPU 核数且低 idle 时应报告 load finding, got=%+v", got)
	}
	if finding.Metrics["cpu_count"] != 4 || finding.Metrics["load1_max_per_cpu"] < 1.2 {
		t.Fatalf("已知核数场景应输出核数和归一化 load 指标: %+v", finding.Metrics)
	}
	if finding.Threshold != 4 {
		t.Fatalf("已知 4 CPU 时 hard 阈值应使用 CPU 核数, got=%f", finding.Threshold)
	}
}

func TestBuildTopFindingsDoesNotCallHighIdleRunnableLoadCPUQueuePressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 18.0, CpuIdle: 96, CpuWait: 0, TaskRunning: 9},
			{Timestamp: start.Add(5 * time.Second), Load1: 21.0, CpuIdle: 97, CpuWait: 0, TaskRunning: 10},
			{Timestamp: start.Add(10 * time.Second), Load1: 17.0, CpuIdle: 96, CpuWait: 0, TaskRunning: 8},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("高 load 且同窗口存在 running 峰值时仍应保留 load 线索, got=%+v", got)
	}
	if strings.Contains(finding.Summary, "倾向 CPU 排队压力") {
		t.Fatalf("CPU idle 很高且 iowait 为 0 时不应把 high load 归因为 CPU 排队: %s", finding.Summary)
	}
	for _, want := range []string{"CPU idle 仍高", "不能单独定性为 CPU 饱和"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("summary 应提醒 high idle 下 running 只能作为谨慎线索 %q: %s", want, finding.Summary)
		}
	}
}

func TestBuildTopFindingsRelatesHighIdleLoadToDStateBlockedTasks(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp:   start,
				Load1:       18.0,
				CpuIdle:     96,
				CpuWait:     0,
				TaskRunning: 9,
				Processes: []top.ProcessStats{{
					PID:     19518,
					User:    "root",
					State:   "D",
					Command: "node_ex+",
				}},
			},
			{Timestamp: start.Add(5 * time.Second), Load1: 21.0, CpuIdle: 97, CpuWait: 0, TaskRunning: 10},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("高 load 且同窗口存在 D 状态进程时应保留 load 线索, got=%+v", got)
	}
	for _, want := range []string{"D 状态", "不可中断睡眠", "阻塞任务"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("summary 应把 high idle + high load 关联到 D 状态阻塞任务 %q: %s", want, finding.Summary)
		}
	}
	if strings.Contains(finding.Summary, "CPU 饱和") && !strings.Contains(finding.Summary, "不能单独定性为 CPU 饱和") {
		t.Fatalf("summary 不应把 high idle + D 状态场景归因为 CPU 饱和: %s", finding.Summary)
	}
}

func TestBuildTopFindingsDoesNotReportSingleIOWaitSpikeWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.2, CpuIdle: 80, CpuWait: 25, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-cpu-wait"); ok {
		t.Fatalf("单点 iowait 尖峰且无 load/D 状态佐证时不应报告 iowait 异常: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseRunnableQueueAtDifferentTimeToCorroborateIOWait(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 1.0, CpuIdle: 80, CpuWait: 25, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 12},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-cpu-wait"); ok {
		t.Fatalf("不同时间点的 runnable 队列不应佐证单点 iowait 尖峰: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseHistoricalLoadToCorroborateSingleIOWaitSpike(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 9.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 8.8, CpuIdle: 76, CpuWait: 25, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 8.6, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-cpu-wait"); ok {
		t.Fatalf("历史 load 高不能单独佐证单点 iowait 尖峰: %+v", finding)
	}
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("单点 iowait 尖峰也不能反向佐证历史 load 异常: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotReportSingleSampleIOWaitWithoutCorroboration(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       1.0,
			CpuIdle:     75,
			CpuWait:     25,
			TaskRunning: 1,
		}},
	}

	got := BuildTopFindings(log, at, at)
	if finding, ok := findByRuleID(got, "top-cpu-wait"); ok {
		t.Fatalf("单采样 iowait 高但无 D/load/running 佐证时不应直接报根因: %+v", finding)
	}
}

func TestBuildTopFindingsDoesNotUseDStateAtDifferentTimeToCorroborateIOWait(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp:   start,
				Load1:       1.0,
				CpuIdle:     90,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.2, CpuIdle: 80, CpuWait: 25, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "top-cpu-wait"); ok {
		t.Fatalf("不同时间点的 D 状态进程不应佐证单点 iowait 尖峰: %+v", finding)
	}
	if _, ok := findByRuleID(got, "top-process-d-state"); !ok {
		t.Fatalf("D 状态进程本身仍应作为进程线索保留, got=%+v", got)
	}
}

func TestBuildTopFindingsReportsSingleHardIOWaitWithSameTimeRunnableQueue(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       1.0,
			CpuIdle:     70,
			CpuWait:     25,
			TaskRunning: 12,
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-cpu-wait")
	if !ok {
		t.Fatalf("同采样 hard iowait + runnable 队列应报告 wait finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh || finding.Nature != FindingNatureRisk {
		t.Fatalf("同采样 runnable 佐证的 hard iowait 应保持风险信号, got=%+v", finding)
	}
	if finding.Metrics["cpu_wait_corroborated"] != 1 {
		t.Fatalf("同采样 runnable 队列应标记 iowait corroborated: %+v", finding.Metrics)
	}
}

func TestBuildTopFindingsReportsSingleSoftIOWaitWithSameTimeDStateAsMedium(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       1.0,
			CpuIdle:     80,
			CpuWait:     12,
			TaskRunning: 1,
			Processes: []top.ProcessStats{{
				PID:     3666962,
				User:    "root",
				State:   "D",
				Command: "sshd",
			}},
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-cpu-wait")
	if !ok {
		t.Fatalf("同采样 soft iowait + D 状态应报告 wait finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium || finding.Nature != FindingNatureRisk {
		t.Fatalf("同采样 D 状态佐证的 soft iowait 应为 medium risk, got=%+v", finding)
	}
	if finding.Metrics["cpu_wait_corroborated"] != 1 {
		t.Fatalf("同采样 D 状态应标记 iowait corroborated: %+v", finding.Metrics)
	}
}

func TestBuildTopFindingsDoesNotUseMisalignedDStateToCorroborateSustainedIOWait(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp:   start,
				Load1:       1.0,
				CpuIdle:     90,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 80, CpuWait: 12, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 82, CpuWait: 14, TaskRunning: 1},
			{Timestamp: start.Add(15 * time.Second), Load1: 1.0, CpuIdle: 84, CpuWait: 11, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "top-cpu-wait")
	if !ok {
		t.Fatalf("持续 iowait 高应保留 wait 候选线索, got=%+v", got)
	}
	if finding.Nature != FindingNatureCandidate || finding.Metrics["cpu_wait_corroborated"] != 0 {
		t.Fatalf("错位 D 状态不应佐证持续 iowait: %+v", finding)
	}
	if _, ok := findByRuleID(got, "top-process-d-state"); !ok {
		t.Fatalf("错位 D 状态本身仍应保留为进程线索, got=%+v", got)
	}
}

func TestBuildTopFindingsDoesNotUseLaterPressureToEscalateEarlierDState(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp:   start,
				Load1:       1.0,
				CpuIdle:     90,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.2, CpuIdle: 80, CpuWait: 25, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("D 状态进程本身仍应作为进程线索保留, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("不同时刻的 iowait 不应把单次 D 状态升级为高风险, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Metrics["d_state_pressure_corroborated"] != 0 {
		t.Fatalf("D 状态所在采样无压力佐证，pressure metric 应为 0: %+v", finding.Metrics)
	}
	if strings.Contains(finding.Summary, "同时存在") {
		t.Fatalf("D 状态摘要不应引用其他时间点的压力佐证: %s", finding.Summary)
	}
}

func TestBuildTopFindingsKeepsSingleZombieAsLowSeverity(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, TaskZombie: 0, CpuIdle: 90},
			{Timestamp: start.Add(5 * time.Second), TaskZombie: 1, CpuIdle: 88},
			{Timestamp: start.Add(10 * time.Second), TaskZombie: 0, CpuIdle: 92},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-zombie")
	if !ok {
		t.Fatalf("expected zombie finding, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("single transient zombie should be low severity, got=%q", finding.Severity)
	}
	if finding.Metrics["task_zombie_max"] != 1 || finding.Metrics["task_zombie_sample_count"] != 1 {
		t.Fatalf("zombie metrics mismatch: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "单次") || !strings.Contains(finding.Summary, "不等同于 CPU 或内存压力") {
		t.Fatalf("summary should explain evidence-only zombie classification: %s", finding.Summary)
	}
}

func TestBuildTopFindingsReportsPersistentSingleZombieAsMediumSeverity(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, TaskZombie: 1, CpuIdle: 90},
			{Timestamp: start.Add(5 * time.Second), TaskZombie: 1, CpuIdle: 88},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-zombie")
	if !ok {
		t.Fatalf("expected zombie finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("persistent single zombie should be medium severity, got=%q", finding.Severity)
	}
	if finding.Metrics["task_zombie_sample_count"] != 2 {
		t.Fatalf("zombie sample count metric mismatch: %+v", finding.Metrics)
	}
}

func TestBuildTopFindingsReportsMultipleZombiesAsHighSeverity(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, TaskZombie: 2, CpuIdle: 90},
		},
	}

	got := BuildTopFindings(log, start, start)
	finding, ok := findByRuleID(got, "top-zombie")
	if !ok {
		t.Fatalf("expected zombie finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("multiple zombies should be high severity, got=%q", finding.Severity)
	}
}

func TestBuildTopFindingsKeepsSingleDStateAsLowSeverityWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 1.0, CpuIdle: 90, CpuWait: 0, TaskRunning: 1},
			{
				Timestamp:   start.Add(5 * time.Second),
				Load1:       1.2,
				CpuIdle:     88,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.1, CpuIdle: 92, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("single transient D-state without pressure should be low severity, got=%q", finding.Severity)
	}
	if finding.ObservedValue != 1 {
		t.Fatalf("observed count mismatch: got=%.2f", finding.ObservedValue)
	}
	if finding.Metrics["d_state_process_count"] != 1 {
		t.Fatalf("process count metric missing: %+v", finding.Metrics)
	}
	if finding.Metrics["cpu_wait_max"] != 0 ||
		finding.Metrics["load1_max"] >= config.Default().Top.LoadHighSoft ||
		finding.Metrics["cpu_idle_avg"] <= config.Default().Top.CPUIdleSoftPct {
		t.Fatalf("pressure metrics should show no iowait/runnable/idle corroboration: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "3666962/sshd") {
		t.Fatalf("summary should include representative D-state process: %s", finding.Summary)
	}
	if !strings.Contains(finding.Summary, "单次") || !strings.Contains(finding.Summary, "未见 iowait、运行队列或低 idle 佐证") {
		t.Fatalf("summary should explain low-severity evidence-only classification: %s", finding.Summary)
	}
}

func TestBuildTopFindingsDoesNotTreatSmallRunningAsDStatePressureOnLargeCPUHost(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       18,
			CpuIdle:     95,
			CpuWait:     0,
			TaskRunning: 14,
			CPUCount:    192,
			Processes: []top.ProcessStats{{
				PID:     3666962,
				User:    "root",
				State:   "D",
				Command: "sshd",
			}},
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityLow || finding.Nature != FindingNatureCandidate {
		t.Fatalf("192 核主机少量 running 不应把单个 D 状态升级为压力风险: %+v", finding)
	}
	if finding.Metrics["d_state_pressure_corroborated"] != 0 ||
		finding.Metrics["task_running_max"] != 14 {
		t.Fatalf("running=14 在 192 核主机上不应作为 D-state 压力佐证: %+v", finding.Metrics)
	}
	if loadFinding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("192 核主机 load/running 低于核数阈值时不应生成 load 风险: %+v", loadFinding)
	}
}

func TestBuildTopFindingsDoesNotPresentSpreadDStatePIDsAsConcurrentProcessCount(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp:   start,
				Load1:       1.0,
				CpuIdle:     90,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     1001,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			},
			{
				Timestamp:   start.Add(5 * time.Second),
				Load1:       1.0,
				CpuIdle:     92,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     1002,
					User:    "root",
					State:   "D",
					Command: "backup",
				}},
			},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("spread transient D-state PIDs without pressure should remain low severity, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.ObservedValue != 1 {
		t.Fatalf("observed value should be max concurrent D-state processes, got=%.2f finding=%+v", finding.ObservedValue, finding)
	}
	if finding.Metrics["d_state_unique_process_count"] != 2 ||
		finding.Metrics["d_state_max_concurrent_process_count"] != 1 ||
		finding.Metrics["d_state_process_count"] != 1 {
		t.Fatalf("D 状态计数应区分唯一 PID 和并发峰值: %+v", finding.Metrics)
	}
	if strings.Contains(finding.Summary, "发现 2 个不可中断睡眠进程") {
		t.Fatalf("summary 不应把跨采样累计 PID 表述成并发进程数: %s", finding.Summary)
	}
	for _, want := range []string{"范围内 2 个不同 PID", "单次峰值 1 个", "2 个采样点"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("summary 缺少跨采样 D 状态计数语义 %q: %s", want, finding.Summary)
		}
	}
}

func TestBuildTopFindingsKeepsSingleDStateLowWhenOnlyLoadIsHigh(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       6.2,
			CpuIdle:     84.2,
			CpuWait:     0.1,
			TaskRunning: 1,
			Processes: []top.ProcessStats{{
				PID:     3666962,
				User:    "root",
				State:   "D",
				Command: "sshd",
			}},
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("single D-state with only historical load high should remain low severity, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Metrics["d_state_pressure_corroborated"] != 0 ||
		finding.Metrics["task_running_max"] != 1 ||
		finding.Metrics["load1_max"] != 6.2 {
		t.Fatalf("pressure metrics should keep load as context but not corroboration: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "单次") || !strings.Contains(finding.Summary, "未见 iowait、运行队列或低 idle 佐证") {
		t.Fatalf("summary should explain low-severity evidence-only classification: %s", finding.Summary)
	}
	if loadFinding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("load without runnable/cpu/io pressure should not become a load finding: %+v", loadFinding)
	}
}

func TestBuildTopFindingsKeepsDStateLowForSmallRunnableQueueWithHighIdle(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       9.0,
			CpuIdle:     85,
			CpuWait:     0,
			TaskRunning: 4,
			Processes: []top.ProcessStats{{
				PID:     3666962,
				User:    "root",
				State:   "D",
				Command: "sshd",
			}},
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityLow {
		t.Fatalf("少量 running 且 CPU idle 充足时不应把单个 D 状态升级为压力问题: %+v", finding)
	}
	if finding.Metrics["d_state_pressure_corroborated"] != 0 {
		t.Fatalf("running=4 在高 idle/低 iowait 场景不应作为 D 状态压力佐证: %+v", finding.Metrics)
	}
}

func TestBuildTopFindingsReportsDStateProcess(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 5, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			CpuIdle:   80,
			Processes: []top.ProcessStats{{
				PID:        3666962,
				User:       "root",
				State:      "D",
				Command:    "sshd",
				CPUPercent: 0,
				MemPercent: 0,
			}, {
				PID:        19518,
				User:       "oracle",
				State:      "D",
				Command:    "node_ex+",
				CPUPercent: 0,
				MemPercent: 0,
			}},
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("severity mismatch: got=%q", finding.Severity)
	}
	if finding.Target != "process" {
		t.Fatalf("target mismatch: got=%q", finding.Target)
	}
	if finding.Time != "2026-06-13 10:00:05" {
		t.Fatalf("time mismatch: got=%q", finding.Time)
	}
	if finding.ObservedValue != 2 {
		t.Fatalf("observed count mismatch: got=%.2f", finding.ObservedValue)
	}
	if finding.Metrics["d_state_process_count"] != 2 {
		t.Fatalf("process count metric missing: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "3666962/sshd") || !strings.Contains(finding.Summary, "19518/node_ex+") {
		t.Fatalf("summary should include representative D-state processes: %s", finding.Summary)
	}
}

func TestBuildTopFindingsReportsDStateProcessAsHighWithIOWaitPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 5, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp: at,
			Load1:     1.5,
			CpuIdle:   70,
			CpuWait:   25,
			Processes: []top.ProcessStats{{
				PID:     3666962,
				User:    "root",
				State:   "D",
				Command: "sshd",
			}},
		}},
	}

	got := BuildTopFindings(log, at, at)
	finding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("expected D-state process finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("D-state with iowait pressure should be high severity, got=%q", finding.Severity)
	}
	if finding.Metrics["d_state_pressure_corroborated"] != 1 {
		t.Fatalf("pressure corroboration metric missing: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "同时存在 iowait、运行队列或低 idle 佐证") {
		t.Fatalf("summary should explain pressure corroboration: %s", finding.Summary)
	}
	waitFinding, ok := findByRuleID(got, "top-cpu-wait")
	if !ok {
		t.Fatalf("D 状态闭合证据链时应同时保留 iowait finding, got=%+v", got)
	}
	if waitFinding.Severity != SeverityHigh {
		t.Fatalf("D 状态伴随硬 iowait 峰值应为 high, got=%q", waitFinding.Severity)
	}
}

func TestBuildTopFindingsMarksSustainedIOWaitWithoutCorroborationAsCandidate(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 1.0, CpuIdle: 80, CpuWait: 12, TaskRunning: 1},
			{Timestamp: start.Add(5 * time.Second), Load1: 1.0, CpuIdle: 82, CpuWait: 14, TaskRunning: 1},
			{Timestamp: start.Add(10 * time.Second), Load1: 1.0, CpuIdle: 84, CpuWait: 11, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "top-cpu-wait")
	if !ok {
		t.Fatalf("持续 iowait 高即使缺少 D/running 佐证也应保留为候选线索, got=%+v", got)
	}
	if finding.Severity != SeverityMedium || finding.Nature != FindingNatureCandidate {
		t.Fatalf("无佐证的持续 iowait 不应作为风险信号, got=%+v", finding)
	}
	if finding.Metrics["cpu_wait_corroborated"] != 0 {
		t.Fatalf("无 D/running 佐证时不应标记 iowait corroborated: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "未见同采样 D 状态或运行队列佐证") {
		t.Fatalf("summary 应说明 iowait 缺少佐证: %s", finding.Summary)
	}
}

func TestBuildTopFindingsReportsHighLoadWithDStateOnly(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{
				Timestamp:   start,
				Load1:       9.0,
				CpuIdle:     95,
				CpuWait:     0,
				TaskRunning: 1,
				Processes: []top.ProcessStats{{
					PID:     3666962,
					User:    "root",
					State:   "D",
					Command: "sshd",
				}},
			},
			{Timestamp: start.Add(5 * time.Second), Load1: 8.6, CpuIdle: 96, CpuWait: 0, TaskRunning: 1},
		},
	}

	got := BuildTopFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("高 load 且同窗口仅有 D 状态进程时也应保留阻塞型 load 线索, got=%+v", got)
	}
	if finding.Severity != SeverityHigh || finding.Nature != FindingNatureRisk {
		t.Fatalf("D 状态佐证的高 load 应保持风险信号, got=%+v", finding)
	}
	if finding.Metrics["load_d_state_corroborated"] != 1 ||
		finding.Metrics["load_idle_low_corroborated"] != 0 ||
		finding.Metrics["load_iowait_corroborated"] != 0 {
		t.Fatalf("D-only load metrics 不正确: %+v", finding.Metrics)
	}
	for _, want := range []string{"D 状态", "CPU idle 仍高", "不能单独定性为 CPU 饱和"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("D-only load summary 缺少 %q: %s", want, finding.Summary)
		}
	}
}
