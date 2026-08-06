package findings

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
)

func TestBuildIOStatFindingsRealArchiveMergedRegression(t *testing.T) {
	log := parseRealArchiveIOStat(t, realArchiveDir("oswiostat"))
	if len(log.Data) != 7745 {
		t.Fatalf("真实 iostat archive 解析点数变化: got=%d", len(log.Data))
	}
	if got := len(log.GetAllDevices()); got != 19 {
		t.Fatalf("真实 iostat archive 设备数变化: got=%d", got)
	}

	start, end := log.GetTimeRange()
	got := BuildIOStatFindings(log, start, end)

	queueFinding, ok := findByRuleID(got, "iostat-queue-sda")
	if !ok {
		t.Fatalf("真实 archive 应保留 sda 队列高风险, got=%+v", got)
	}
	if queueFinding.Nature != FindingNatureRisk ||
		queueFinding.Severity != SeverityHigh ||
		queueFinding.Time != "2026-04-23 05:12:10" ||
		queueFinding.Metric != "avg_queue_peak" ||
		queueFinding.ObservedValue != 36.28 {
		t.Fatalf("sda 队列高风险关键字段变化: %+v", queueFinding)
	}

	writeFinding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("真实 archive 应保留 nvme11n1 写延迟候选, got=%+v", got)
	}
	if writeFinding.Nature != FindingNatureCandidate ||
		writeFinding.Severity != SeverityHigh ||
		writeFinding.Time != "2026-04-21 03:29:12" ||
		writeFinding.Metric != "write_await_ms" ||
		writeFinding.ObservedValue != 300.11 ||
		writeFinding.Metrics["latency_system_pressure"] != 0 {
		t.Fatalf("nvme11n1 写延迟候选关键字段变化: %+v", writeFinding)
	}

	for _, ruleID := range []string{
		"iostat-read-latency-nvme11n1",
		"iostat-read-latency-nvme13n1",
		"iostat-read-latency-nvme15n1",
		"iostat-read-latency-nvme1n1",
		"iostat-read-latency-nvme3n1",
		"iostat-read-latency-nvme9n1",
	} {
		finding, ok := findByRuleID(got, ruleID)
		if !ok {
			t.Fatalf("真实 archive 应保留读延迟候选 %s, got=%+v", ruleID, got)
		}
		if finding.Nature != FindingNatureCandidate ||
			finding.Severity != SeverityHigh ||
			finding.Time != "2026-04-21 05:49:10" ||
			finding.Metric != "read_await_ms" ||
			finding.Metrics["latency_system_pressure"] != 0 ||
			finding.Metrics["total_iops_at_peak"] <= 0 {
			t.Fatalf("真实读延迟候选关键字段变化 %s: %+v", ruleID, finding)
		}
	}

}

func TestBuildMemInfoFindingsRealArchiveMergedRegression(t *testing.T) {
	log := parseRealArchiveMemInfo(t, realArchiveDir("oswmeminfo"))
	if len(log.Data) != 7031 {
		t.Fatalf("真实 meminfo archive 解析点数变化: got=%d", len(log.Data))
	}

	start, end := log.GetTimeRange()
	got := BuildMemInfoFindings(log, start, end)

	anonFinding, ok := findByRuleID(got, "meminfo-anon-growth")
	if !ok {
		t.Fatalf("真实 archive 应保留匿名页增长 finding, got=%+v", got)
	}
	if anonFinding.Nature != FindingNatureCandidate ||
		anonFinding.Severity != SeverityLow ||
		anonFinding.Time != "2026-04-23 05:14:35" ||
		anonFinding.ObservedValue < 14000 ||
		anonFinding.ObservedValue > 14300 ||
		anonFinding.Metrics["anon_pressure_corroborated"] != 0 {
		t.Fatalf("匿名页增长 finding 关键字段变化: %+v", anonFinding)
	}

	for _, ruleID := range []string{
		"meminfo-available",
		"meminfo-swap-usage",
		"meminfo-commit-pressure",
		"meminfo-slab",
		"meminfo-writeback-pressure",
	} {
		if finding, ok := findByRuleID(got, ruleID); ok {
			t.Fatalf("真实 meminfo archive 当前不应误报 %s: %+v", ruleID, finding)
		}
	}
}

func TestBuildTopFindingsRealArchiveMergedRegression(t *testing.T) {
	log := parseRealArchiveTop(t, realArchiveDir("oswtop"))
	if len(log.Snapshots) != 5271 {
		t.Fatalf("真实 top archive 解析点数变化: got=%d", len(log.Snapshots))
	}

	start, end := log.GetTimeRange()
	got := BuildTopFindings(log, start, end)

	loadFinding, ok := findByRuleID(got, "top-load-high")
	if !ok {
		t.Fatalf("真实 archive 应保留 high load finding, got=%+v", got)
	}
	if loadFinding.Nature != FindingNatureRisk ||
		loadFinding.Severity != SeverityHigh ||
		loadFinding.Time != "2026-04-21 05:57:16" ||
		loadFinding.ObservedValue != 28.50 ||
		loadFinding.Metrics["load_idle_low_corroborated"] != 0 ||
		loadFinding.Metrics["load_d_state_corroborated"] != 1 ||
		loadFinding.Metrics["cpu_wait_max"] >= 1 ||
		loadFinding.Metrics["cpu_idle_avg"] <= 90 {
		t.Fatalf("真实 high load 语义变化，应保持 D 状态佐证且不定性 CPU 饱和: %+v", loadFinding)
	}
	for _, want := range []string{"CPU idle 仍高", "不能单独定性为 CPU 饱和"} {
		if !strings.Contains(loadFinding.Summary, want) {
			t.Fatalf("真实 high load 摘要应保留 high-idle 谨慎归因 %q: %s", want, loadFinding.Summary)
		}
	}
	for _, ruleID := range []string{"top-cpu-idle", "top-cpu-wait"} {
		if finding, ok := findByRuleID(got, ruleID); ok {
			t.Fatalf("真实 top archive 当前不应误报 %s: %+v", ruleID, finding)
		}
	}

	zombieFinding, ok := findByRuleID(got, "top-zombie")
	if !ok {
		t.Fatalf("真实 archive 应保留 zombie finding, got=%+v", got)
	}
	if zombieFinding.Nature != FindingNatureRisk ||
		zombieFinding.Severity != SeverityHigh ||
		zombieFinding.Time != "2026-04-21 01:18:33" ||
		zombieFinding.ObservedValue != 2 {
		t.Fatalf("真实 zombie finding 关键字段变化: %+v", zombieFinding)
	}

	dStateFinding, ok := findByRuleID(got, "top-process-d-state")
	if !ok {
		t.Fatalf("真实 archive 应保留 D 状态候选线索, got=%+v", got)
	}
	if dStateFinding.Nature != FindingNatureCandidate ||
		dStateFinding.Severity != SeverityMedium ||
		dStateFinding.Time != "2026-04-21 05:48:40" ||
		dStateFinding.ObservedValue != 2 ||
		dStateFinding.Metrics["d_state_unique_process_count"] != 45 ||
		dStateFinding.Metrics["d_state_snapshot_count"] != 53 ||
		dStateFinding.Metrics["d_state_observation_count"] != 55 {
		t.Fatalf("真实 D 状态候选关键字段变化: %+v", dStateFinding)
	}
}

func TestBuildTopFindingsRealArchiveWithMPStatCPUCountSuppressesLoadFalsePositive(t *testing.T) {
	log := parseRealArchiveTop(t, realArchiveDir("oswtop"))
	for i := range log.Snapshots {
		log.Snapshots[i].CPUCount = 192
	}

	start, end := log.GetTimeRange()
	got := BuildTopFindings(log, start, end)
	if finding, ok := findByRuleID(got, "top-load-high"); ok {
		t.Fatalf("真实 archive 有 192 CPU 核数时不应把 load 28.5/running 9 误报为 CPU 队列压力: %+v", finding)
	}
	if _, ok := findByRuleID(got, "top-zombie"); !ok {
		t.Fatalf("注入 CPUCount 不应影响 zombie finding, got=%+v", got)
	}
	if _, ok := findByRuleID(got, "top-process-d-state"); !ok {
		t.Fatalf("注入 CPUCount 不应影响 D 状态候选线索, got=%+v", got)
	}
}

// realArchiveDir points at large real OSWbb samples kept outside the engineering tree.
func realArchiveDir(parts ...string) string {
	allParts := append([]string{"..", "..", "other", "archive"}, parts...)
	return filepath.Join(allParts...)
}

func parseRealArchiveIOStat(t *testing.T, dir string) *iostat.IOStatLog {
	t.Helper()
	files := requireArchiveFiles(t, dir, "*_iostat_*.dat", 11)
	merged := &iostat.IOStatLog{}
	for _, file := range files {
		parsed, err := (&iostat.IOStatParser{}).ParseFile(file)
		if err != nil {
			t.Fatalf("解析真实 iostat archive 失败 %s: %v", file, err)
		}
		merged.Data = append(merged.Data, parsed.Data...)
		if merged.Header == "" {
			merged.Header = parsed.Header
		}
	}
	sort.Slice(merged.Data, func(i, j int) bool {
		return merged.Data[i].Timestamp.Before(merged.Data[j].Timestamp)
	})
	return merged
}

func parseRealArchiveMemInfo(t *testing.T, dir string) *meminfo.MemInfoLog {
	t.Helper()
	files := requireArchiveFiles(t, dir, "*_meminfo_*.dat", 10)
	merged := &meminfo.MemInfoLog{}
	for _, file := range files {
		parsed, err := (&meminfo.MemInfoParser{}).ParseFile(file)
		if err != nil {
			t.Fatalf("解析真实 meminfo archive 失败 %s: %v", file, err)
		}
		merged.Data = append(merged.Data, parsed.Data...)
	}
	sort.Slice(merged.Data, func(i, j int) bool {
		return merged.Data[i].Timestamp.Before(merged.Data[j].Timestamp)
	})
	return merged
}

func parseRealArchiveTop(t *testing.T, dir string) *top.TopLog {
	t.Helper()
	files := requireArchiveFiles(t, dir, "*_top_*.dat", 11)
	merged := &top.TopLog{}
	for _, file := range files {
		parsed, err := top.NewTopParser().ParseFile(file)
		if err != nil {
			t.Fatalf("解析真实 top archive 失败 %s: %v", file, err)
		}
		merged.Snapshots = append(merged.Snapshots, parsed.Snapshots...)
	}
	sort.Slice(merged.Snapshots, func(i, j int) bool {
		return merged.Snapshots[i].Timestamp.Before(merged.Snapshots[j].Timestamp)
	})
	return merged
}

func requireArchiveFiles(t *testing.T, dir, pattern string, want int) []string {
	t.Helper()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skipf("跳过需要本地真实 OSWbb archive 的回归测试: %s", dir)
	} else if err != nil {
		t.Fatalf("检查 archive 目录失败 %s: %v", dir, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatalf("archive glob 失败: %v", err)
	}
	if len(files) != want {
		t.Fatalf("archive 文件数量变化: pattern=%s got=%d want=%d files=%v", pattern, len(files), want, files)
	}
	sort.Strings(files)
	return files
}
