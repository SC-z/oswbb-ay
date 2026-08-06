package diagnosis

import (
	"fmt"
	"oswbb-analyse/internal/config"
	rulefindings "oswbb-analyse/pkg/findings"
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
	"sort"
	"strings"
	"time"
)

const (
	contextTimeLayout = "2006-01-02 15:04:05"

	topProcessEvidenceLimit  = 8
	topProcessCommandMaxRune = 80
)

type BuildInput struct {
	Hostname string
	Start    time.Time
	End      time.Time
	IOStat   *iostat.IOStatLog
	MemInfo  *meminfo.MemInfoLog
	Top      *top.TopLog
	Config   config.Config
}

func BuildContext(input BuildInput) Context {
	cfg := input.Config
	if cfg == (config.Config{}) {
		cfg = config.Default()
	}
	context := Context{
		Hostname:  input.Hostname,
		StartTime: formatTimestamp(input.Start),
		EndTime:   formatTimestamp(input.End),
		Notes: []string{
			"仅允许基于 evidence 中的 signal_id 给出结论，不能虚构新的指标或时间点。",
			"hard 表示已触发规则或明显异常，soft 表示接近阈值或组合型线索。",
		},
	}

	var evidence []Evidence
	if input.IOStat != nil {
		context.Modules = append(context.Modules, "iostat")
		evidence = append(evidence, buildIOStatEvidenceWithConfig(input.IOStat, input.Start, input.End, cfg.Iostat)...)
	}
	var memInfoFindings []rulefindings.Finding
	if input.MemInfo != nil {
		context.Modules = append(context.Modules, "meminfo")
		memInfoFindings = rulefindings.BuildMemInfoFindingsWithConfig(input.MemInfo, input.Start, input.End, cfg.Meminfo)
		evidence = append(evidence, evidenceFromFindings(memInfoFindings)...)
	}
	if input.Top != nil {
		context.Modules = append(context.Modules, "top")
		evidence = append(evidence, buildTopEvidenceWithConfig(input.Top, input.Start, input.End, memInfoFindings, cfg.Top)...)
	}

	evidence = append(evidence, buildCrossEvidence(evidence, cfg.Top)...)
	sortEvidence(evidence)
	evidence = trimEvidence(evidence, 18)
	context.Evidence = evidence
	return context
}

func trimEvidence(evidence []Evidence, limit int) []Evidence {
	if limit <= 0 || len(evidence) <= limit {
		return evidence
	}

	buckets := make(map[string][]Evidence)
	for _, item := range evidence {
		buckets[item.Source] = append(buckets[item.Source], item)
	}

	selected := make([]Evidence, 0, limit)
	selectedIDs := make(map[string]struct{}, limit)
	addIfMissing := func(item Evidence) bool {
		if len(selected) >= limit {
			return false
		}
		if _, exists := selectedIDs[item.ID]; exists {
			return false
		}
		selected = append(selected, item)
		selectedIDs[item.ID] = struct{}{}
		return true
	}

	// 跨模块证据是 AI 诊断的核心，上限内优先全部保留。
	for _, item := range buckets["cross"] {
		if !addIfMissing(item) {
			return selected
		}
	}

	sourceOrder := []string{"meminfo", "top", "iostat"}

	// 先保证每个非空来源至少保留一个代表证据，避免 iostat 独占上下文。
	for _, source := range sourceOrder {
		if len(buckets[source]) == 0 {
			continue
		}
		if addIfMissing(buckets[source][0]) {
			buckets[source] = buckets[source][1:]
		}
	}

	// 再按来源轮转填充剩余名额，兼顾来源覆盖和单源内部优先级。
	for len(selected) < limit {
		progressed := false
		for _, source := range sourceOrder {
			if len(buckets[source]) == 0 {
				continue
			}
			item := buckets[source][0]
			buckets[source] = buckets[source][1:]
			if addIfMissing(item) {
				progressed = true
			}
			if len(selected) >= limit {
				break
			}
		}
		if !progressed {
			break
		}
	}

	return selected
}

func buildIOStatEvidence(log *iostat.IOStatLog, start, end time.Time) []Evidence {
	return buildIOStatEvidenceWithConfig(log, start, end, config.Default().Iostat)
}

func buildIOStatEvidenceWithConfig(log *iostat.IOStatLog, start, end time.Time, cfg config.IostatConfig) []Evidence {
	findings := rulefindings.BuildIOStatFindingsWithConfig(log, start, end, cfg)
	if len(findings) == 0 {
		return nil
	}

	return evidenceFromFindings(findings)
}

func evidenceFromFindings(findings []rulefindings.Finding) []Evidence {
	evidence := make([]Evidence, 0, len(findings))
	for _, finding := range findings {
		evidence = append(evidence, evidenceFromFinding(finding))
	}
	return evidence
}

func evidenceFromFinding(finding rulefindings.Finding) Evidence {
	return Evidence{
		ID:            finding.RuleID,
		Source:        finding.Source,
		Level:         signalLevelFromFindingSeverity(finding.Severity),
		Title:         finding.Title,
		Summary:       finding.Summary,
		Category:      finding.Category,
		Target:        finding.Target,
		Metric:        finding.Metric,
		Operator:      finding.Operator,
		Threshold:     finding.Threshold,
		ObservedValue: finding.ObservedValue,
		EvidenceRef:   finding.EvidenceRef,
		Time:          finding.Time,
		WindowStart:   finding.WindowStart,
		WindowEnd:     finding.WindowEnd,
		Metrics:       finding.Metrics,
		Tags:          finding.Tags,
	}
}

func signalLevelFromFindingSeverity(severity rulefindings.Severity) SignalLevel {
	switch severity {
	case rulefindings.SeverityHigh:
		return SignalLevelHard
	case rulefindings.SeverityMedium, rulefindings.SeverityLow:
		return SignalLevelSoft
	default:
		return ""
	}
}

func buildMemInfoEvidence(log *meminfo.MemInfoLog, start, end time.Time) []Evidence {
	return buildMemInfoEvidenceWithConfig(log, start, end, config.Default().Meminfo)
}

func buildMemInfoEvidenceWithConfig(log *meminfo.MemInfoLog, start, end time.Time, cfg config.MeminfoConfig) []Evidence {
	findings := rulefindings.BuildMemInfoFindingsWithConfig(log, start, end, cfg)
	if len(findings) == 0 {
		return nil
	}

	return evidenceFromFindings(findings)
}

func buildTopEvidence(log *top.TopLog, start, end time.Time, memInfoFindings []rulefindings.Finding) []Evidence {
	return buildTopEvidenceWithConfig(log, start, end, memInfoFindings, config.Default().Top)
}

func buildTopEvidenceWithConfig(log *top.TopLog, start, end time.Time, memInfoFindings []rulefindings.Finding, cfg config.TopConfig) []Evidence {
	findings := rulefindings.BuildTopFindingsWithConfig(log, start, end, cfg)
	processEvidence := buildTopProcessRowsEvidence(log, start, end, findings, memInfoFindings, cfg)
	if len(findings) == 0 && processEvidence == nil {
		return nil
	}

	evidence := make([]Evidence, 0, len(findings)+1)
	for _, finding := range findings {
		evidence = append(evidence, evidenceFromFinding(finding))
	}
	if processEvidence != nil {
		evidence = append(evidence, *processEvidence)
	}
	return evidence
}

type topProcessCandidate struct {
	at       time.Time
	process  top.ProcessStats
	reason   string
	priority int
}

func buildTopProcessRowsEvidence(log *top.TopLog, start, end time.Time, findings, memInfoFindings []rulefindings.Finding, cfg config.TopConfig) *Evidence {
	if log == nil {
		return nil
	}
	cfg = cfg.WithDefaults()

	candidateByKey := make(map[string]topProcessCandidate)
	dStateKeys := make(map[string]struct{})
	zStateKeys := make(map[string]struct{})
	dStateCount := 0
	zStateCount := 0
	maxCPU := 0.0
	maxMem := 0.0
	for _, snap := range log.Snapshots {
		if snap.Timestamp.Before(start) || snap.Timestamp.After(end) {
			continue
		}
		for _, process := range snap.Processes {
			if process.CPUPercent > maxCPU {
				maxCPU = process.CPUPercent
			}
			if process.MemPercent > maxMem {
				maxMem = process.MemPercent
			}
			reason, priority, selected := topProcessReason(process, cfg)
			processKey := topProcessKey(process, "")
			if process.State == "D" {
				dStateKeys[processKey] = struct{}{}
			}
			if process.State == "Z" {
				zStateKeys[processKey] = struct{}{}
			}
			if !selected {
				continue
			}
			candidate := topProcessCandidate{
				at:       snap.Timestamp,
				process:  process,
				reason:   reason,
				priority: priority,
			}
			candidateKey := topProcessKey(process, reason)
			if existing, exists := candidateByKey[candidateKey]; !exists || betterTopProcessCandidate(candidate, existing) {
				candidateByKey[candidateKey] = candidate
			}
		}
	}
	dStateCount = len(dStateKeys)
	zStateCount = len(zStateKeys)
	candidates := make([]topProcessCandidate, 0, len(candidateByKey))
	for _, candidate := range candidateByKey {
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return nil
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		if candidates[i].process.CPUPercent != candidates[j].process.CPUPercent {
			return candidates[i].process.CPUPercent > candidates[j].process.CPUPercent
		}
		if candidates[i].process.MemPercent != candidates[j].process.MemPercent {
			return candidates[i].process.MemPercent > candidates[j].process.MemPercent
		}
		if !candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].at.Before(candidates[j].at)
		}
		return candidates[i].process.PID < candidates[j].process.PID
	})
	if len(candidates) > topProcessEvidenceLimit {
		candidates = candidates[:topProcessEvidenceLimit]
	}

	reasonCounts := topProcessReasonCounts(candidates)
	level := SignalLevelSoft
	dStateFinding, hasDStateFinding := findingByRuleID(findings, "top-process-d-state")
	zombieFinding, hasZombieFinding := findingByRuleID(findings, "top-zombie")
	if dStateCount > 0 && hasDStateFinding {
		level = signalLevelFromFindingSeverity(dStateFinding.Severity)
	}
	if zStateCount > 0 && hasZombieFinding && signalLevelFromFindingSeverity(zombieFinding.Severity) == SignalLevelHard {
		level = SignalLevelHard
	}
	cpuPressureCorroborated := topCPUProcessPressureCorroborated(findings)
	memPressureCorroborated, memPressureMetrics := topMemProcessPressureCorroboration(memInfoFindings)
	rows := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		process := candidate.process
		rows = append(rows, fmt.Sprintf("%s pid=%d/%s/%s/%s cpu=%.1f%% mem=%.1f%% res=%.2fMB reason=%s",
			candidate.at.Format(contextTimeLayout),
			process.PID,
			process.User,
			process.State,
			truncateProcessCommand(process.Command),
			process.CPUPercent,
			process.MemPercent,
			float64(process.ResKB)/1024.0,
			candidate.reason,
		))
	}
	summary := topProcessRowsSummary(rows, reasonCounts, cpuPressureCorroborated, memPressureCorroborated)

	metrics := map[string]float64{
		"selected_process_rows":        float64(len(candidates)),
		"d_state_process_count":        float64(dStateCount),
		"d_state_unique_process_count": float64(dStateCount),
		"z_state_process_count":        float64(zStateCount),
		"high_cpu_process_count":       float64(reasonCounts["high_cpu"]),
		"high_mem_process_count":       float64(reasonCounts["high_mem"]),
		"max_process_cpu_percent":      maxCPU,
		"max_process_mem_percent":      maxMem,
		"process_evidence_row_cap":     topProcessEvidenceLimit,
		"cpu_pressure_corroborated":    cpuPressureCorroborated,
		"mem_pressure_corroborated":    memPressureCorroborated,
	}
	if hasDStateFinding {
		for _, key := range []string{
			"d_state_process_count",
			"d_state_max_concurrent_process_count",
			"d_state_unique_process_count",
			"d_state_pressure_corroborated",
			"d_state_observation_count",
			"d_state_snapshot_count",
			"d_state_persistent_process_count",
			"cpu_idle_avg",
			"cpu_idle_min",
			"cpu_wait_max",
			"load1_avg",
			"load1_max",
			"task_running_max",
		} {
			if value, ok := dStateFinding.Metrics[key]; ok {
				metrics[key] = value
			}
		}
	}
	if hasZombieFinding {
		for _, key := range []string{
			"task_zombie_max",
			"task_zombie_sample_count",
		} {
			if value, ok := zombieFinding.Metrics[key]; ok {
				metrics[key] = value
			}
		}
	}
	for key, value := range memPressureMetrics {
		metrics[key] = value
	}

	return &Evidence{
		ID:            "top-process-rows",
		Source:        "top",
		Level:         level,
		Title:         "top 代表进程行",
		Summary:       summary,
		Category:      "process_rows",
		Target:        "process",
		Metric:        "selected_process_rows",
		Operator:      ">",
		Threshold:     0,
		ObservedValue: float64(len(candidates)),
		Metrics:       metrics,
		Tags:          []string{"top", "process", "process_rows"},
	}
}

func topProcessReasonCounts(candidates []topProcessCandidate) map[string]int {
	counts := make(map[string]int)
	for _, candidate := range candidates {
		counts[candidate.reason]++
	}
	return counts
}

func topCPUProcessPressureCorroborated(findings []rulefindings.Finding) float64 {
	for _, ruleID := range []string{"top-cpu-idle", "top-load-high"} {
		if _, exists := findingByRuleID(findings, ruleID); exists {
			return 1
		}
	}
	return 0
}

func topMemProcessPressureCorroboration(findings []rulefindings.Finding) (float64, map[string]float64) {
	metrics := make(map[string]float64)
	corroborated := 0.0
	for _, ruleID := range []string{"meminfo-available", "meminfo-swap-usage", "meminfo-commit-pressure", "meminfo-anon-growth"} {
		finding, exists := findingByRuleID(findings, ruleID)
		if !exists {
			continue
		}
		corroborated = 1
		for _, key := range []string{
			"mem_available_pct",
			"swap_used_pct",
			"committed_pct",
			"anon_growth_window_mb",
			"anon_growth_rate_mb_per_sample",
		} {
			if value, ok := finding.Metrics[key]; ok {
				metrics[key] = value
			}
		}
	}
	return corroborated, metrics
}

func topProcessRowsSummary(rows []string, reasonCounts map[string]int, cpuPressureCorroborated, memPressureCorroborated float64) string {
	parts := []string{
		"top-process-rows 为代表进程行，仅用于定位候选进程；这些行只是候选线索，需要结合其他 evidence 判断",
		fmt.Sprintf("代表进程: %s", strings.Join(rows, "；")),
	}
	if reasonCounts["high_cpu"] > 0 {
		parts = append(parts, "high_cpu 行表示窗口内 CPU 高占用候选，是否异常需结合 CPU idle/load/running queue")
		if cpuPressureCorroborated > 0 {
			parts = append(parts, "已有 top CPU 压力佐证，high_cpu 行可作为 CPU 排查的进程线索")
		}
	}
	if reasonCounts["high_mem"] > 0 {
		parts = append(parts, "high_mem 行表示内存占用候选，是否异常需结合 MemAvailable、swap、commit、anon 增长")
		if memPressureCorroborated > 0 {
			parts = append(parts, "已有 meminfo 内存压力佐证，high_mem 行可作为内存排查的进程线索")
		}
	}
	return strings.Join(parts, "。") + "。"
}

func findingByRuleID(findings []rulefindings.Finding, ruleID string) (rulefindings.Finding, bool) {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return finding, true
		}
	}
	return rulefindings.Finding{}, false
}

func topProcessReason(process top.ProcessStats, cfg config.TopConfig) (string, int, bool) {
	switch {
	case process.State == "D":
		return "D-state", 400, true
	case process.State == "Z":
		return "zombie", 300, true
	case process.CPUPercent >= cfg.HighCPUProcessPct:
		return "high_cpu", 200, true
	case process.MemPercent >= cfg.HighMemoryProcessPct:
		return "high_mem", 100, true
	default:
		return "", 0, false
	}
}

func topProcessKey(process top.ProcessStats, reason string) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s", process.PID, process.User, process.State, process.Command, reason)
}

func betterTopProcessCandidate(candidate, existing topProcessCandidate) bool {
	if candidate.priority != existing.priority {
		return candidate.priority > existing.priority
	}
	if candidate.process.CPUPercent != existing.process.CPUPercent {
		return candidate.process.CPUPercent > existing.process.CPUPercent
	}
	if candidate.process.MemPercent != existing.process.MemPercent {
		return candidate.process.MemPercent > existing.process.MemPercent
	}
	if candidate.process.ResKB != existing.process.ResKB {
		return candidate.process.ResKB > existing.process.ResKB
	}
	return candidate.at.Before(existing.at)
}

func truncateProcessCommand(command string) string {
	runes := []rune(command)
	if len(runes) <= topProcessCommandMaxRune {
		return command
	}
	return string(runes[:topProcessCommandMaxRune]) + "..."
}

func buildCrossEvidence(evidence []Evidence, cfg config.TopConfig) []Evidence {
	cfg = cfg.WithDefaults()
	index := make(map[string]Evidence, len(evidence))
	for _, item := range evidence {
		index[item.ID] = item
	}

	var combined []Evidence

	ioWait, hasIOWait := index["top-cpu-wait"]
	loadHigh, hasLoad := index["top-load-high"]
	memAvail, hasMemAvail := index["meminfo-available"]
	swapUsage, hasSwap := index["meminfo-swap-usage"]

	if hasIOWait && hasLoad {
		if hasEvidenceTag(evidence, "queue") || hasEvidenceTag(evidence, "latency") {
			level := SignalLevelSoft
			if ioWait.Level == SignalLevelHard && hasHardDiskSignal(evidence) {
				level = SignalLevelHard
			}
			combined = append(combined, Evidence{
				ID:      "cross-io-contention",
				Source:  "cross",
				Level:   level,
				Title:   "高负载更像是 I/O 争用而非纯 CPU 饱和",
				Summary: fmt.Sprintf("负载升高同时伴随 CPU Wait %.1f%% 和磁盘延迟/队列信号。", ioWait.Metrics["cpu_wait_max"]),
				Metrics: map[string]float64{
					"cpu_wait_max": ioWait.Metrics["cpu_wait_max"],
					"load1_avg":    loadHigh.Metrics["load1_avg"],
				},
				Tags: []string{"cross", "io", "load"},
			})
		}
	}

	if hasMemAvail && (hasSwap || hasEvidenceTag(evidence, "anon")) {
		level := SignalLevelSoft
		if memAvail.Level == SignalLevelHard || (hasSwap && swapUsage.Level == SignalLevelHard) {
			level = SignalLevelHard
		}
		summary := fmt.Sprintf("可用内存 %.1f%%。", memAvail.Metrics["mem_available_pct"])
		if hasSwap {
			summary = fmt.Sprintf("可用内存 %.1f%%，同时 Swap 已使用 %.1f%%。", memAvail.Metrics["mem_available_pct"], swapUsage.Metrics["swap_used_pct"])
		}
		combined = append(combined, Evidence{
			ID:      "cross-memory-pressure",
			Source:  "cross",
			Level:   level,
			Title:   "存在组合型内存压力",
			Summary: summary,
			Metrics: map[string]float64{
				"mem_available_pct": memAvail.Metrics["mem_available_pct"],
				"swap_used_pct":     metricOrZero(swapUsage.Metrics, "swap_used_pct"),
			},
			Tags: []string{"cross", "memory"},
		})
	}

	if hasLoad && !hasIOWait {
		idleEvidence, hasIdle := index["top-cpu-idle"]
		if hasIdle && idleEvidence.Metrics["cpu_idle_avg"] <= cfg.CPUIdleSoftPct {
			level := SignalLevelSoft
			if idleEvidence.Level == SignalLevelHard && loadHigh.Level == SignalLevelHard {
				level = SignalLevelHard
			}
			combined = append(combined, Evidence{
				ID:      "cross-cpu-saturation",
				Source:  "cross",
				Level:   level,
				Title:   "高负载更接近 CPU 饱和",
				Summary: fmt.Sprintf("Load1 平均 %.2f，CPU Idle 平均 %.1f%%，且未观察到明显 I/O wait。", loadHigh.Metrics["load1_avg"], idleEvidence.Metrics["cpu_idle_avg"]),
				Metrics: map[string]float64{
					"load1_avg":    loadHigh.Metrics["load1_avg"],
					"cpu_idle_avg": idleEvidence.Metrics["cpu_idle_avg"],
				},
				Tags: []string{"cross", "cpu"},
			})
		}
	}

	return combined
}

func sortEvidence(evidence []Evidence) {
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].Level != evidence[j].Level {
			return evidence[i].Level == SignalLevelHard
		}
		return evidence[i].ID < evidence[j].ID
	})
}

func hasEvidenceTag(evidence []Evidence, tag string) bool {
	for _, item := range evidence {
		for _, current := range item.Tags {
			if current == tag {
				return true
			}
		}
	}
	return false
}

func hasHardDiskSignal(evidence []Evidence) bool {
	for _, item := range evidence {
		if item.Level != SignalLevelHard {
			continue
		}
		for _, tag := range item.Tags {
			if tag == "latency" || tag == "queue" {
				return true
			}
		}
	}
	return false
}

func metricOrZero(metrics map[string]float64, key string) float64 {
	if metrics == nil {
		return 0
	}
	return metrics[key]
}

func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(contextTimeLayout)
}
