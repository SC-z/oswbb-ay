package findings

import (
	"fmt"
	"math"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/pkg/top"
	"strings"
	"time"
)

func BuildTopFindings(log *top.TopLog, start, end time.Time) []Finding {
	return BuildTopFindingsWithConfig(log, start, end, config.Default().Top)
}

func BuildTopFindingsWithConfig(log *top.TopLog, start, end time.Time, cfg config.TopConfig) []Finding {
	if log == nil {
		return nil
	}
	cfg = cfg.WithDefaults()

	data := filterTopRange(log.Snapshots, start, end)
	if len(data) == 0 {
		return nil
	}

	var result []Finding
	idleAvg, idleMin, idleMinTime := summarizeTopMetricMin(data, func(s top.TopSnapshot) float64 { return s.CpuIdle })
	waitAvg, waitMax, waitMaxTime := summarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.CpuWait })
	waitSoftSamples := countTopMetricAtLeast(data, func(s top.TopSnapshot) float64 { return s.CpuWait }, cfg.CPUWaitSoftPct)
	waitHardSamples := countTopMetricAtLeast(data, func(s top.TopSnapshot) float64 { return s.CpuWait }, cfg.CPUWaitHardPct)
	stealAvg, stealMax, stealMaxTime := summarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.CpuSteal })
	stealSoftSamples := countTopMetricAtLeast(data, func(s top.TopSnapshot) float64 { return s.CpuSteal }, cfg.CPUStealSoftPct)
	stealHardSamples := countTopMetricAtLeast(data, func(s top.TopSnapshot) float64 { return s.CpuSteal }, cfg.CPUStealHardPct)
	loadAvg, loadMax, loadMaxTime := summarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.Load1 })
	cpuCount := topCPUCount(data)
	loadSoftThreshold := topLoadSoftThreshold(cpuCount, cfg)
	loadHardThreshold := topLoadHardThreshold(cpuCount, cfg)
	runnableThreshold := topRunnableThreshold(cpuCount, cfg)
	zombieMax, zombieMaxTime, zombieSampleCount := summarizePositiveTopInt(data, func(s top.TopSnapshot) int { return s.TaskZombie })
	hasDStateAtWaitPeak := hasDStateProcessAt(data, waitMaxTime)
	hasRunnableQueueAtWaitPeak := hasRunnableQueueAt(data, waitMaxTime, runnableThreshold)
	hasRunnableQueueAtIdleMin := hasRunnableQueueAt(data, idleMinTime, runnableThreshold)
	hasRunnableQueueDuringHighLoad := hasRunnableQueueWhenLoadAtLeast(data, loadSoftThreshold, runnableThreshold)
	runningMaxDuringHighLoad := maxRunningWhenLoadAtLeast(data, loadSoftThreshold)
	hasLowIdleDuringHighLoad := hasLowIdleWhenLoadAtLeast(data, loadSoftThreshold, cfg)
	hasDStateDuringHighLoad := hasDStateWhenLoadAtLeast(data, loadSoftThreshold)

	idleSoftSamples := countTopMetricAtMost(data, func(s top.TopSnapshot) float64 { return s.CpuIdle }, cfg.CPUIdleSoftPct)
	idleHardSamples := countTopMetricAtMost(data, func(s top.TopSnapshot) float64 { return s.CpuIdle }, cfg.CPUIdleHardPct)
	idleHighProcessCorroborated := hasHighCPUProcessAt(data, idleMinTime, cfg)
	idleCorroborated := idleHighProcessCorroborated || hasRunnableQueueAtIdleMin
	idleSeverity := cpuIdleSeverity(idleAvg, idleMin, idleSoftSamples, idleHardSamples, len(data), idleCorroborated, cfg)
	if idleSeverity != "" {
		threshold := lowerBoundThresholdForSeverity(idleSeverity, cfg.CPUIdleHardPct, cfg.CPUIdleSoftPct)
		metric := "cpu_idle_avg_pct"
		observed := idleAvg
		if idleAvg > threshold {
			metric = "cpu_idle_min_pct"
			observed = idleMin
		}
		idleHighProcessCorroboratedValue := 0.0
		if idleHighProcessCorroborated {
			idleHighProcessCorroboratedValue = 1
		}
		idleRunnableCorroboratedValue := 0.0
		if hasRunnableQueueAtIdleMin {
			idleRunnableCorroboratedValue = 1
		}
		result = append(result, Finding{
			RuleID:        "top-cpu-idle",
			Source:        "top",
			Category:      "cpu_idle",
			Severity:      idleSeverity,
			Title:         "CPU 空闲率偏低",
			Summary:       fmt.Sprintf("CPU Idle 平均 %.1f%%，最低 %.1f%%。", idleAvg, idleMin),
			Target:        "cpu",
			Metric:        metric,
			Operator:      "<=",
			Threshold:     threshold,
			ObservedValue: observed,
			EvidenceRef:   evidenceRef("top", "cpu", "cpu_idle_min_pct", idleMinTime),
			Time:          idleMinTime.Format(timeLayout),
			Metrics: map[string]float64{
				"cpu_idle_avg":                       idleAvg,
				"cpu_idle_min":                       idleMin,
				"cpu_idle_soft_sample_count":         float64(idleSoftSamples),
				"cpu_idle_hard_sample_count":         float64(idleHardSamples),
				"cpu_idle_high_process_corroborated": idleHighProcessCorroboratedValue,
				"cpu_idle_runnable_corroborated":     idleRunnableCorroboratedValue,
			},
			Tags: []string{"cpu", "load"},
		})
	}

	waitCorroborated := hasDStateAtWaitPeak || hasRunnableQueueAtWaitPeak
	waitSeverity := cpuWaitSeverity(waitAvg, waitMax, waitSoftSamples, waitHardSamples, len(data), waitCorroborated, cfg)
	if waitSeverity != "" {
		waitCorroboratedValue := 0.0
		if waitCorroborated {
			waitCorroboratedValue = 1
		}
		result = append(result, Finding{
			RuleID:        "top-cpu-wait",
			Source:        "top",
			Category:      "cpu_iowait",
			Severity:      waitSeverity,
			Title:         "top 视角下 I/O wait 偏高",
			Summary:       cpuWaitSummary(waitAvg, waitMax, waitCorroborated),
			Target:        "cpu",
			Metric:        "cpu_wait_max_pct",
			Operator:      ">=",
			Threshold:     thresholdForSeverity(waitSeverity, cfg.CPUWaitHardPct, cfg.CPUWaitSoftPct),
			ObservedValue: waitMax,
			EvidenceRef:   evidenceRef("top", "cpu", "cpu_wait_max_pct", waitMaxTime),
			Time:          waitMaxTime.Format(timeLayout),
			Metrics: map[string]float64{
				"cpu_wait_avg":               waitAvg,
				"cpu_wait_max":               waitMax,
				"cpu_wait_soft_sample_count": float64(waitSoftSamples),
				"cpu_wait_hard_sample_count": float64(waitHardSamples),
				"cpu_wait_corroborated":      waitCorroboratedValue,
			},
			Tags: []string{"cpu", "iowait"},
		})
	}

	stealSeverity := cpuStealSeverity(stealAvg, stealMax, stealSoftSamples, stealHardSamples, len(data), cfg)
	if stealSeverity != "" {
		result = append(result, Finding{
			RuleID:        "top-cpu-steal",
			Source:        "top",
			Category:      "cpu_steal",
			Severity:      stealSeverity,
			Title:         "CPU steal 偏高",
			Summary:       fmt.Sprintf("CPU Steal 平均 %.1f%%，峰值 %.1f%%，可能存在虚拟化宿主机资源争抢。", stealAvg, stealMax),
			Target:        "cpu",
			Metric:        "cpu_steal_max_pct",
			Operator:      ">=",
			Threshold:     thresholdForSeverity(stealSeverity, cfg.CPUStealHardPct, cfg.CPUStealSoftPct),
			ObservedValue: stealMax,
			EvidenceRef:   evidenceRef("top", "cpu", "cpu_steal_max_pct", stealMaxTime),
			Time:          stealMaxTime.Format(timeLayout),
			Metrics: map[string]float64{
				"cpu_steal_avg":               stealAvg,
				"cpu_steal_max":               stealMax,
				"cpu_steal_soft_sample_count": float64(stealSoftSamples),
				"cpu_steal_hard_sample_count": float64(stealHardSamples),
			},
			Tags: []string{"cpu", "steal", "virtualization"},
		})
	}

	if zombieMax > 0 {
		severity := zombieSeverity(zombieMax, zombieSampleCount)
		result = append(result, Finding{
			RuleID:        "top-zombie",
			Source:        "top",
			Category:      "process_zombie",
			Severity:      severity,
			Title:         "存在僵尸进程",
			Summary:       zombieSummary(zombieMax, zombieSampleCount),
			Target:        "process",
			Metric:        "task_zombie_max",
			Operator:      ">",
			Threshold:     0,
			ObservedValue: float64(zombieMax),
			EvidenceRef:   evidenceRef("top", "process", "task_zombie_max", zombieMaxTime),
			Time:          zombieMaxTime.Format(timeLayout),
			Metrics: map[string]float64{
				"task_zombie_max":          float64(zombieMax),
				"task_zombie_sample_count": float64(zombieSampleCount),
			},
			Tags: []string{"process"},
		})
	}

	for _, processFinding := range buildDStateProcessFindings(data, cfg) {
		result = append(result, processFinding)
	}
	for _, processFinding := range buildHighCPUProcessFindings(data, cfg) {
		result = append(result, processFinding)
	}

	loadSeverity := Severity("")
	waitCorroboratesLoad := hasIOWaitWhenLoadAtLeast(data, loadSoftThreshold, cfg)
	dStateCorroboratesHardLoad := hasDStateDuringHighLoad && loadMax >= loadHardThreshold
	hasLoadCorroboration := hasLowIdleDuringHighLoad || waitCorroboratesLoad || hasRunnableQueueDuringHighLoad || dStateCorroboratesHardLoad
	switch {
	case loadMax >= loadHardThreshold && hasLoadCorroboration:
		loadSeverity = SeverityHigh
	case loadAvg >= loadSoftThreshold && hasLoadCorroboration:
		loadSeverity = SeverityMedium
	}
	if loadSeverity != "" {
		observed := loadAvg
		if loadSeverity == SeverityHigh {
			observed = loadMax
		}
		result = append(result, Finding{
			RuleID:        "top-load-high",
			Source:        "top",
			Category:      "system_load",
			Severity:      loadSeverity,
			Title:         "系统负载持续偏高",
			Summary:       topLoadSummary(loadAvg, loadMax, runningMaxDuringHighLoad, idleAvg, cpuCount, hasRunnableQueueDuringHighLoad, waitCorroboratesLoad, hasLowIdleDuringHighLoad, hasDStateDuringHighLoad, cfg),
			Target:        "system",
			Metric:        "load1",
			Operator:      ">=",
			Threshold:     thresholdForSeverity(loadSeverity, loadHardThreshold, loadSoftThreshold),
			ObservedValue: observed,
			EvidenceRef:   evidenceRef("top", "system", "load1", loadMaxTime),
			Time:          loadMaxTime.Format(timeLayout),
			Metrics: map[string]float64{
				"load1_avg":        loadAvg,
				"load1_max":        loadMax,
				"task_running_max": float64(runningMaxDuringHighLoad),
				"cpu_idle_avg":     idleAvg,
				"cpu_wait_max":     waitMax,
			},
			Tags: []string{"cpu", "load"},
		})
		if cpuCount > 0 {
			result[len(result)-1].Metrics["cpu_count"] = float64(cpuCount)
			result[len(result)-1].Metrics["load1_avg_per_cpu"] = loadAvg / float64(cpuCount)
			result[len(result)-1].Metrics["load1_max_per_cpu"] = loadMax / float64(cpuCount)
			result[len(result)-1].Metrics["task_running_max_per_cpu"] = float64(runningMaxDuringHighLoad) / float64(cpuCount)
		}
		if hasRunnableQueueDuringHighLoad {
			result[len(result)-1].Metrics["load_running_queue_corroborated"] = 1
		}
		if hasDStateDuringHighLoad {
			result[len(result)-1].Metrics["load_d_state_corroborated"] = 1
		}
		if hasLowIdleDuringHighLoad {
			result[len(result)-1].Metrics["load_idle_low_corroborated"] = 1
		} else {
			result[len(result)-1].Metrics["load_idle_low_corroborated"] = 0
		}
		if waitCorroboratesLoad {
			result[len(result)-1].Metrics["load_iowait_corroborated"] = 1
		} else {
			result[len(result)-1].Metrics["load_iowait_corroborated"] = 0
		}
	}

	sortFindings(result)
	return result
}

func topLoadSummary(loadAvg, loadMax float64, runningMax int, idleAvg float64, cpuCount int, hasRunnableQueue, waitCorroboratesLoad, hasLowIdle, hasDState bool, cfg config.TopConfig) string {
	reasons := make([]string, 0, 3)
	if hasDState {
		if idleAvg >= cfg.CPUIdleHighPct && !hasLowIdle {
			reasons = append(reasons, "同窗口存在 D 状态进程，CPU idle 仍高，不能单独定性为 CPU 饱和，高 load 可能由不可中断睡眠/阻塞任务贡献")
		} else {
			reasons = append(reasons, "同窗口存在 D 状态进程，高 load 可能由不可中断睡眠/阻塞任务贡献")
		}
	}
	if hasRunnableQueue {
		if idleAvg >= cfg.CPUIdleHighPct && !hasLowIdle && !waitCorroboratesLoad {
			reasons = append(reasons, "运行队列曾偏高，但 CPU idle 仍高，不能单独定性为 CPU 饱和")
		} else {
			reasons = append(reasons, "运行队列偏高，倾向 CPU 排队压力")
		}
	}
	if waitCorroboratesLoad {
		reasons = append(reasons, "iowait 偏高，需关联 I/O 等待")
	}
	if hasLowIdle {
		reasons = append(reasons, "CPU idle 偏低")
	}
	capacity := ""
	if cpuCount > 0 {
		capacity = fmt.Sprintf("CPU=%d 核，load/core 峰值 %.2f，running/core 峰值 %.2f；", cpuCount, loadMax/float64(cpuCount), float64(runningMax)/float64(cpuCount))
	}
	if len(reasons) == 0 {
		return fmt.Sprintf("Load1 平均 %.2f，峰值 %.2f；%s运行队列峰值 %d。", loadAvg, loadMax, capacity, runningMax)
	}
	return fmt.Sprintf("Load1 平均 %.2f，峰值 %.2f；%s运行队列峰值 %d；佐证: %s。", loadAvg, loadMax, capacity, runningMax, strings.Join(reasons, "；"))
}

func cpuWaitSummary(waitAvg, waitMax float64, corroborated bool) string {
	base := fmt.Sprintf("CPU Wait 平均 %.1f%%，峰值 %.1f%%。", waitAvg, waitMax)
	if corroborated {
		return base
	}
	return base + " 未见同采样 D 状态或运行队列佐证，按候选线索保留，需结合 iostat 延迟/队列确认。"
}

func topCPUCount(data []top.TopSnapshot) int {
	for _, snap := range data {
		if snap.CPUCount > 0 {
			return snap.CPUCount
		}
	}
	return 0
}

func topLoadSoftThreshold(cpuCount int, cfg config.TopConfig) float64 {
	if cpuCount <= 0 {
		return cfg.LoadHighSoft
	}
	return math.Max(1, float64(cpuCount)*cfg.LoadPerCPUSoft)
}

func topLoadHardThreshold(cpuCount int, cfg config.TopConfig) float64 {
	if cpuCount <= 0 {
		return cfg.LoadHighHard
	}
	return float64(cpuCount) * cfg.LoadPerCPUHard
}

func topRunnableThreshold(cpuCount int, cfg config.TopConfig) int {
	if cpuCount <= 0 {
		return cfg.RunnableSoft
	}
	threshold := int(math.Ceil(float64(cpuCount) * cfg.RunnablePerCPU))
	if threshold < 2 {
		return 2
	}
	return threshold
}

func filterTopRange(data []top.TopSnapshot, start, end time.Time) []top.TopSnapshot {
	var filtered []top.TopSnapshot
	for _, item := range data {
		if item.Timestamp.Before(start) || item.Timestamp.After(end) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func hasRunnableQueueWhenLoadAtLeast(data []top.TopSnapshot, threshold float64, runnableThreshold int) bool {
	for _, snap := range data {
		if snap.Load1 >= threshold && snap.TaskRunning >= runnableThreshold {
			return true
		}
	}
	return false
}

func maxRunningWhenLoadAtLeast(data []top.TopSnapshot, threshold float64) int {
	maxRunning := 0
	for _, snap := range data {
		if snap.Load1 >= threshold && snap.TaskRunning > maxRunning {
			maxRunning = snap.TaskRunning
		}
	}
	return maxRunning
}

func hasIOWaitWhenLoadAtLeast(data []top.TopSnapshot, threshold float64, cfg config.TopConfig) bool {
	samples := 0
	waitSamples := 0
	waitTotal := 0.0
	for _, snap := range data {
		if snap.Load1 < threshold {
			continue
		}
		samples++
		waitTotal += snap.CpuWait
		if snap.CpuWait >= cfg.CPUWaitSoftPct {
			waitSamples++
		}
	}
	return waitSamples >= 2 || (samples >= 2 && waitTotal/float64(samples) >= cfg.CPUWaitSoftPct)
}

func hasLowIdleWhenLoadAtLeast(data []top.TopSnapshot, threshold float64, cfg config.TopConfig) bool {
	for _, snap := range data {
		if snap.Load1 >= threshold && snap.CpuIdle < cfg.CPUIdleSoftPct {
			return true
		}
	}
	return false
}

func hasDStateWhenLoadAtLeast(data []top.TopSnapshot, threshold float64) bool {
	for _, snap := range data {
		if snap.Load1 < threshold {
			continue
		}
		for _, process := range snap.Processes {
			if process.State == "D" {
				return true
			}
		}
	}
	return false
}

type dStatePressureContext struct {
	cpuIdleAvg     float64
	cpuIdleMin     float64
	cpuWaitMax     float64
	load1Avg       float64
	load1Max       float64
	taskRunningMax int
	cpuCount       int
}

type dStateProcess struct {
	pid     int
	command string
	at      time.Time
}

func buildDStateProcessFindings(data []top.TopSnapshot, cfg config.TopConfig) []Finding {
	seen := make(map[int]struct{})
	snapshotsByPID := make(map[int]int)
	var processes []dStateProcess
	var dStateSnapshots []top.TopSnapshot
	var firstTime time.Time
	var maxConcurrentDState int
	var maxConcurrentDStateTime time.Time
	dStateSnapshotCount := 0
	dStateObservationCount := 0
	for _, snap := range data {
		snapshotPIDs := make(map[int]struct{})
		hasDStateProcess := false
		for _, process := range snap.Processes {
			if process.State != "D" {
				continue
			}
			hasDStateProcess = true
			dStateObservationCount++
			if _, counted := snapshotPIDs[process.PID]; !counted {
				snapshotPIDs[process.PID] = struct{}{}
				snapshotsByPID[process.PID]++
			}
			if _, exists := seen[process.PID]; exists {
				continue
			}
			seen[process.PID] = struct{}{}
			if firstTime.IsZero() || snap.Timestamp.Before(firstTime) {
				firstTime = snap.Timestamp
			}
			processes = append(processes, dStateProcess{
				pid:     process.PID,
				command: process.Command,
				at:      snap.Timestamp,
			})
		}
		if hasDStateProcess {
			if len(snapshotPIDs) > maxConcurrentDState {
				maxConcurrentDState = len(snapshotPIDs)
				maxConcurrentDStateTime = snap.Timestamp
			}
			dStateSnapshotCount++
			dStateSnapshots = append(dStateSnapshots, snap)
		}
	}
	if len(processes) == 0 {
		return nil
	}

	persistentProcessCount := 0
	for _, count := range snapshotsByPID {
		if count >= 2 {
			persistentProcessCount++
		}
	}
	pressure := dStatePressureFromSnapshots(dStateSnapshots)
	hasPressure := dStateHasPressureCorroboration(pressure, cfg)
	severity := dStateSeverity(maxConcurrentDState, persistentProcessCount, hasPressure)
	summary := dStateSummary(len(processes), maxConcurrentDState, representativesForDState(processes), hasPressure, persistentProcessCount, dStateSnapshotCount)

	pressureValue := 0.0
	if hasPressure {
		pressureValue = 1.0
	}
	if maxConcurrentDStateTime.IsZero() {
		maxConcurrentDStateTime = firstTime
	}

	return []Finding{{
		RuleID:        "top-process-d-state",
		Source:        "top",
		Category:      "process_state",
		Severity:      severity,
		Title:         "存在 D 状态进程",
		Summary:       summary,
		Target:        "process",
		Metric:        "d_state_process_count",
		Operator:      ">",
		Threshold:     0,
		ObservedValue: float64(maxConcurrentDState),
		EvidenceRef:   evidenceRef("top", "process", "d_state_process_count", maxConcurrentDStateTime),
		Time:          maxConcurrentDStateTime.Format(timeLayout),
		Metrics: map[string]float64{
			"d_state_process_count":                float64(maxConcurrentDState),
			"d_state_max_concurrent_process_count": float64(maxConcurrentDState),
			"d_state_unique_process_count":         float64(len(processes)),
			"d_state_observation_count":            float64(dStateObservationCount),
			"d_state_snapshot_count":               float64(dStateSnapshotCount),
			"d_state_persistent_process_count":     float64(persistentProcessCount),
			"d_state_pressure_corroborated":        pressureValue,
			"cpu_idle_avg":                         pressure.cpuIdleAvg,
			"cpu_idle_min":                         pressure.cpuIdleMin,
			"cpu_wait_max":                         pressure.cpuWaitMax,
			"load1_avg":                            pressure.load1Avg,
			"load1_max":                            pressure.load1Max,
			"task_running_max":                     float64(pressure.taskRunningMax),
		},
		Tags: []string{"process", "d_state", "io_wait"},
	}}
}

func dStatePressureFromSnapshots(data []top.TopSnapshot) dStatePressureContext {
	if len(data) == 0 {
		return dStatePressureContext{}
	}
	idleAvg, idleMin, _ := summarizeTopMetricMin(data, func(s top.TopSnapshot) float64 { return s.CpuIdle })
	_, waitMax, _ := summarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.CpuWait })
	loadAvg, loadMax, _ := summarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.Load1 })
	runningMax, _ := summarizeTopInt(data, func(s top.TopSnapshot) int { return s.TaskRunning })
	return dStatePressureContext{
		cpuIdleAvg:     idleAvg,
		cpuIdleMin:     idleMin,
		cpuWaitMax:     waitMax,
		load1Avg:       loadAvg,
		load1Max:       loadMax,
		taskRunningMax: runningMax,
		cpuCount:       topCPUCount(data),
	}
}

type highCPUProcess struct {
	pid     int
	command string
	cpu     float64
	at      time.Time
}

func buildHighCPUProcessFindings(data []top.TopSnapshot, cfg config.TopConfig) []Finding {
	seen := make(map[int]struct{})
	snapshotsByPID := make(map[int]int)
	var processes []highCPUProcess
	var peak highCPUProcess
	idleAtPeak := 0.0
	pressureSnapshotCount := 0
	observationCount := 0

	for _, snap := range data {
		if snap.CpuIdle > cfg.CPUIdleSoftPct {
			continue
		}
		snapshotPIDs := make(map[int]struct{})
		hasHighCPUProcess := false
		for _, process := range snap.Processes {
			if process.CPUPercent < cfg.HighCPUProcessPct {
				continue
			}
			hasHighCPUProcess = true
			observationCount++
			if _, counted := snapshotPIDs[process.PID]; !counted {
				snapshotPIDs[process.PID] = struct{}{}
				snapshotsByPID[process.PID]++
			}
			if peak.pid == 0 || process.CPUPercent > peak.cpu {
				peak = highCPUProcess{
					pid:     process.PID,
					command: process.Command,
					cpu:     process.CPUPercent,
					at:      snap.Timestamp,
				}
				idleAtPeak = snap.CpuIdle
			}
			if _, exists := seen[process.PID]; exists {
				continue
			}
			seen[process.PID] = struct{}{}
			processes = append(processes, highCPUProcess{
				pid:     process.PID,
				command: process.Command,
				cpu:     process.CPUPercent,
				at:      snap.Timestamp,
			})
		}
		if hasHighCPUProcess {
			pressureSnapshotCount++
		}
	}
	if len(processes) == 0 {
		return nil
	}

	persistentProcessCount := 0
	for _, count := range snapshotsByPID {
		if count >= 2 {
			persistentProcessCount++
		}
	}
	severity := highCPUProcessSeverity(pressureSnapshotCount, persistentProcessCount)

	return []Finding{{
		RuleID:        "top-process-high-cpu",
		Source:        "top",
		Category:      "process_cpu",
		Severity:      severity,
		Title:         "CPU 饱和时存在高 CPU 进程",
		Summary:       highCPUProcessSummary(len(processes), representativesForHighCPU(processes), pressureSnapshotCount),
		Target:        "process",
		Metric:        "process_cpu_pct",
		Operator:      ">=",
		Threshold:     cfg.HighCPUProcessPct,
		ObservedValue: peak.cpu,
		EvidenceRef:   evidenceRef("top", "process", "process_cpu_pct", peak.at),
		Time:          peak.at.Format(timeLayout),
		Metrics: map[string]float64{
			"high_cpu_process_count":            float64(len(processes)),
			"high_cpu_observation_count":        float64(observationCount),
			"high_cpu_pressure_snapshot_count":  float64(pressureSnapshotCount),
			"high_cpu_persistent_process_count": float64(persistentProcessCount),
			"process_cpu_peak":                  peak.cpu,
			"cpu_idle_at_peak":                  idleAtPeak,
		},
		Tags: []string{"process", "cpu"},
	}}
}

func representativesForDState(processes []dStateProcess) []string {
	representatives := make([]string, 0, minInt(len(processes), 5))
	for i, process := range processes {
		if i >= 5 {
			break
		}
		representatives = append(representatives, fmt.Sprintf("%d/%s", process.pid, process.command))
	}
	return representatives
}

func representativesForHighCPU(processes []highCPUProcess) []string {
	representatives := make([]string, 0, minInt(len(processes), 5))
	for i, process := range processes {
		if i >= 5 {
			break
		}
		representatives = append(representatives, fmt.Sprintf("PID=%d %s CPU=%.1f%%", process.pid, process.command, process.cpu))
	}
	return representatives
}

func highCPUProcessSeverity(pressureSnapshotCount, persistentProcessCount int) Severity {
	if pressureSnapshotCount >= 2 || persistentProcessCount >= 1 {
		return SeverityHigh
	}
	return SeverityMedium
}

func dStateHasPressureCorroboration(pressure dStatePressureContext, cfg config.TopConfig) bool {
	return pressure.cpuWaitMax >= cfg.CPUWaitSoftPct ||
		pressure.cpuIdleAvg < cfg.CPUIdleSoftPct ||
		pressure.cpuIdleMin < cfg.CPUIdleSoftPct ||
		pressure.taskRunningMax >= topRunnableThreshold(pressure.cpuCount, cfg)
}

func dStateSeverity(maxConcurrentProcessCount, persistentProcessCount int, hasPressure bool) Severity {
	switch {
	case hasPressure:
		return SeverityHigh
	case maxConcurrentProcessCount > 1 || persistentProcessCount > 0:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func dStateSummary(uniqueProcessCount, maxConcurrentProcessCount int, representatives []string, hasPressure bool, persistentProcessCount, snapshotCount int) string {
	extra := ""
	if uniqueProcessCount > len(representatives) {
		extra = fmt.Sprintf(" 等共 %d 个不同 PID", uniqueProcessCount)
	}
	base := fmt.Sprintf("范围内 %d 个不同 PID 曾进入不可中断睡眠，单次峰值 %d 个，涉及 %d 个采样点；代表进程: %s%s。",
		uniqueProcessCount, maxConcurrentProcessCount, snapshotCount, strings.Join(representatives, ", "), extra)
	if hasPressure {
		return base + "同时存在 iowait、运行队列或低 idle 佐证，倾向 I/O 或内核等待路径存在阻塞风险。"
	}
	if uniqueProcessCount == 1 && persistentProcessCount == 0 && snapshotCount == 1 {
		return base + "该 D 状态仅单次出现，且未见 iowait、运行队列或低 idle 佐证；当前更适合作为线索保留。"
	}
	if persistentProcessCount > 0 {
		return base + "存在跨采样持续 D 状态，但未见 iowait、运行队列或低 idle 佐证；建议继续关联磁盘延迟和内核等待证据。"
	}
	return base + "未见 iowait、运行队列或低 idle 佐证；建议继续关联磁盘延迟和内核等待证据。"
}

func highCPUProcessSummary(uniqueProcessCount int, representatives []string, pressureSnapshotCount int) string {
	extra := ""
	if uniqueProcessCount > len(representatives) {
		extra = fmt.Sprintf(" 等 %d 个", uniqueProcessCount)
	}
	return fmt.Sprintf("CPU 低 idle 样本中发现 %d 个高 CPU 进程，代表进程: %s%s；出现于 %d 个 CPU 压力采样点。",
		uniqueProcessCount, strings.Join(representatives, ", "), extra, pressureSnapshotCount)
}

func summarizeTopMetricMax(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64) (avg, maxVal float64, at time.Time) {
	if len(data) == 0 {
		return 0, 0, time.Time{}
	}
	sum := 0.0
	for _, item := range data {
		val := extractor(item)
		sum += val
	}
	avg = sum / float64(len(data))

	maxVal = extractor(data[0])
	at = data[0].Timestamp
	for _, item := range data[1:] {
		val := extractor(item)
		if val > maxVal {
			maxVal = val
			at = item.Timestamp
		}
	}

	return avg, maxVal, at
}

func summarizeTopMetricMin(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64) (avg, minVal float64, at time.Time) {
	if len(data) == 0 {
		return 0, 0, time.Time{}
	}
	sum := 0.0
	minVal = extractor(data[0])
	at = data[0].Timestamp
	for _, item := range data {
		val := extractor(item)
		sum += val
		if val < minVal {
			minVal = val
			at = item.Timestamp
		}
	}
	return sum / float64(len(data)), minVal, at
}

func countTopMetricAtLeast(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64, threshold float64) int {
	count := 0
	for _, item := range data {
		if extractor(item) >= threshold {
			count++
		}
	}
	return count
}

func countTopMetricAtMost(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64, threshold float64) int {
	count := 0
	for _, item := range data {
		if extractor(item) <= threshold {
			count++
		}
	}
	return count
}

func cpuIdleSeverity(avg, minVal float64, softSamples, hardSamples, totalSamples int, corroborated bool, cfg config.TopConfig) Severity {
	switch {
	case avg <= cfg.CPUIdleHardPct || hardSamples >= 2:
		return SeverityHigh
	case avg <= cfg.CPUIdleSoftPct || softSamples >= 2:
		return SeverityMedium
	case totalSamples == 1 && minVal <= cfg.CPUIdleHardPct:
		return SeverityHigh
	case minVal <= cfg.CPUIdleHardPct && corroborated:
		return SeverityMedium
	default:
		return ""
	}
}

func cpuWaitSeverity(avg, maxVal float64, softSamples, hardSamples, totalSamples int, corroborated bool, cfg config.TopConfig) Severity {
	switch {
	case hardSamples >= 2 || (totalSamples >= 2 && avg >= cfg.CPUWaitHardPct) || (maxVal >= cfg.CPUWaitHardPct && corroborated):
		return SeverityHigh
	case softSamples >= 2 || (totalSamples >= 2 && avg >= cfg.CPUWaitSoftPct) || (maxVal >= cfg.CPUWaitSoftPct && corroborated):
		return SeverityMedium
	default:
		return ""
	}
}

func cpuStealSeverity(avg, maxVal float64, softSamples, hardSamples, totalSamples int, cfg config.TopConfig) Severity {
	switch {
	case hardSamples >= 2 || avg >= cfg.CPUStealHardPct || (maxVal >= cfg.CPUStealHardPct && avg >= cfg.CPUStealSoftPct):
		return SeverityHigh
	case maxVal >= cfg.CPUStealHardPct || softSamples >= 2 || (totalSamples >= 2 && avg >= cfg.CPUStealSoftPct):
		return SeverityMedium
	default:
		return ""
	}
}

func hasDStateProcess(data []top.TopSnapshot) bool {
	for _, snap := range data {
		for _, process := range snap.Processes {
			if process.State == "D" {
				return true
			}
		}
	}
	return false
}

func hasDStateProcessAt(data []top.TopSnapshot, at time.Time) bool {
	for _, snap := range data {
		if !snap.Timestamp.Equal(at) {
			continue
		}
		for _, process := range snap.Processes {
			if process.State == "D" {
				return true
			}
		}
	}
	return false
}

func hasRunnableQueueAt(data []top.TopSnapshot, at time.Time, runnableThreshold int) bool {
	for _, snap := range data {
		if snap.Timestamp.Equal(at) && snap.TaskRunning >= runnableThreshold {
			return true
		}
	}
	return false
}

func hasHighCPUProcessAt(data []top.TopSnapshot, at time.Time, cfg config.TopConfig) bool {
	for _, snap := range data {
		if !snap.Timestamp.Equal(at) {
			continue
		}
		for _, process := range snap.Processes {
			if process.CPUPercent >= cfg.HighCPUProcessPct {
				return true
			}
		}
	}
	return false
}

func summarizeTopInt(data []top.TopSnapshot, extractor func(top.TopSnapshot) int) (int, time.Time) {
	if len(data) == 0 {
		return 0, time.Time{}
	}
	maxVal := extractor(data[0])
	at := data[0].Timestamp
	for _, item := range data[1:] {
		val := extractor(item)
		if val > maxVal {
			maxVal = val
			at = item.Timestamp
		}
	}
	return maxVal, at
}

func summarizePositiveTopInt(data []top.TopSnapshot, extractor func(top.TopSnapshot) int) (maxVal int, at time.Time, positiveCount int) {
	if len(data) == 0 {
		return 0, time.Time{}, 0
	}
	maxVal = extractor(data[0])
	at = data[0].Timestamp
	if maxVal > 0 {
		positiveCount++
	}
	for _, item := range data[1:] {
		val := extractor(item)
		if val > 0 {
			positiveCount++
		}
		if val > maxVal {
			maxVal = val
			at = item.Timestamp
		}
	}
	return maxVal, at, positiveCount
}

func zombieSeverity(maxZombie, positiveSampleCount int) Severity {
	if maxZombie > 1 {
		return SeverityHigh
	}
	if positiveSampleCount > 1 {
		return SeverityMedium
	}
	return SeverityLow
}

func zombieSummary(maxZombie, positiveSampleCount int) string {
	if maxZombie > 1 {
		return fmt.Sprintf("最大僵尸进程数 %d，出现于 %d 个采样点。Z 状态指向父进程回收异常，建议检查对应父进程和进程生命周期。", maxZombie, positiveSampleCount)
	}
	if positiveSampleCount > 1 {
		return fmt.Sprintf("最大僵尸进程数 %d，出现于 %d 个采样点。持续单个 Z 状态进程是父进程回收异常线索，建议检查父进程，但不等同于 CPU 或内存压力。", maxZombie, positiveSampleCount)
	}
	return fmt.Sprintf("最大僵尸进程数 %d，仅单次出现。Z 状态是进程回收异常线索，不等同于 CPU 或内存压力。", maxZombie)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func severityFromLowerBound(value, high, medium float64) Severity {
	switch {
	case value <= high:
		return SeverityHigh
	case value <= medium:
		return SeverityMedium
	default:
		return ""
	}
}

func lowerBoundThresholdForSeverity(severity Severity, high, medium float64) float64 {
	if severity == SeverityHigh {
		return high
	}
	return medium
}
