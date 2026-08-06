package findings

import (
	"fmt"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/pkg/iostat"
	"sort"
	"strings"
	"time"
)

const (
	timeLayout = "2006-01-02 15:04:05"
)

func BuildIOStatFindings(log *iostat.IOStatLog, start, end time.Time) []Finding {
	return BuildIOStatFindingsWithConfig(log, start, end, config.Default().Iostat)
}

func BuildIOStatFindingsWithConfig(log *iostat.IOStatLog, start, end time.Time, cfg config.IostatConfig) []Finding {
	if log == nil {
		return nil
	}
	cfg = cfg.WithDefaults()
	latencyThresholds := iostat.LatencyThresholds{
		NVMeMS:        cfg.NVMeLatencyHardMS,
		DefaultMS:     cfg.DefaultLatencyHardMS,
		ZScore:        cfg.LatencyZScoreThreshold,
		MAD:           cfg.LatencyMADThreshold,
		IQRMultiplier: cfg.LatencyIQRMultiplier,
	}

	var result []Finding
	cpuWaitStats := summarizeIOWait(log, start, end, cfg)
	cpuWaitMax, cpuWaitAvg, hasCPUWait := cpuWaitStats.max, cpuWaitStats.avg, cpuWaitStats.samples > 0
	if hasCPUWait {
		cpuWaitStats.corroborated = iostatCPUWaitHasDiskEvidence(log, start, end, cpuWaitStats.maxTime, cfg)
		severity := iostatCPUWaitSeverity(cpuWaitStats, cfg)
		if severity != "" {
			corroboratedValue := 0.0
			if cpuWaitStats.corroborated {
				corroboratedValue = 1
			}
			result = append(result, Finding{
				RuleID:        "iostat-cpu-iowait",
				Source:        "iostat",
				Category:      "cpu_iowait",
				Severity:      severity,
				Title:         "iostat 采样中 CPU iowait 偏高",
				Summary:       fmt.Sprintf("iowait 平均 %.1f%%，峰值 %.1f%%。", cpuWaitAvg, cpuWaitMax),
				Metric:        "cpu_iowait_max_pct",
				Operator:      ">=",
				Threshold:     thresholdForSeverity(severity, cfg.CPUWaitHardPct, cfg.CPUWaitSoftPct),
				ObservedValue: cpuWaitMax,
				EvidenceRef:   evidenceRef("iostat", "cpu", "iowait", cpuWaitStats.maxTime),
				Time:          cpuWaitStats.maxTime.Format(timeLayout),
				Metrics: map[string]float64{
					"cpu_iowait_avg":               cpuWaitAvg,
					"cpu_iowait_max":               cpuWaitMax,
					"cpu_iowait_soft_sample_count": float64(cpuWaitStats.softSamples),
					"cpu_iowait_hard_sample_count": float64(cpuWaitStats.hardSamples),
					"cpu_iowait_corroborated":      corroboratedValue,
				},
				Tags: []string{"cpu", "iowait"},
			})
		}
	}

	devices := log.GetAllDevices()
	sort.Strings(devices)
	for _, device := range devices {
		if !deviceHasActivityInRange(log, device, start, end) {
			continue
		}

		readStats := log.GetReadLatencyStatsWithThresholds(device, start, end, latencyThresholds)
		writeStats := log.GetWriteLatencyStatsWithThresholds(device, start, end, latencyThresholds)
		discardStats := log.GetDiscardLatencyStatsWithThresholds(device, start, end, latencyThresholds)
		avgQueue := log.GetAverageQueueDepth(device, start, end)
		queueStats := summarizeActiveQueue(log, device, start, end, cfg)
		hardLatencyThreshold := deviceLatencyHardThreshold(device, cfg)
		softLatencyThreshold := deviceLatencySoftThreshold(device, cfg)

		if len(readStats.Anomalies) > 0 {
			maxAnomaly := maxLatencyAnomaly(readStats.Anomalies)
			context := latencyEvidenceContext(log, device, start, end, maxAnomaly.Timestamp, cfg)
			severity := latencySeverity(readStats, context)
			result = append(result, Finding{
				RuleID:        fmt.Sprintf("iostat-read-latency-%s", device),
				Source:        "iostat",
				Category:      "disk_latency",
				Severity:      severity,
				Title:         latencyTitle(device, "读", readStats),
				Summary:       latencySummary("读", readStats, maxAnomaly.Value, context),
				Target:        device,
				Metric:        "read_await_ms",
				Operator:      ">=",
				Threshold:     hardLatencyThreshold,
				ObservedValue: maxAnomaly.Value,
				EvidenceRef:   evidenceRef("iostat", device, "read_await_ms", maxAnomaly.Timestamp),
				Time:          maxAnomaly.Timestamp.Format(timeLayout),
				Metrics: map[string]float64{
					"read_latency_p95_ms":       readStats.P95,
					"read_latency_p99_ms":       readStats.P99,
					"read_latency_peak":         maxAnomaly.Value,
					"anomaly_count":             float64(len(readStats.Anomalies)),
					"high_latency_sample_count": float64(len(readStats.Anomalies)),
					"active_sample_count":       float64(readStats.Count),
					"read_iops_at_peak":         context.readIOPSAtPeak,
					"write_iops_at_peak":        context.writeIOPSAtPeak,
					"discard_iops_at_peak":      context.discardIOPSAtPeak,
					"total_iops_at_peak":        context.totalIOPSAtPeak,
					"avg_queue_at_peak":         context.avgQueueAtPeak,
					"cpu_iowait_at_peak":        context.cpuIOWaitAtPeak,
					"latency_corroborated":      context.corroboratedValue(),
					"latency_system_pressure":   context.systemPressureValue(),
				},
				Tags: []string{"disk", "latency", device, "read"},
			})
		} else if readStats.P95 >= softLatencyThreshold {
			context := softLatencyEvidenceContext(log, device, start, end, "read", softLatencyThreshold, cfg)
			if context.corroborated {
				result = append(result, Finding{
					RuleID:        fmt.Sprintf("iostat-read-soft-%s", device),
					Source:        "iostat",
					Category:      "disk_latency",
					Severity:      SeverityMedium,
					Title:         fmt.Sprintf("%s 读延迟接近阈值", device),
					Summary:       softLatencySummary("读", readStats.P95, softLatencyThreshold, context),
					Target:        device,
					Metric:        "read_await_p95_ms",
					Operator:      ">=",
					Threshold:     softLatencyThreshold,
					ObservedValue: readStats.P95,
					EvidenceRef:   fmt.Sprintf("iostat:%s:read_await_p95_ms", device),
					Metrics: map[string]float64{
						"read_latency_p95_ms":     readStats.P95,
						"soft_threshold_ms":       softLatencyThreshold,
						"total_iops_at_peak":      context.totalIOPSAtPeak,
						"avg_queue_at_peak":       context.avgQueueAtPeak,
						"cpu_iowait_at_peak":      context.cpuIOWaitAtPeak,
						"latency_corroborated":    context.corroboratedValue(),
						"latency_system_pressure": context.systemPressureValue(),
					},
					Tags: []string{"disk", "latency", device, "read"},
				})
			}
		}

		if len(writeStats.Anomalies) > 0 {
			maxAnomaly := maxLatencyAnomaly(writeStats.Anomalies)
			context := latencyEvidenceContext(log, device, start, end, maxAnomaly.Timestamp, cfg)
			severity := latencySeverity(writeStats, context)
			result = append(result, Finding{
				RuleID:        fmt.Sprintf("iostat-write-latency-%s", device),
				Source:        "iostat",
				Category:      "disk_latency",
				Severity:      severity,
				Title:         latencyTitle(device, "写", writeStats),
				Summary:       latencySummary("写", writeStats, maxAnomaly.Value, context),
				Target:        device,
				Metric:        "write_await_ms",
				Operator:      ">=",
				Threshold:     hardLatencyThreshold,
				ObservedValue: maxAnomaly.Value,
				EvidenceRef:   evidenceRef("iostat", device, "write_await_ms", maxAnomaly.Timestamp),
				Time:          maxAnomaly.Timestamp.Format(timeLayout),
				Metrics: map[string]float64{
					"write_latency_p95_ms":      writeStats.P95,
					"write_latency_p99_ms":      writeStats.P99,
					"write_latency_peak":        maxAnomaly.Value,
					"anomaly_count":             float64(len(writeStats.Anomalies)),
					"high_latency_sample_count": float64(len(writeStats.Anomalies)),
					"active_sample_count":       float64(writeStats.Count),
					"read_iops_at_peak":         context.readIOPSAtPeak,
					"write_iops_at_peak":        context.writeIOPSAtPeak,
					"discard_iops_at_peak":      context.discardIOPSAtPeak,
					"total_iops_at_peak":        context.totalIOPSAtPeak,
					"avg_queue_at_peak":         context.avgQueueAtPeak,
					"cpu_iowait_at_peak":        context.cpuIOWaitAtPeak,
					"latency_corroborated":      context.corroboratedValue(),
					"latency_system_pressure":   context.systemPressureValue(),
				},
				Tags: []string{"disk", "latency", device, "write"},
			})
		} else if writeStats.P95 >= softLatencyThreshold {
			context := softLatencyEvidenceContext(log, device, start, end, "write", softLatencyThreshold, cfg)
			if context.corroborated {
				result = append(result, Finding{
					RuleID:        fmt.Sprintf("iostat-write-soft-%s", device),
					Source:        "iostat",
					Category:      "disk_latency",
					Severity:      SeverityMedium,
					Title:         fmt.Sprintf("%s 写延迟接近阈值", device),
					Summary:       softLatencySummary("写", writeStats.P95, softLatencyThreshold, context),
					Target:        device,
					Metric:        "write_await_p95_ms",
					Operator:      ">=",
					Threshold:     softLatencyThreshold,
					ObservedValue: writeStats.P95,
					EvidenceRef:   fmt.Sprintf("iostat:%s:write_await_p95_ms", device),
					Metrics: map[string]float64{
						"write_latency_p95_ms":    writeStats.P95,
						"soft_threshold_ms":       softLatencyThreshold,
						"total_iops_at_peak":      context.totalIOPSAtPeak,
						"avg_queue_at_peak":       context.avgQueueAtPeak,
						"cpu_iowait_at_peak":      context.cpuIOWaitAtPeak,
						"latency_corroborated":    context.corroboratedValue(),
						"latency_system_pressure": context.systemPressureValue(),
					},
					Tags: []string{"disk", "latency", device, "write"},
				})
			}
		}

		if len(discardStats.Anomalies) > 0 {
			maxAnomaly := maxLatencyAnomaly(discardStats.Anomalies)
			context := latencyEvidenceContext(log, device, start, end, maxAnomaly.Timestamp, cfg)
			severity := latencySeverity(discardStats, context)
			result = append(result, Finding{
				RuleID:        fmt.Sprintf("iostat-discard-latency-%s", device),
				Source:        "iostat",
				Category:      "disk_latency",
				Severity:      severity,
				Title:         latencyTitle(device, "discard/TRIM ", discardStats),
				Summary:       latencySummary("discard/TRIM ", discardStats, maxAnomaly.Value, context),
				Target:        device,
				Metric:        "discard_await_ms",
				Operator:      ">=",
				Threshold:     hardLatencyThreshold,
				ObservedValue: maxAnomaly.Value,
				EvidenceRef:   evidenceRef("iostat", device, "discard_await_ms", maxAnomaly.Timestamp),
				Time:          maxAnomaly.Timestamp.Format(timeLayout),
				Metrics: map[string]float64{
					"discard_latency_p95_ms":  discardStats.P95,
					"discard_latency_p99_ms":  discardStats.P99,
					"discard_latency_peak":    maxAnomaly.Value,
					"anomaly_count":           float64(len(discardStats.Anomalies)),
					"active_sample_count":     float64(discardStats.Count),
					"read_iops_at_peak":       context.readIOPSAtPeak,
					"write_iops_at_peak":      context.writeIOPSAtPeak,
					"discard_iops_at_peak":    context.discardIOPSAtPeak,
					"total_iops_at_peak":      context.totalIOPSAtPeak,
					"avg_queue_at_peak":       context.avgQueueAtPeak,
					"cpu_iowait_at_peak":      context.cpuIOWaitAtPeak,
					"latency_corroborated":    context.corroboratedValue(),
					"latency_system_pressure": context.systemPressureValue(),
				},
				Tags: []string{"disk", "latency", device, "discard"},
			})
		} else if discardStats.P95 >= softLatencyThreshold {
			context := softLatencyEvidenceContext(log, device, start, end, "discard", softLatencyThreshold, cfg)
			if context.corroborated {
				result = append(result, Finding{
					RuleID:        fmt.Sprintf("iostat-discard-soft-%s", device),
					Source:        "iostat",
					Category:      "disk_latency",
					Severity:      SeverityMedium,
					Title:         fmt.Sprintf("%s discard/TRIM 延迟接近阈值", device),
					Summary:       softLatencySummary("discard/TRIM ", discardStats.P95, softLatencyThreshold, context),
					Target:        device,
					Metric:        "discard_await_p95_ms",
					Operator:      ">=",
					Threshold:     softLatencyThreshold,
					ObservedValue: discardStats.P95,
					EvidenceRef:   fmt.Sprintf("iostat:%s:discard_await_p95_ms", device),
					Metrics: map[string]float64{
						"discard_latency_p95_ms":  discardStats.P95,
						"soft_threshold_ms":       softLatencyThreshold,
						"total_iops_at_peak":      context.totalIOPSAtPeak,
						"avg_queue_at_peak":       context.avgQueueAtPeak,
						"cpu_iowait_at_peak":      context.cpuIOWaitAtPeak,
						"latency_corroborated":    context.corroboratedValue(),
						"latency_system_pressure": context.systemPressureValue(),
					},
					Tags: []string{"disk", "latency", device, "discard"},
				})
			}
		}

		queueSeverity := queueSeverity(queueStats, cfg)
		if queueSeverity != "" {
			result = append(result, Finding{
				RuleID:        fmt.Sprintf("iostat-queue-%s", device),
				Source:        "iostat",
				Category:      "disk_queue",
				Severity:      queueSeverity,
				Title:         fmt.Sprintf("%s 队列深度偏高", device),
				Summary:       queueSummary(queueStats),
				Target:        device,
				Metric:        "avg_queue_peak",
				Operator:      ">=",
				Threshold:     thresholdForSeverity(queueSeverity, cfg.QueueHard, cfg.QueueSoft),
				ObservedValue: queueStats.peak,
				EvidenceRef:   evidenceRef("iostat", device, "avg_queue_peak", queueStats.peakTime),
				Time:          queueStats.peakTime.Format(timeLayout),
				Metrics: map[string]float64{
					"avg_queue_depth":         avgQueue,
					"active_avg_queue_depth":  queueStats.avg,
					"avg_queue_peak":          queueStats.peak,
					"queue_depth_peak":        queueStats.peak,
					"queue_active_samples":    float64(queueStats.activeSamples),
					"active_sample_count":     float64(queueStats.activeSamples),
					"active_ratio":            queueStats.activeRatio,
					"soft_queue_sample_count": float64(queueStats.softQueueSamples),
					"hard_queue_sample_count": float64(queueStats.hardQueueSamples),
					"high_queue_sample_count": float64(queueStats.hardQueueSamples),
					"longest_queue_run":       float64(queueStats.longestQueueRun),
					"queue_peak_iops":         queueStats.iopsAtPeak,
					"read_iops_at_peak":       queueStats.readIOPSAtPeak,
					"write_iops_at_peak":      queueStats.writeIOPSAtPeak,
					"discard_iops_at_peak":    queueStats.discardIOPSAtPeak,
					"total_iops_at_peak":      queueStats.iopsAtPeak,
					"cpu_iowait_at_peak":      queueStats.cpuIOWaitAtPeak,
				},
				Tags: []string{"disk", "queue", device},
			})
		}

		utilStats := summarizeDeviceUtilization(log, device, start, end, softLatencyThreshold, cfg)
		utilSeverity := utilSeverity(utilStats, cfg)
		if utilSeverity != "" {
			result = append(result, Finding{
				RuleID:        fmt.Sprintf("iostat-util-%s", device),
				Source:        "iostat",
				Category:      "disk_utilization",
				Severity:      utilSeverity,
				Title:         fmt.Sprintf("%s 磁盘利用率持续偏高", device),
				Summary:       utilSummary(utilStats),
				Target:        device,
				Metric:        "util_pct",
				Operator:      ">=",
				Threshold:     thresholdForSeverity(utilSeverity, cfg.UtilHardPct, cfg.UtilSoftPct),
				ObservedValue: utilStats.peak,
				EvidenceRef:   evidenceRef("iostat", device, "util_pct", utilStats.peakTime),
				Time:          utilStats.peakTime.Format(timeLayout),
				Metrics: map[string]float64{
					"util_avg_pct":            utilStats.avg,
					"util_peak_pct":           utilStats.peak,
					"util_active_samples":     float64(utilStats.activeSamples),
					"util_soft_sample_count":  float64(utilStats.softSamples),
					"util_hard_sample_count":  float64(utilStats.hardSamples),
					"util_high_sample_count":  float64(utilStats.hardSamples),
					"util_corroborated":       boolAsFloat(utilStats.corroborated),
					"read_await_at_peak":      utilStats.readAwaitAtPeak,
					"write_await_at_peak":     utilStats.writeAwaitAtPeak,
					"discard_await_at_peak":   utilStats.discardAwaitAtPeak,
					"avg_queue_at_peak":       utilStats.avgQueueAtPeak,
					"cpu_iowait_at_peak":      utilStats.cpuIOWaitAtPeak,
					"read_iops_at_peak":       utilStats.readIOPSAtPeak,
					"write_iops_at_peak":      utilStats.writeIOPSAtPeak,
					"discard_iops_at_peak":    utilStats.discardIOPSAtPeak,
					"total_iops_at_peak":      utilStats.iopsAtPeak,
					"throughput_kb_s_at_peak": utilStats.throughputKBAtPeak,
				},
				Tags: []string{"disk", "utilization", device},
			})
		}
	}

	annotateStackDuplicateLatency(result)
	result = append(result, buildMultiDeviceLatencyFindings(result)...)
	sortFindings(result)
	return result
}

type iostatCPUWaitStats struct {
	max          float64
	avg          float64
	maxTime      time.Time
	samples      int
	softSamples  int
	hardSamples  int
	corroborated bool
}

func summarizeIOWait(log *iostat.IOStatLog, start, end time.Time, cfg config.IostatConfig) iostatCPUWaitStats {
	var stats iostatCPUWaitStats
	sum := 0.0
	for _, item := range log.Data {
		if item.Timestamp.Before(start) || item.Timestamp.After(end) {
			continue
		}
		stats.samples++
		sum += item.CPU.IOWait
		if item.CPU.IOWait >= cfg.CPUWaitSoftPct {
			stats.softSamples++
		}
		if item.CPU.IOWait >= cfg.CPUWaitHardPct {
			stats.hardSamples++
		}
		if stats.samples == 1 || item.CPU.IOWait > stats.max {
			stats.max = item.CPU.IOWait
			stats.maxTime = item.Timestamp
		}
	}
	if stats.samples == 0 {
		return stats
	}
	stats.avg = sum / float64(stats.samples)
	return stats
}

func iostatCPUWaitSeverity(stats iostatCPUWaitStats, cfg config.IostatConfig) Severity {
	switch {
	case stats.hardSamples >= 2 || (stats.samples >= 2 && stats.avg >= cfg.CPUWaitHardPct) || (stats.max >= cfg.CPUWaitHardPct && stats.corroborated):
		return SeverityHigh
	case stats.softSamples >= 2 || (stats.samples >= 2 && stats.avg >= cfg.CPUWaitSoftPct) || (stats.max >= cfg.CPUWaitSoftPct && stats.corroborated):
		return SeverityMedium
	default:
		return ""
	}
}

func iostatCPUWaitHasDiskEvidence(log *iostat.IOStatLog, start, end, at time.Time, cfg config.IostatConfig) bool {
	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) || !data.Timestamp.Equal(at) {
			continue
		}
		for _, device := range data.Devices {
			if !deviceHasActiveIO(device) {
				continue
			}
			if device.AvgQueueSize >= cfg.QueueSoft ||
				(deviceHasReadActivity(device) && device.ReadAwait >= deviceLatencySoftThreshold(device.Device, cfg)) ||
				(deviceHasWriteActivity(device) && device.WriteAwait >= deviceLatencySoftThreshold(device.Device, cfg)) ||
				(deviceHasDiscardActivity(device) && device.DiscardAwait >= deviceLatencySoftThreshold(device.Device, cfg)) {
				return true
			}
		}
	}
	return false
}

type activeQueueStats struct {
	avg               float64
	peak              float64
	peakTime          time.Time
	totalSamples      int
	activeSamples     int
	activeRatio       float64
	softQueueSamples  int
	hardQueueSamples  int
	longestQueueRun   int
	currentQueueRun   int
	readIOPSAtPeak    float64
	writeIOPSAtPeak   float64
	discardIOPSAtPeak float64
	iopsAtPeak        float64
	cpuIOWaitAtPeak   float64
}

type deviceUtilStats struct {
	avg                float64
	peak               float64
	peakTime           time.Time
	activeSamples      int
	softSamples        int
	hardSamples        int
	corroborated       bool
	readAwaitAtPeak    float64
	writeAwaitAtPeak   float64
	discardAwaitAtPeak float64
	avgQueueAtPeak     float64
	cpuIOWaitAtPeak    float64
	readIOPSAtPeak     float64
	writeIOPSAtPeak    float64
	discardIOPSAtPeak  float64
	iopsAtPeak         float64
	throughputKBAtPeak float64
}

func summarizeDeviceUtilization(log *iostat.IOStatLog, deviceName string, start, end time.Time, latencySoftThreshold float64, cfg config.IostatConfig) deviceUtilStats {
	var stats deviceUtilStats
	if log == nil {
		return stats
	}
	sum := 0.0
	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) {
			continue
		}
		for _, device := range data.Devices {
			if device.Device != deviceName {
				continue
			}
			if !deviceHasActiveIO(device) {
				break
			}
			stats.activeSamples++
			sum += device.Utilization
			sampleCorroborated := device.Utilization >= cfg.UtilSoftPct && utilPeakHasEvidence(device, data.CPU.IOWait, latencySoftThreshold, cfg)
			if sampleCorroborated {
				stats.corroborated = true
			}
			if device.Utilization >= cfg.UtilSoftPct {
				stats.softSamples++
			}
			if device.Utilization >= cfg.UtilHardPct {
				stats.hardSamples++
			}
			if stats.activeSamples == 1 || device.Utilization > stats.peak {
				stats.peak = device.Utilization
				stats.peakTime = data.Timestamp
				stats.readAwaitAtPeak = device.ReadAwait
				stats.writeAwaitAtPeak = device.WriteAwait
				stats.discardAwaitAtPeak = device.DiscardAwait
				stats.avgQueueAtPeak = device.AvgQueueSize
				stats.cpuIOWaitAtPeak = data.CPU.IOWait
				stats.readIOPSAtPeak = device.ReadReqPerSec
				stats.writeIOPSAtPeak = device.WriteReqPerSec
				stats.discardIOPSAtPeak = device.DiscardReqPerSec
				stats.iopsAtPeak = deviceTotalIOPS(device)
				stats.throughputKBAtPeak = deviceThroughputKB(device)
			}
			break
		}
	}
	if stats.activeSamples > 0 {
		stats.avg = sum / float64(stats.activeSamples)
	}
	return stats
}

func utilPeakHasEvidence(device iostat.DeviceStats, cpuIOWait float64, latencySoftThreshold float64, cfg config.IostatConfig) bool {
	return (deviceHasReadActivity(device) && device.ReadAwait >= latencySoftThreshold) ||
		(deviceHasWriteActivity(device) && device.WriteAwait >= latencySoftThreshold) ||
		(deviceHasDiscardActivity(device) && device.DiscardAwait >= latencySoftThreshold) ||
		device.AvgQueueSize >= cfg.QueueSoft ||
		cpuIOWait >= cfg.CPUWaitSoftPct
}

func utilSeverity(stats deviceUtilStats, cfg config.IostatConfig) Severity {
	if stats.activeSamples < cfg.UtilMinSamples {
		return ""
	}
	if !stats.corroborated {
		if stats.hardSamples >= cfg.UtilMinSamples || stats.avg >= cfg.UtilHardPct {
			return SeverityMedium
		}
		return ""
	}
	switch {
	case stats.hardSamples >= cfg.UtilMinSamples || stats.avg >= cfg.UtilHardPct:
		return SeverityHigh
	case stats.softSamples >= cfg.UtilMinSamples || stats.avg >= cfg.UtilSoftPct:
		return SeverityMedium
	default:
		return ""
	}
}

func utilSummary(stats deviceUtilStats) string {
	base := fmt.Sprintf("活跃样本平均 util %.1f%%，峰值 %.1f%%；峰值时 IOPS %.2f，吞吐 %.1f KB/s，写延迟 %.1fms，队列 %.2f，CPU iowait %.1f%%。",
		stats.avg, stats.peak, stats.iopsAtPeak, stats.throughputKBAtPeak, stats.writeAwaitAtPeak, stats.avgQueueAtPeak, stats.cpuIOWaitAtPeak)
	if !stats.corroborated {
		return base + " 未见延迟/队列/iowait 佐证，按设备繁忙候选线索保留。"
	}
	return base
}

func summarizeActiveQueue(log *iostat.IOStatLog, deviceName string, start, end time.Time, cfg config.IostatConfig) activeQueueStats {
	var stats activeQueueStats
	if log == nil {
		return stats
	}
	sum := 0.0
	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) {
			continue
		}
		for _, device := range data.Devices {
			if device.Device != deviceName {
				continue
			}
			stats.totalSamples++
			iops := deviceTotalIOPS(device)
			if !deviceHasActiveIO(device) {
				stats.currentQueueRun = 0
				break
			}
			stats.activeSamples++
			sum += device.AvgQueueSize
			if device.AvgQueueSize >= cfg.QueueSoft {
				stats.softQueueSamples++
				stats.currentQueueRun++
				if stats.currentQueueRun > stats.longestQueueRun {
					stats.longestQueueRun = stats.currentQueueRun
				}
			} else {
				stats.currentQueueRun = 0
			}
			if device.AvgQueueSize >= cfg.QueueHard {
				stats.hardQueueSamples++
			}
			if stats.activeSamples == 1 || device.AvgQueueSize > stats.peak {
				stats.peak = device.AvgQueueSize
				stats.peakTime = data.Timestamp
				stats.readIOPSAtPeak = device.ReadReqPerSec
				stats.writeIOPSAtPeak = device.WriteReqPerSec
				stats.discardIOPSAtPeak = device.DiscardReqPerSec
				stats.iopsAtPeak = iops
				stats.cpuIOWaitAtPeak = data.CPU.IOWait
			}
			break
		}
	}
	if stats.activeSamples > 0 {
		stats.avg = sum / float64(stats.activeSamples)
	}
	if stats.totalSamples > 0 {
		stats.activeRatio = float64(stats.activeSamples) / float64(stats.totalSamples)
	}
	return stats
}

func deviceTotalIOPS(device iostat.DeviceStats) float64 {
	return device.ReadReqPerSec + device.WriteReqPerSec + device.DiscardReqPerSec
}

func deviceThroughputKB(device iostat.DeviceStats) float64 {
	return device.ReadKBPerSec + device.WriteKBPerSec + device.DiscardKBPerSec
}

func deviceHasActiveIO(device iostat.DeviceStats) bool {
	return deviceTotalIOPS(device) > 0 ||
		device.ReadKBPerSec > 0 ||
		device.WriteKBPerSec > 0 ||
		device.DiscardKBPerSec > 0
}

func deviceHasReadActivity(device iostat.DeviceStats) bool {
	return device.ReadReqPerSec > 0 || device.ReadKBPerSec > 0
}

func deviceHasWriteActivity(device iostat.DeviceStats) bool {
	return device.WriteReqPerSec > 0 || device.WriteKBPerSec > 0
}

func deviceHasDiscardActivity(device iostat.DeviceStats) bool {
	return device.DiscardReqPerSec > 0 || device.DiscardKBPerSec > 0
}

func deviceHasActivityInRange(log *iostat.IOStatLog, deviceName string, start, end time.Time) bool {
	if log == nil {
		return false
	}
	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) {
			continue
		}
		for _, device := range data.Devices {
			if device.Device == deviceName && deviceHasActiveIO(device) {
				return true
			}
		}
	}
	return false
}

func annotateStackDuplicateLatency(findings []Finding) {
	physicalByKey := make(map[string]int)
	for _, finding := range findings {
		if finding.Category != "disk_latency" || finding.Severity != SeverityHigh || !isPhysicalDevice(finding.Target) {
			continue
		}
		key := latencyDuplicateKey(finding)
		if key == "" {
			continue
		}
		physicalByKey[key]++
	}

	for index := range findings {
		finding := &findings[index]
		if finding.Category != "disk_latency" || finding.Severity != SeverityHigh || !isUpperLayerDevice(finding.Target) {
			continue
		}
		peerCount := physicalByKey[latencyDuplicateKey(*finding)]
		if peerCount == 0 {
			continue
		}
		finding.Severity = SeverityMedium
		if finding.Metrics == nil {
			finding.Metrics = make(map[string]float64)
		}
		finding.Metrics["stack_duplicate_with_physical"] = 1
		finding.Metrics["physical_peer_count"] = float64(peerCount)
		finding.Summary += " 该上层设备异常与同时间物理盘异常重合，按设备栈重复线索降级，优先查看底层物理盘。"
	}
}

func latencyDuplicateKey(finding Finding) string {
	if finding.Time == "" {
		return ""
	}
	switch finding.Metric {
	case "read_await_ms", "write_await_ms", "discard_await_ms":
		return finding.Metric + "|" + finding.Time
	default:
		return ""
	}
}

func isUpperLayerDevice(device string) bool {
	return strings.HasPrefix(device, "dm-") || strings.HasPrefix(device, "md")
}

func isPhysicalDevice(device string) bool {
	return strings.HasPrefix(device, "nvme") ||
		strings.HasPrefix(device, "sd") ||
		strings.HasPrefix(device, "vd") ||
		strings.HasPrefix(device, "xvd") ||
		strings.HasPrefix(device, "mpath")
}

type multiDeviceLatencyGroup struct {
	metric       string
	time         string
	devices      []string
	maxLatency   float64
	maxQueue     float64
	maxIOWait    float64
	totalIOPS    float64
	threshold    float64
	evidenceRefs []string
}

func buildMultiDeviceLatencyFindings(items []Finding) []Finding {
	groups := make(map[string]*multiDeviceLatencyGroup)
	for _, item := range items {
		if item.Category != "disk_latency" ||
			item.Severity != SeverityHigh ||
			item.Time == "" ||
			!isPhysicalDevice(item.Target) ||
			item.Metrics["latency_system_pressure"] != 1 {
			continue
		}
		switch item.Metric {
		case "read_await_ms", "write_await_ms", "discard_await_ms":
		default:
			continue
		}
		key := item.Metric + "|" + item.Time
		group := groups[key]
		if group == nil {
			group = &multiDeviceLatencyGroup{
				metric:    item.Metric,
				time:      item.Time,
				threshold: item.Threshold,
			}
			groups[key] = group
		}
		group.devices = append(group.devices, item.Target)
		group.evidenceRefs = append(group.evidenceRefs, item.EvidenceRef)
		if item.ObservedValue > group.maxLatency {
			group.maxLatency = item.ObservedValue
		}
		if queue := item.Metrics["avg_queue_at_peak"]; queue > group.maxQueue {
			group.maxQueue = queue
		}
		if iowait := item.Metrics["cpu_iowait_at_peak"]; iowait > group.maxIOWait {
			group.maxIOWait = iowait
		}
		group.totalIOPS += item.Metrics["total_iops_at_peak"]
	}

	var findings []Finding
	for _, group := range groups {
		if len(group.devices) < 2 {
			continue
		}
		sort.Strings(group.devices)
		direction := latencyDirectionLabel(group.metric)
		findings = append(findings, Finding{
			RuleID:        fmt.Sprintf("iostat-multi-device-%s-latency", direction),
			Source:        "iostat",
			Category:      "disk_latency",
			Severity:      SeverityHigh,
			Nature:        FindingNatureRisk,
			Title:         fmt.Sprintf("多块物理盘%s延迟同窗口偏高", latencyDirectionChinese(group.metric)),
			Summary:       multiDeviceLatencySummary(group, latencyDirectionChinese(group.metric)),
			Target:        "storage",
			Metric:        group.metric,
			Operator:      ">=",
			Threshold:     group.threshold,
			ObservedValue: group.maxLatency,
			EvidenceRef:   fmt.Sprintf("iostat:storage:%s:%s", group.metric, group.time),
			Time:          group.time,
			Metrics: map[string]float64{
				"affected_device_count": float64(len(group.devices)),
				"max_latency_ms":        group.maxLatency,
				"max_queue_depth":       group.maxQueue,
				"cpu_iowait_at_peak":    group.maxIOWait,
				"total_iops_at_peak":    group.totalIOPS,
			},
			Tags: []string{"disk", "latency", "multi_device", direction},
		})
	}
	return findings
}

func latencyDirectionLabel(metric string) string {
	switch metric {
	case "read_await_ms":
		return "read"
	case "write_await_ms":
		return "write"
	case "discard_await_ms":
		return "discard"
	default:
		return "unknown"
	}
}

func latencyDirectionChinese(metric string) string {
	switch metric {
	case "read_await_ms":
		return "读"
	case "write_await_ms":
		return "写"
	case "discard_await_ms":
		return "discard/TRIM "
	default:
		return ""
	}
}

func multiDeviceLatencySummary(group *multiDeviceLatencyGroup, direction string) string {
	return fmt.Sprintf("%s延迟在同一时间由 %s 共同出现异常；影响 %d 块物理盘，最高 %.1fms，最大队列 %.2f，CPU iowait %.1f%%，合计 IOPS %.2f。多设备同窗口异常更像系统级 I/O 压力或共享存储路径问题，优先排查控制器、链路、阵列或宿主机 I/O 栈。",
		direction, strings.Join(group.devices, ", "), len(group.devices), group.maxLatency, group.maxQueue, group.maxIOWait, group.totalIOPS)
}

func queueSeverity(stats activeQueueStats, cfg config.IostatConfig) Severity {
	switch {
	case stats.activeSamples == 0:
		return ""
	case stats.avg >= cfg.QueueHard && stats.activeSamples >= 2:
		return SeverityHigh
	case stats.hardQueueSamples >= 2:
		return SeverityHigh
	case stats.peak >= cfg.QueueHard && stats.cpuIOWaitAtPeak >= cfg.CPUWaitSoftPct:
		return SeverityHigh
	case stats.peak >= cfg.QueueHard && stats.iopsAtPeak >= cfg.LatencyIOPSSoft:
		return SeverityMedium
	case stats.avg >= cfg.QueueSoft && stats.activeSamples >= 2:
		return SeverityMedium
	default:
		return ""
	}
}

func queueSummary(stats activeQueueStats) string {
	return fmt.Sprintf("活跃样本平均队列 %.2f，峰值 %.2f；峰值时 IOPS %.2f，CPU iowait %.1f%%。", stats.avg, stats.peak, stats.iopsAtPeak, stats.cpuIOWaitAtPeak)
}

func maxLatencyAnomaly(anomalies []iostat.AnomalyPoint) iostat.AnomalyPoint {
	if len(anomalies) == 0 {
		return iostat.AnomalyPoint{}
	}
	maxPoint := anomalies[0]
	for _, item := range anomalies[1:] {
		if item.Value > maxPoint.Value {
			maxPoint = item
		}
	}
	return maxPoint
}

type iostatLatencyContext struct {
	readIOPSAtPeak    float64
	writeIOPSAtPeak   float64
	discardIOPSAtPeak float64
	totalIOPSAtPeak   float64
	avgQueueAtPeak    float64
	cpuIOWaitAtPeak   float64
	corroborated      bool
	systemPressure    bool
}

func latencyEvidenceContext(log *iostat.IOStatLog, deviceName string, start, end, at time.Time, cfg config.IostatConfig) iostatLatencyContext {
	var context iostatLatencyContext
	if log == nil {
		return context
	}

	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) || !data.Timestamp.Equal(at) {
			continue
		}
		context.cpuIOWaitAtPeak = data.CPU.IOWait
		for _, device := range data.Devices {
			if device.Device != deviceName {
				continue
			}
			context.readIOPSAtPeak = device.ReadReqPerSec
			context.writeIOPSAtPeak = device.WriteReqPerSec
			context.discardIOPSAtPeak = device.DiscardReqPerSec
			context.totalIOPSAtPeak = deviceTotalIOPS(device)
			context.avgQueueAtPeak = device.AvgQueueSize
			context.systemPressure = context.avgQueueAtPeak >= cfg.QueueSoft ||
				context.cpuIOWaitAtPeak >= cfg.CPUWaitSoftPct
			context.corroborated = context.totalIOPSAtPeak >= cfg.LatencyIOPSSoft ||
				context.systemPressure
			return context
		}
	}
	return context
}

func softLatencyHasEvidence(log *iostat.IOStatLog, deviceName string, start, end time.Time, direction string, softThreshold float64, cfg config.IostatConfig) bool {
	if log == nil {
		return false
	}
	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) {
			continue
		}
		for _, device := range data.Devices {
			if device.Device != deviceName {
				continue
			}
			active, iops, await := latencyDirectionActivity(device, direction)
			if !active || await < softThreshold {
				break
			}
			if iops >= cfg.LatencyIOPSSoft ||
				device.AvgQueueSize >= cfg.QueueSoft ||
				data.CPU.IOWait >= cfg.CPUWaitSoftPct {
				return true
			}
			break
		}
	}
	return false
}

func softLatencyEvidenceContext(log *iostat.IOStatLog, deviceName string, start, end time.Time, direction string, softThreshold float64, cfg config.IostatConfig) iostatLatencyContext {
	var context iostatLatencyContext
	if log == nil {
		return context
	}
	for _, data := range log.Data {
		if data.Timestamp.Before(start) || data.Timestamp.After(end) {
			continue
		}
		for _, device := range data.Devices {
			if device.Device != deviceName {
				continue
			}
			active, iops, await := latencyDirectionActivity(device, direction)
			if !active || await < softThreshold {
				break
			}
			if iops > context.totalIOPSAtPeak {
				context.totalIOPSAtPeak = iops
			}
			if device.AvgQueueSize > context.avgQueueAtPeak {
				context.avgQueueAtPeak = device.AvgQueueSize
			}
			if data.CPU.IOWait > context.cpuIOWaitAtPeak {
				context.cpuIOWaitAtPeak = data.CPU.IOWait
			}
			if device.AvgQueueSize >= cfg.QueueSoft || data.CPU.IOWait >= cfg.CPUWaitSoftPct {
				context.systemPressure = true
			}
			if iops >= cfg.LatencyIOPSSoft || context.systemPressure {
				context.corroborated = true
			}
			break
		}
	}
	return context
}

func latencyDirectionActivity(device iostat.DeviceStats, direction string) (bool, float64, float64) {
	switch direction {
	case "read":
		return deviceHasReadActivity(device), device.ReadReqPerSec, device.ReadAwait
	case "write":
		return deviceHasWriteActivity(device), device.WriteReqPerSec, device.WriteAwait
	case "discard":
		return deviceHasDiscardActivity(device), device.DiscardReqPerSec, device.DiscardAwait
	default:
		return false, 0, 0
	}
}

func latencySeverity(stats iostat.LatencyStats, context iostatLatencyContext) Severity {
	if !context.corroborated {
		return SeverityMedium
	}
	return SeverityHigh
}

func latencyTitle(device, direction string, stats iostat.LatencyStats) string {
	if isSustainedThresholdLatency(stats) {
		return fmt.Sprintf("%s %s延迟持续偏高", device, direction)
	}
	return fmt.Sprintf("%s %s延迟存在突增", device, direction)
}

func latencySummary(direction string, stats iostat.LatencyStats, peak float64, context iostatLatencyContext) string {
	peakLabel := "最严重异常"
	if isSustainedThresholdLatency(stats) {
		peakLabel = "最高样本"
	}
	base := fmt.Sprintf("%s延迟 P95 %.1fms，%s %.1fms；峰值时 IOPS %.2f，队列 %.2f，CPU iowait %.1f%%。", direction, stats.P95, peakLabel, peak, context.totalIOPSAtPeak, context.avgQueueAtPeak, context.cpuIOWaitAtPeak)
	if !context.corroborated {
		return base + " 当前缺少 IOPS、队列或 iowait 佐证，按慢请求线索保留。"
	}
	if !context.systemPressure {
		return base + " 峰值时存在 IOPS，说明设备有活跃 I/O；但未见队列或 iowait 系统级压力，优先按设备级慢请求/瞬时尖峰排查。"
	}
	return base
}

func softLatencySummary(direction string, p95, softThreshold float64, context iostatLatencyContext) string {
	base := fmt.Sprintf("%s延迟 P95 %.1fms，已接近设备软阈值 %.1fms；相关样本最大 IOPS %.2f，最大队列 %.2f，最大 CPU iowait %.1f%%。", direction, p95, softThreshold, context.totalIOPSAtPeak, context.avgQueueAtPeak, context.cpuIOWaitAtPeak)
	if !context.systemPressure {
		return base + " 未见系统级压力佐证，按设备级候选线索保留。"
	}
	return base
}

func isSustainedThresholdLatency(stats iostat.LatencyStats) bool {
	if stats.Count <= 1 || len(stats.Anomalies) != stats.Count {
		return false
	}
	for _, anomaly := range stats.Anomalies {
		if anomaly.Method != "threshold" {
			return false
		}
	}
	return true
}

func (context iostatLatencyContext) corroboratedValue() float64 {
	if context.corroborated {
		return 1
	}
	return 0
}

func (context iostatLatencyContext) systemPressureValue() float64 {
	if context.systemPressure {
		return 1
	}
	return 0
}

func deviceLatencyHardThreshold(device string, cfg config.IostatConfig) float64 {
	switch {
	case strings.HasPrefix(device, "nvme"):
		return cfg.NVMeLatencyHardMS
	case strings.HasPrefix(device, "sd"), isUpperLayerDevice(device):
		return cfg.DefaultLatencyHardMS
	default:
		return cfg.DefaultLatencyHardMS
	}
}

func deviceLatencySoftThreshold(device string, cfg config.IostatConfig) float64 {
	switch {
	case strings.HasPrefix(device, "nvme"):
		return cfg.NVMeLatencySoftMS
	case strings.HasPrefix(device, "sd"), isUpperLayerDevice(device):
		return cfg.DefaultLatencySoftMS
	default:
		return cfg.DefaultLatencySoftMS
	}
}

func severityFromThreshold(value, high, medium float64) Severity {
	switch {
	case value >= high:
		return SeverityHigh
	case value >= medium:
		return SeverityMedium
	default:
		return ""
	}
}

func thresholdForSeverity(severity Severity, high, medium float64) float64 {
	if severity == SeverityHigh {
		return high
	}
	return medium
}

func evidenceRef(source, target, metric string, at time.Time) string {
	return fmt.Sprintf("%s:%s:%s:%s", source, target, metric, at.Format(timeLayout))
}

func sortFindings(findings []Finding) {
	applyFindingNature(findings)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default:
		return 3
	}
}
