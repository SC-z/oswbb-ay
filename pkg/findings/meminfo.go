package findings

import (
	"fmt"
	"math"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/pkg/meminfo"
	"time"
)

func BuildMemInfoFindings(log *meminfo.MemInfoLog, start, end time.Time) []Finding {
	return BuildMemInfoFindingsWithConfig(log, start, end, config.Default().Meminfo)
}

func BuildMemInfoFindingsWithConfig(log *meminfo.MemInfoLog, start, end time.Time, cfg config.MeminfoConfig) []Finding {
	if log == nil {
		return nil
	}
	cfg = cfg.WithDefaults()

	data := filterMemInfoRange(log.Data, start, end)
	if len(data) == 0 {
		return nil
	}
	data = filterValidMemInfoSamples(data)
	if len(data) == 0 {
		return nil
	}

	latest := data[len(data)-1]

	var result []Finding
	windowStart := data[0].Timestamp.Format(timeLayout)
	windowEnd := data[len(data)-1].Timestamp.Format(timeLayout)
	availableData := filterAvailableMemInfoSamples(data)
	if len(availableData) > 0 {
		latestAvailable := availableData[len(availableData)-1]
		memTotalKB := float64(latestAvailable.MemStats.MemTotal)
		worstAvailable := minMemInfoSample(availableData, func(item meminfo.MemStatData) float64 {
			return ratioPct(effectiveMemAvailableKB(item.MemStats), float64(item.MemStats.MemTotal))
		})
		worstMemTotalKB := float64(worstAvailable.MemStats.MemTotal)
		availKB := effectiveMemAvailableKB(worstAvailable.MemStats)
		availPct := ratioPct(availKB, worstMemTotalKB)
		availMB := kbToMB(availKB)
		currentAvailKB := effectiveMemAvailableKB(latestAvailable.MemStats)
		currentAvailPct := ratioPct(currentAvailKB, memTotalKB)
		currentAvailMB := kbToMB(currentAvailKB)
		availableStats := summarizeAvailablePressure(availableData, currentAvailPct, cfg)
		availSeverity := availabilitySeverityWithRecovery(availPct, availableStats, cfg)
		if availSeverity != "" {
			result = append(result, Finding{
				RuleID:        "meminfo-available",
				Source:        "meminfo",
				Category:      "memory_available",
				Severity:      availSeverity,
				Title:         "可用内存偏低",
				Summary:       availableSummary(availPct, availKB, currentAvailPct, currentAvailKB, availableStats),
				Target:        "memory",
				Metric:        "mem_available_pct",
				Operator:      "<",
				Threshold:     memAvailableThresholdForSeverity(availSeverity, cfg),
				ObservedValue: availPct,
				EvidenceRef:   fmt.Sprintf("meminfo:memory:mem_available_pct:%s", worstAvailable.Timestamp.Format(timeLayout)),
				Time:          worstAvailable.Timestamp.Format(timeLayout),
				WindowStart:   windowStart,
				WindowEnd:     windowEnd,
				Metrics: map[string]float64{
					"mem_available_pct":                 availPct,
					"mem_available_mb":                  availMB,
					"mem_available_current_pct":         currentAvailPct,
					"mem_available_current_mb":          currentAvailMB,
					"mem_available_soft_sample_count":   float64(availableStats.softSamples),
					"mem_available_warn_sample_count":   float64(availableStats.warnSamples),
					"mem_available_severe_sample_count": float64(availableStats.severeSamples),
					"mem_available_recovered":           boolAsFloat(availableStats.recovered),
				},
				Tags: []string{"memory", "available"},
			})
		}
	}

	anonSegment, hasAnonGrowth := worstAnonGrowthSegment(data, cfg)
	anonDeltaMB := anonSegment.deltaMB
	anonRateMB := anonSegment.rateMB
	anonSeverity := anonSeverity(anonSegment, cfg)
	if hasAnonGrowth && anonSeverity != "" {
		currentAnonMB := kbToMB(float64(latest.MemStats.AnonPages))
		anonDeltaPct := anonGrowthDeltaPct(anonSegment)
		anonPeakPct := anonGrowthPeakPct(anonSegment)
		hasPressure := anonGrowthHasMemoryPressure(anonSegment, cfg)
		result = append(result, Finding{
			RuleID:        "meminfo-anon-growth",
			Source:        "meminfo",
			Category:      "memory_anon_growth",
			Severity:      anonSeverity,
			Title:         "匿名页持续增长",
			Summary:       fmt.Sprintf("短窗匿名页从 %.1f MB 增至 %.1f MB，增量 %.1f MB，占总内存 %.2f%%，平均变化 %.1f MB/点，约 %.1f MB/min；当前 %.1f MB；%s。", anonSegment.startMB, anonSegment.endMB, anonDeltaMB, anonDeltaPct, anonRateMB, anonSegment.rateMBPerMinute, currentAnonMB, anonPressureSummary(hasPressure)),
			Target:        "memory",
			Metric:        "anon_delta_mb",
			Operator:      ">=",
			Threshold:     thresholdForSeverity(anonSeverity, cfg.AnonLeakHardMB, cfg.AnonLeakSoftMB),
			ObservedValue: anonDeltaMB,
			EvidenceRef:   fmt.Sprintf("meminfo:memory:anon_delta_mb:%s", anonSegment.end.Timestamp.Format(timeLayout)),
			Time:          anonSegment.end.Timestamp.Format(timeLayout),
			WindowStart:   anonSegment.start.Timestamp.Format(timeLayout),
			WindowEnd:     anonSegment.end.Timestamp.Format(timeLayout),
			Metrics: map[string]float64{
				"anon_delta_mb":                  anonDeltaMB,
				"anon_rate_mb":                   anonRateMB,
				"anon_growth_window_mb":          anonDeltaMB,
				"anon_growth_rate_mb_per_sample": anonRateMB,
				"anon_growth_rate_mb_per_min":    anonSegment.rateMBPerMinute,
				"anon_start_mb":                  anonSegment.startMB,
				"anon_peak_mb":                   anonSegment.endMB,
				"anon_current_mb":                currentAnonMB,
				"anon_growth_pct_of_memtotal":    anonDeltaPct,
				"anon_peak_pct_of_memtotal":      anonPeakPct,
				"anon_pressure_corroborated":     boolAsFloat(hasPressure),
			},
			Tags: []string{"memory", "anon"},
		})
	}

	if swapStats, ok := worstSwapUsage(data); ok {
		worstSwap := swapStats.sample
		swapUsed := swapStats.usedKB
		swapPct := swapStats.usedPct
		swapUsedGB := kbToGB(swapUsed)
		currentSwapUsed, currentSwapPct := latestSwapUsage(data, swapStats.usedKB, swapStats.usedPct)
		swapGrowthMB := kbToMB(swapStats.growthKB)
		swapAvailPct, swapHasAvailable := availablePctForSample(worstSwap.MemStats)
		swapRecovered := currentSwapPct == 0
		swapSeverity := Severity("")
		switch {
		case swapPct >= cfg.SwapWarnPct && (swapGrowthMB >= cfg.SwapGrowthSoftMB || (swapHasAvailable && swapAvailPct < cfg.AvailableWarnPct)):
			swapSeverity = SeverityHigh
		case swapPct > 0 && (swapGrowthMB >= cfg.SwapGrowthSoftMB || (swapHasAvailable && swapAvailPct < cfg.AvailableSoftPct)):
			swapSeverity = SeverityMedium
		}
		if swapSeverity != "" {
			result = append(result, Finding{
				RuleID:        "meminfo-swap-usage",
				Source:        "meminfo",
				Category:      "memory_swap",
				Severity:      swapSeverity,
				Title:         "Swap 已开始参与回收",
				Summary:       fmt.Sprintf("Swap 使用峰值 %.1f%%，已用 %.2f GB；当前 %.1f%%，已用 %.2f GB。%s", swapPct, swapUsedGB, currentSwapPct, kbToGB(currentSwapUsed), recoveredSummarySuffix(swapRecovered)),
				Target:        "memory",
				Metric:        "swap_used_pct",
				Operator:      ">",
				Threshold:     swapThresholdForSeverity(swapSeverity, cfg),
				ObservedValue: swapPct,
				EvidenceRef:   fmt.Sprintf("meminfo:memory:swap_used_pct:%s", worstSwap.Timestamp.Format(timeLayout)),
				Time:          worstSwap.Timestamp.Format(timeLayout),
				WindowStart:   windowStart,
				WindowEnd:     windowEnd,
				Metrics: map[string]float64{
					"swap_used_pct":         swapPct,
					"swap_used_gb":          swapUsedGB,
					"swap_used_growth_gb":   kbToGB(swapStats.growthKB),
					"swap_used_current_pct": currentSwapPct,
					"swap_used_current_gb":  kbToGB(currentSwapUsed),
					"swap_recovered":        boolAsFloat(swapRecovered),
				},
				Tags: []string{"memory", "swap"},
			})
		}
	}

	if worstCommit, ok := maxMemInfoSample(data, func(item meminfo.MemStatData) (float64, bool) {
		if item.MemStats.CommitLimit <= 0 || item.MemStats.Committed <= 0 {
			return 0, false
		}
		return ratioPct(float64(item.MemStats.Committed), float64(item.MemStats.CommitLimit)), true
	}); ok {
		commitPct := ratioPct(float64(worstCommit.MemStats.Committed), float64(worstCommit.MemStats.CommitLimit))
		currentCommit := latestValidCommitSample(data, worstCommit)
		currentCommitPct := ratioPct(float64(currentCommit.MemStats.Committed), float64(currentCommit.MemStats.CommitLimit))
		commitRecovered := currentCommitPct < cfg.CommitWarnPct
		commitSeverity := severityFromThreshold(commitPct, cfg.CommitHardPct, cfg.CommitWarnPct)
		if commitSeverity != "" {
			result = append(result, Finding{
				RuleID:        "meminfo-commit-pressure",
				Source:        "meminfo",
				Category:      "memory_commit",
				Severity:      commitSeverity,
				Title:         "Committed_AS 接近或超过 CommitLimit",
				Summary:       fmt.Sprintf("Committed_AS 峰值 %.1f%%，约 %.2f/%.2f GB；当前 %.1f%%。%s", commitPct, kbToGB(float64(worstCommit.MemStats.Committed)), kbToGB(float64(worstCommit.MemStats.CommitLimit)), currentCommitPct, recoveredSummarySuffix(commitRecovered)),
				Target:        "memory",
				Metric:        "committed_pct",
				Operator:      ">=",
				Threshold:     thresholdForSeverity(commitSeverity, cfg.CommitHardPct, cfg.CommitWarnPct),
				ObservedValue: commitPct,
				EvidenceRef:   fmt.Sprintf("meminfo:memory:committed_pct:%s", worstCommit.Timestamp.Format(timeLayout)),
				Time:          worstCommit.Timestamp.Format(timeLayout),
				WindowStart:   windowStart,
				WindowEnd:     windowEnd,
				Metrics: map[string]float64{
					"committed_pct":         commitPct,
					"committed_gb":          kbToGB(float64(worstCommit.MemStats.Committed)),
					"commit_limit_gb":       kbToGB(float64(worstCommit.MemStats.CommitLimit)),
					"committed_current_pct": currentCommitPct,
					"committed_recovered":   boolAsFloat(commitRecovered),
				},
				Tags: []string{"memory", "commit"},
			})
		}
	}

	worstSlab, slabTrigger, hasSlabTrigger := worstSlabTrigger(data, cfg)
	if hasSlabTrigger {
		currentSlab := latestValidSlabSample(data, worstSlab)
		currentSlabPct := ratioPct(float64(currentSlab.MemStats.Slab), float64(currentSlab.MemStats.MemTotal))
		currentUnreclaimPct := ratioPct(float64(currentSlab.MemStats.SUnreclaim), float64(currentSlab.MemStats.MemTotal))
		currentSlabGB := kbToGB(float64(currentSlab.MemStats.Slab))
		_, hasCurrentSlabTrigger := slabTriggerFor(currentSlabGB, currentSlabPct, currentUnreclaimPct, cfg)
		slabRecovered := !hasCurrentSlabTrigger
		slabGB := kbToGB(float64(worstSlab.MemStats.Slab))
		slabPct := ratioPct(float64(worstSlab.MemStats.Slab), float64(worstSlab.MemStats.MemTotal))
		unreclaimPct := ratioPct(float64(worstSlab.MemStats.SUnreclaim), float64(worstSlab.MemStats.MemTotal))
		result = append(result, Finding{
			RuleID:        "meminfo-slab",
			Source:        "meminfo",
			Category:      "memory_slab",
			Severity:      slabTrigger.severity,
			Title:         "Slab/不可回收内存偏高",
			Summary:       fmt.Sprintf("%s；Slab 峰值 %.2f GB，占总内存 %.2f%%；SUnreclaim %.2f%%；当前 Slab %.2f%%，SUnreclaim %.2f%%。%s", slabTrigger.summaryPrefix, slabGB, slabPct, unreclaimPct, currentSlabPct, currentUnreclaimPct, recoveredSummarySuffix(slabRecovered)),
			Target:        "memory",
			Metric:        slabTrigger.metric,
			Operator:      ">=",
			Threshold:     slabTrigger.threshold,
			ObservedValue: slabTrigger.observed,
			EvidenceRef:   fmt.Sprintf("meminfo:memory:%s:%s", slabTrigger.metric, worstSlab.Timestamp.Format(timeLayout)),
			Time:          worstSlab.Timestamp.Format(timeLayout),
			WindowStart:   windowStart,
			WindowEnd:     windowEnd,
			Metrics: map[string]float64{
				"slab_gb":                slabGB,
				"slab_pct":               slabPct,
				"sunreclaim_pct":         unreclaimPct,
				"sunreclaim_gb":          kbToGB(float64(worstSlab.MemStats.SUnreclaim)),
				"sreclaimable_gb":        kbToGB(float64(worstSlab.MemStats.SReclaimable)),
				"slab_current_pct":       currentSlabPct,
				"sunreclaim_current_pct": currentUnreclaimPct,
				"slab_recovered":         boolAsFloat(slabRecovered),
			},
			Tags: []string{"memory", "slab"},
		})
	}

	worstWriteback, writebackTrigger, hasWritebackTrigger := worstWritebackTrigger(data, cfg)
	if hasWritebackTrigger {
		currentWriteback := latestValidWritebackSample(data, worstWriteback)
		currentDirtyMB := kbToMB(float64(currentWriteback.MemStats.Dirty))
		currentWritebackMB := kbToMB(float64(currentWriteback.MemStats.Writeback))
		currentDirtyPct := ratioPct(float64(currentWriteback.MemStats.Dirty), float64(currentWriteback.MemStats.MemTotal))
		currentWritebackPct := ratioPct(float64(currentWriteback.MemStats.Writeback), float64(currentWriteback.MemStats.MemTotal))
		_, hasCurrentWritebackTrigger := writebackTriggerFor(currentDirtyMB, currentDirtyPct, currentWritebackMB, currentWritebackPct, cfg)
		writebackRecovered := !hasCurrentWritebackTrigger
		dirtyMB := kbToMB(float64(worstWriteback.MemStats.Dirty))
		writebackMB := kbToMB(float64(worstWriteback.MemStats.Writeback))
		dirtyPct := ratioPct(float64(worstWriteback.MemStats.Dirty), float64(worstWriteback.MemStats.MemTotal))
		writebackPct := ratioPct(float64(worstWriteback.MemStats.Writeback), float64(worstWriteback.MemStats.MemTotal))
		result = append(result, Finding{
			RuleID:        "meminfo-writeback-pressure",
			Source:        "meminfo",
			Category:      "memory_writeback",
			Severity:      writebackTrigger.severity,
			Title:         "Dirty/Writeback 回写积压",
			Summary:       fmt.Sprintf("%s；Dirty %.2f GB (%.2f%%)，Writeback %.2f GB (%.2f%%)；当前 Dirty %.1f MB，Writeback %.1f MB。%s", writebackTrigger.summaryPrefix, kbToGB(float64(worstWriteback.MemStats.Dirty)), dirtyPct, kbToGB(float64(worstWriteback.MemStats.Writeback)), writebackPct, currentDirtyMB, currentWritebackMB, recoveredSummarySuffix(writebackRecovered)),
			Target:        "memory",
			Metric:        writebackTrigger.metric,
			Operator:      ">=",
			Threshold:     writebackTrigger.threshold,
			ObservedValue: writebackTrigger.observed,
			EvidenceRef:   fmt.Sprintf("meminfo:memory:%s:%s", writebackTrigger.metric, worstWriteback.Timestamp.Format(timeLayout)),
			Time:          worstWriteback.Timestamp.Format(timeLayout),
			WindowStart:   windowStart,
			WindowEnd:     windowEnd,
			Metrics: map[string]float64{
				"dirty_mb":              dirtyMB,
				"dirty_pct":             dirtyPct,
				"writeback_mb":          writebackMB,
				"writeback_pct":         writebackPct,
				"dirty_current_mb":      currentDirtyMB,
				"dirty_current_pct":     currentDirtyPct,
				"writeback_current_mb":  currentWritebackMB,
				"writeback_current_pct": currentWritebackPct,
				"writeback_recovered":   boolAsFloat(writebackRecovered),
			},
			Tags: []string{"memory", "writeback"},
		})
	}

	sortFindings(result)
	return result
}

func filterMemInfoRange(data []meminfo.MemStatData, start, end time.Time) []meminfo.MemStatData {
	var filtered []meminfo.MemStatData
	for _, item := range data {
		if item.Timestamp.Before(start) || item.Timestamp.After(end) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func filterValidMemInfoSamples(data []meminfo.MemStatData) []meminfo.MemStatData {
	var filtered []meminfo.MemStatData
	for _, item := range data {
		if item.MemStats.MemTotal <= 0 {
			continue
		}
		if !hasAvailableMemorySignal(item.MemStats) && !hasIndependentMemoryPressureSignal(item.MemStats) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func filterAvailableMemInfoSamples(data []meminfo.MemStatData) []meminfo.MemStatData {
	var filtered []meminfo.MemStatData
	for _, item := range data {
		if hasAvailableMemorySignal(item.MemStats) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func hasAvailableMemorySignal(stats meminfo.MemStats) bool {
	return stats.MemAvailable > 0 ||
		stats.Buffers > 0 ||
		stats.Cached > 0 ||
		stats.SReclaimable > 0
}

func hasIndependentMemoryPressureSignal(stats meminfo.MemStats) bool {
	return (stats.CommitLimit > 0 && stats.Committed > 0) ||
		hasSwapUsageSignal(stats) ||
		stats.AnonPages > 0 ||
		stats.Slab > 0 ||
		stats.SUnreclaim > 0 ||
		stats.Dirty > 0 ||
		stats.Writeback > 0
}

func effectiveMemAvailableKB(stats meminfo.MemStats) float64 {
	return float64(meminfo.EffectiveMemAvailableKB(stats))
}

func availablePctForSample(stats meminfo.MemStats) (float64, bool) {
	if stats.MemTotal <= 0 || !hasAvailableMemorySignal(stats) {
		return 0, false
	}
	return ratioPct(effectiveMemAvailableKB(stats), float64(stats.MemTotal)), true
}

func minMemInfoSample(data []meminfo.MemStatData, value func(meminfo.MemStatData) float64) meminfo.MemStatData {
	if len(data) == 0 {
		return meminfo.MemStatData{}
	}
	minSample := data[0]
	minValue := value(data[0])
	for _, item := range data[1:] {
		itemValue := value(item)
		if itemValue < minValue {
			minSample = item
			minValue = itemValue
		}
	}
	return minSample
}

func maxMemInfoSample(data []meminfo.MemStatData, value func(meminfo.MemStatData) (float64, bool)) (meminfo.MemStatData, bool) {
	var maxSample meminfo.MemStatData
	maxValue := 0.0
	found := false
	for _, item := range data {
		itemValue, ok := value(item)
		if !ok {
			continue
		}
		if !found || itemValue > maxValue {
			maxSample = item
			maxValue = itemValue
			found = true
		}
	}
	return maxSample, found
}

func latestValidCommitSample(data []meminfo.MemStatData, fallback meminfo.MemStatData) meminfo.MemStatData {
	for i := len(data) - 1; i >= 0; i-- {
		stats := data[i].MemStats
		if stats.CommitLimit > 0 && stats.Committed > 0 {
			return data[i]
		}
	}
	return fallback
}

func latestValidWritebackSample(data []meminfo.MemStatData, fallback meminfo.MemStatData) meminfo.MemStatData {
	for i := len(data) - 1; i >= 0; i-- {
		stats := data[i].MemStats
		if stats.Dirty > 0 || stats.Writeback > 0 {
			return data[i]
		}
	}
	return fallback
}

func latestValidSlabSample(data []meminfo.MemStatData, fallback meminfo.MemStatData) meminfo.MemStatData {
	for i := len(data) - 1; i >= 0; i-- {
		stats := data[i].MemStats
		if stats.Slab > 0 || stats.SUnreclaim > 0 || stats.SReclaimable > 0 {
			return data[i]
		}
	}
	return fallback
}

func availabilitySeverity(availPct float64, cfg config.MeminfoConfig) Severity {
	switch {
	case availPct < cfg.AvailableSeverePct:
		return SeverityHigh
	case availPct < cfg.AvailableWarnPct:
		return SeverityHigh
	case availPct < cfg.AvailableSoftPct:
		return SeverityMedium
	default:
		return ""
	}
}

type availablePressureStats struct {
	softSamples   int
	warnSamples   int
	severeSamples int
	recovered     bool
}

func summarizeAvailablePressure(data []meminfo.MemStatData, currentAvailPct float64, cfg config.MeminfoConfig) availablePressureStats {
	var stats availablePressureStats
	for _, item := range data {
		availPct, ok := availablePctForSample(item.MemStats)
		if !ok {
			continue
		}
		if availPct < cfg.AvailableSoftPct {
			stats.softSamples++
		}
		if availPct < cfg.AvailableWarnPct {
			stats.warnSamples++
		}
		if availPct < cfg.AvailableSeverePct {
			stats.severeSamples++
		}
	}
	stats.recovered = currentAvailPct >= cfg.AvailableSoftPct
	return stats
}

func availabilitySeverityWithRecovery(availPct float64, stats availablePressureStats, cfg config.MeminfoConfig) Severity {
	severity := availabilitySeverity(availPct, cfg)
	if severity == SeverityHigh && stats.warnSamples <= 1 && stats.recovered {
		return SeverityMedium
	}
	return severity
}

func memAvailableThresholdForSeverity(severity Severity, cfg config.MeminfoConfig) float64 {
	if severity == SeverityHigh {
		return cfg.AvailableWarnPct
	}
	return cfg.AvailableSoftPct
}

func availableSummary(availPct, availKB, currentAvailPct, currentAvailKB float64, stats availablePressureStats) string {
	if stats.recovered && stats.softSamples <= 1 {
		return fmt.Sprintf("窗口内曾出现短时低水位：最低可用内存 %.1f%%，约 %.2f GB；当前已恢复至 %.1f%%，约 %.2f GB。", availPct, kbToGB(availKB), currentAvailPct, kbToGB(currentAvailKB))
	}
	return fmt.Sprintf("窗口最低可用内存 %.1f%%，约 %.2f GB；当前 %.1f%%，约 %.2f GB。", availPct, kbToGB(availKB), currentAvailPct, kbToGB(currentAvailKB))
}

type anonGrowthSegment struct {
	start           meminfo.MemStatData
	end             meminfo.MemStatData
	startIndex      int
	endIndex        int
	deltaMB         float64
	rateMB          float64
	rateMBPerMinute float64
	startMB         float64
	endMB           float64
}

func worstAnonGrowthSegment(data []meminfo.MemStatData, cfg config.MeminfoConfig) (anonGrowthSegment, bool) {
	if len(data) < 2 {
		return anonGrowthSegment{}, false
	}

	var best anonGrowthSegment
	bestStartIndex := 0
	bestEndIndex := 0
	for endIndex := 1; endIndex < len(data); endIndex++ {
		startLimit := maxInt(0, endIndex-cfg.AnonWindowPoints+1)
		minIndex := startLimit
		minAnonKB := data[startLimit].MemStats.AnonPages
		for startIndex := startLimit + 1; startIndex < endIndex; startIndex++ {
			if data[startIndex].MemStats.AnonPages < minAnonKB {
				minIndex = startIndex
				minAnonKB = data[startIndex].MemStats.AnonPages
			}
		}

		deltaMB := kbToMB(float64(data[endIndex].MemStats.AnonPages - minAnonKB))
		if deltaMB <= 0 {
			continue
		}
		rateMB := deltaMB / math.Max(1, float64(endIndex-minIndex))
		rateMBPerMinute := anonGrowthRateMBPerMinute(deltaMB, data[minIndex].Timestamp, data[endIndex].Timestamp, rateMB, cfg)
		candidate := anonGrowthSegment{
			start:           data[minIndex],
			end:             data[endIndex],
			startIndex:      minIndex,
			endIndex:        endIndex,
			deltaMB:         deltaMB,
			rateMB:          rateMB,
			rateMBPerMinute: rateMBPerMinute,
			startMB:         kbToMB(float64(data[minIndex].MemStats.AnonPages)),
			endMB:           kbToMB(float64(data[endIndex].MemStats.AnonPages)),
		}
		if !anonGrowthHasSupport(data, candidate, cfg) {
			continue
		}
		if deltaMB > best.deltaMB || (deltaMB == best.deltaMB && rateMBPerMinute > best.rateMBPerMinute) {
			bestStartIndex = minIndex
			bestEndIndex = endIndex
			best = candidate
		}
	}
	if bestEndIndex <= bestStartIndex {
		return anonGrowthSegment{}, false
	}
	return best, true
}

func anonGrowthRateMBPerMinute(deltaMB float64, start, end time.Time, fallbackRateMBPerSample float64, cfg config.MeminfoConfig) float64 {
	minutes := end.Sub(start).Minutes()
	if minutes <= 0 {
		return fallbackRateMBPerSample * (60.0 / cfg.AnonSampleSeconds)
	}
	return deltaMB / minutes
}

func anonGrowthHasSupport(data []meminfo.MemStatData, segment anonGrowthSegment, cfg config.MeminfoConfig) bool {
	if segment.endIndex-segment.startIndex >= 2 {
		return true
	}
	if anonGrowthHasMemoryPressure(segment, cfg) {
		return true
	}

	elevatedKB := segment.start.MemStats.AnonPages + int64(cfg.AnonLeakSoftMB*1024)
	for i := segment.endIndex + 1; i < len(data) && i <= segment.endIndex+2; i++ {
		if data[i].MemStats.AnonPages >= elevatedKB {
			return true
		}
	}
	return false
}

func anonGrowthHasMemoryPressure(segment anonGrowthSegment, cfg config.MeminfoConfig) bool {
	start := segment.start.MemStats
	end := segment.end.MemStats

	if hasAvailableMemorySignal(end) {
		endAvailPct := ratioPct(effectiveMemAvailableKB(end), float64(end.MemTotal))
		if endAvailPct < cfg.AvailableSoftPct {
			return true
		}
		if hasAvailableMemorySignal(start) {
			startAvailPct := ratioPct(effectiveMemAvailableKB(start), float64(start.MemTotal))
			if startAvailPct-endAvailPct >= 10 {
				return true
			}
		}
	}

	if hasSwapUsageSignal(start) && hasSwapUsageSignal(end) {
		startSwapUsed := start.SwapTotal - start.SwapFree
		endSwapUsed := end.SwapTotal - end.SwapFree
		if endSwapUsed > startSwapUsed {
			return true
		}
	}

	if end.CommitLimit > 0 {
		endCommitPct := ratioPct(float64(end.Committed), float64(end.CommitLimit))
		if endCommitPct >= cfg.CommitWarnPct {
			return true
		}
	}
	return false
}

func anonSeverity(segment anonGrowthSegment, cfg config.MeminfoConfig) Severity {
	deltaMB := segment.deltaMB
	rateMBPerMinute := segment.rateMBPerMinute
	baseSeverity := Severity("")
	switch {
	case deltaMB >= cfg.AnonLeakHardMB && rateMBPerMinute >= memAnonLeakHardRatePerMinute(cfg):
		baseSeverity = SeverityHigh
	case deltaMB >= cfg.AnonLeakSoftMB && rateMBPerMinute >= memAnonLeakSoftRatePerMinute(cfg):
		baseSeverity = SeverityMedium
	default:
		return ""
	}

	if anonGrowthHasMemoryPressure(segment, cfg) {
		return baseSeverity
	}

	deltaPct := anonGrowthDeltaPct(segment)
	peakPct := anonGrowthPeakPct(segment)
	if deltaPct >= cfg.AnonLeakHardPct || peakPct >= cfg.AnonLeakHardPct {
		return baseSeverity
	}
	if deltaPct >= cfg.AnonLeakSoftPct {
		return capSeverity(baseSeverity, SeverityMedium)
	}
	return SeverityLow
}

func memAnonLeakHardRatePerMinute(cfg config.MeminfoConfig) float64 {
	return cfg.AnonLeakHardRateMBPerSample * (60.0 / cfg.AnonSampleSeconds)
}

func memAnonLeakSoftRatePerMinute(cfg config.MeminfoConfig) float64 {
	return cfg.AnonLeakSoftRateMBPerSample * (60.0 / cfg.AnonSampleSeconds)
}

func anonGrowthDeltaPct(segment anonGrowthSegment) float64 {
	memTotalKB := float64(segment.end.MemStats.MemTotal)
	if memTotalKB <= 0 {
		return 0
	}
	return ratioPct(segment.deltaMB*1024, memTotalKB)
}

func anonGrowthPeakPct(segment anonGrowthSegment) float64 {
	memTotalKB := float64(segment.end.MemStats.MemTotal)
	if memTotalKB <= 0 {
		return 0
	}
	return ratioPct(segment.endMB*1024, memTotalKB)
}

func anonPressureSummary(hasPressure bool) string {
	if hasPressure {
		return "存在可用内存/Swap/Commit 压力佐证"
	}
	return "无可用内存/Swap/Commit 压力佐证"
}

func capSeverity(severity, max Severity) Severity {
	if severityRank(severity) < severityRank(max) {
		return max
	}
	return severity
}

func boolAsFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func recoveredSummarySuffix(recovered bool) string {
	if !recovered {
		return ""
	}
	return " 当前已恢复，按历史峰值候选线索保留。"
}

func swapThresholdForSeverity(severity Severity, cfg config.MeminfoConfig) float64 {
	if severity == SeverityHigh {
		return cfg.SwapWarnPct
	}
	return 0
}

type swapUsageStats struct {
	sample   meminfo.MemStatData
	usedKB   float64
	usedPct  float64
	growthKB float64
}

func worstSwapUsage(data []meminfo.MemStatData) (swapUsageStats, bool) {
	var best swapUsageStats
	minUsedKB := 0.0
	hasMin := false
	found := false
	for _, item := range data {
		if !hasSwapUsageSignal(item.MemStats) {
			continue
		}
		usedKB := float64(item.MemStats.SwapTotal - item.MemStats.SwapFree)
		if usedKB < 0 {
			usedKB = 0
		}
		if !hasMin || usedKB < minUsedKB {
			minUsedKB = usedKB
			hasMin = true
		}
		usedPct := ratioPct(usedKB, float64(item.MemStats.SwapTotal))
		if !found || usedPct > best.usedPct {
			best = swapUsageStats{
				sample:   item,
				usedKB:   usedKB,
				usedPct:  usedPct,
				growthKB: usedKB - minUsedKB,
			}
			found = true
		}
	}
	return best, found
}

func latestSwapUsage(data []meminfo.MemStatData, fallbackUsedKB, fallbackUsedPct float64) (float64, float64) {
	for i := len(data) - 1; i >= 0; i-- {
		stats := data[i].MemStats
		if !hasSwapUsageSignal(stats) {
			continue
		}
		usedKB := float64(stats.SwapTotal - stats.SwapFree)
		if usedKB < 0 {
			usedKB = 0
		}
		return usedKB, ratioPct(usedKB, float64(stats.SwapTotal))
	}
	return fallbackUsedKB, fallbackUsedPct
}

func hasSwapUsageSignal(stats meminfo.MemStats) bool {
	return stats.SwapTotal > 0 && (stats.SwapFree > 0 || stats.SwapFreePresent)
}

type slabTrigger struct {
	severity      Severity
	metric        string
	threshold     float64
	observed      float64
	summaryPrefix string
}

func worstSlabTrigger(data []meminfo.MemStatData, cfg config.MeminfoConfig) (meminfo.MemStatData, slabTrigger, bool) {
	var bestSample meminfo.MemStatData
	var bestTrigger slabTrigger
	found := false
	for _, item := range data {
		slabGB := kbToGB(float64(item.MemStats.Slab))
		slabPct := ratioPct(float64(item.MemStats.Slab), float64(item.MemStats.MemTotal))
		unreclaimPct := ratioPct(float64(item.MemStats.SUnreclaim), float64(item.MemStats.MemTotal))
		trigger, ok := slabTriggerFor(slabGB, slabPct, unreclaimPct, cfg)
		if !ok {
			continue
		}
		if !found || slabTriggerRank(trigger) > slabTriggerRank(bestTrigger) {
			bestSample = item
			bestTrigger = trigger
			found = true
		}
	}
	return bestSample, bestTrigger, found
}

func slabTriggerRank(trigger slabTrigger) float64 {
	severityRank := 1.0
	if trigger.severity == SeverityHigh {
		severityRank = 2.0
	}
	return severityRank*1000 + trigger.observed/trigger.threshold
}

func slabTriggerFor(slabGB, slabPct, unreclaimPct float64, cfg config.MeminfoConfig) (slabTrigger, bool) {
	switch {
	case unreclaimPct >= cfg.UnreclaimWarnPct:
		return slabTrigger{
			severity:      SeverityHigh,
			metric:        "sunreclaim_pct",
			threshold:     cfg.UnreclaimWarnPct,
			observed:      unreclaimPct,
			summaryPrefix: "触发原因：不可回收 Slab 占比偏高",
		}, true
	case slabGB*1024 >= cfg.SlabWarnMB && slabPct >= cfg.SlabWarnPct:
		return slabTrigger{
			severity:      SeverityHigh,
			metric:        "slab_pct",
			threshold:     cfg.SlabWarnPct,
			observed:      slabPct,
			summaryPrefix: "触发原因：Slab 总量和占比偏高",
		}, true
	case unreclaimPct >= cfg.UnreclaimSoftPct:
		return slabTrigger{
			severity:      SeverityMedium,
			metric:        "sunreclaim_pct",
			threshold:     cfg.UnreclaimSoftPct,
			observed:      unreclaimPct,
			summaryPrefix: "触发原因：不可回收 Slab 占比达到观察阈值",
		}, true
	case slabGB*1024 >= cfg.SlabSoftMB && slabPct >= cfg.SlabSoftPct:
		return slabTrigger{
			severity:      SeverityMedium,
			metric:        "slab_gb",
			threshold:     cfg.SlabSoftMB / 1024,
			observed:      slabGB,
			summaryPrefix: "触发原因：Slab 绝对值偏高",
		}, true
	default:
		return slabTrigger{}, false
	}
}

type writebackTrigger struct {
	severity      Severity
	metric        string
	threshold     float64
	observed      float64
	summaryPrefix string
}

func worstWritebackTrigger(data []meminfo.MemStatData, cfg config.MeminfoConfig) (meminfo.MemStatData, writebackTrigger, bool) {
	var bestSample meminfo.MemStatData
	var bestTrigger writebackTrigger
	found := false
	for _, item := range data {
		dirtyMB := kbToMB(float64(item.MemStats.Dirty))
		writebackMB := kbToMB(float64(item.MemStats.Writeback))
		dirtyPct := ratioPct(float64(item.MemStats.Dirty), float64(item.MemStats.MemTotal))
		writebackPct := ratioPct(float64(item.MemStats.Writeback), float64(item.MemStats.MemTotal))
		trigger, ok := writebackTriggerFor(dirtyMB, dirtyPct, writebackMB, writebackPct, cfg)
		if !ok {
			continue
		}
		if !found || writebackTriggerRank(trigger) > writebackTriggerRank(bestTrigger) {
			bestSample = item
			bestTrigger = trigger
			found = true
		}
	}
	return bestSample, bestTrigger, found
}

func writebackTriggerRank(trigger writebackTrigger) float64 {
	severityRank := 1.0
	if trigger.severity == SeverityHigh {
		severityRank = 2.0
	}
	return severityRank*1000 + trigger.observed/trigger.threshold
}

func writebackTriggerFor(dirtyMB, dirtyPct, writebackMB, writebackPct float64, cfg config.MeminfoConfig) (writebackTrigger, bool) {
	hasDirtyBacklog := dirtyPct >= cfg.DirtySoftPct || (dirtyMB >= cfg.WritebackSoftMB && writebackPct >= cfg.WritebackSoftPct)
	if !hasDirtyBacklog || writebackMB <= 0 {
		return writebackTrigger{}, false
	}

	switch {
	case writebackPct >= cfg.WritebackHardPct || (writebackMB >= cfg.WritebackHardMB && writebackPct >= cfg.WritebackSoftPct):
		return writebackTrigger{
			severity:      SeverityHigh,
			metric:        "writeback_pct",
			threshold:     cfg.WritebackHardPct,
			observed:      writebackPct,
			summaryPrefix: "触发原因：Writeback 积压达到硬阈值",
		}, true
	case dirtyPct >= cfg.DirtyHardPct && writebackPct >= cfg.WritebackSoftPct:
		return writebackTrigger{
			severity:      SeverityHigh,
			metric:        "dirty_pct",
			threshold:     cfg.DirtyHardPct,
			observed:      dirtyPct,
			summaryPrefix: "触发原因：Dirty 高且 Writeback 正在积压",
		}, true
	case writebackPct >= cfg.WritebackSoftPct || (writebackMB >= cfg.WritebackSoftMB && dirtyPct >= cfg.DirtySoftPct):
		return writebackTrigger{
			severity:      SeverityMedium,
			metric:        "writeback_pct",
			threshold:     cfg.WritebackSoftPct,
			observed:      writebackPct,
			summaryPrefix: "触发原因：Writeback 达到观察阈值",
		}, true
	default:
		return writebackTrigger{}, false
	}
}

func ratioPct(num, den float64) float64 {
	if den == 0 {
		return 0
	}
	return num / den * 100
}

func kbToGB(kb float64) float64 {
	return kb / 1024 / 1024
}

func kbToMB(kb float64) float64 {
	return kb / 1024
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
