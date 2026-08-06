package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadFile loads a partial TOML config over Default().
func LoadFile(path string) (Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		return cfg, cfg.Validate()
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	section := ""
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := stripComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if !knownSection(section) {
				return Config{}, fmt.Errorf("config line %d: unknown section %q", lineNo, section)
			}
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("config line %d: expected key = value", lineNo)
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)
		if section == "" {
			return Config{}, fmt.Errorf("config line %d: key %q must be inside a section", lineNo, key)
		}
		fullKey := section + "." + key
		if err := setConfigValue(&cfg, fullKey, raw); err != nil {
			return Config{}, fmt.Errorf("config line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func knownSection(section string) bool {
	switch section {
	case "general", "iostat", "meminfo", "top", "ai":
		return true
	default:
		return false
	}
}

func stripComment(line string) string {
	inString := false
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && inString {
			escaped = true
			continue
		}
		if r == '"' {
			inString = !inString
			continue
		}
		if r == '#' && !inString {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func setConfigValue(cfg *Config, key, raw string) error {
	switch key {
	case "general.default_output_format":
		return parseString(raw, key, &cfg.General.DefaultOutputFormat)
	case "general.time_zone":
		return parseString(raw, key, &cfg.General.TimeZone)

	case "iostat.enabled":
		return parseBool(raw, key, &cfg.Iostat.Enabled)
	case "iostat.queue_hard":
		return parseFloat(raw, key, &cfg.Iostat.QueueHard)
	case "iostat.queue_soft":
		return parseFloat(raw, key, &cfg.Iostat.QueueSoft)
	case "iostat.cpu_wait_hard_pct":
		return parseFloat(raw, key, &cfg.Iostat.CPUWaitHardPct)
	case "iostat.cpu_wait_soft_pct":
		return parseFloat(raw, key, &cfg.Iostat.CPUWaitSoftPct)
	case "iostat.latency_iops_soft":
		return parseFloat(raw, key, &cfg.Iostat.LatencyIOPSSoft)
	case "iostat.util_hard_pct":
		return parseFloat(raw, key, &cfg.Iostat.UtilHardPct)
	case "iostat.util_soft_pct":
		return parseFloat(raw, key, &cfg.Iostat.UtilSoftPct)
	case "iostat.util_min_samples":
		return parseInt(raw, key, &cfg.Iostat.UtilMinSamples)
	case "iostat.nvme_latency_hard_ms":
		return parseFloat(raw, key, &cfg.Iostat.NVMeLatencyHardMS)
	case "iostat.nvme_latency_soft_ms":
		return parseFloat(raw, key, &cfg.Iostat.NVMeLatencySoftMS)
	case "iostat.default_latency_hard_ms":
		return parseFloat(raw, key, &cfg.Iostat.DefaultLatencyHardMS)
	case "iostat.default_latency_soft_ms":
		return parseFloat(raw, key, &cfg.Iostat.DefaultLatencySoftMS)
	case "iostat.latency_z_score_threshold":
		return parseFloat(raw, key, &cfg.Iostat.LatencyZScoreThreshold)
	case "iostat.latency_mad_threshold":
		return parseFloat(raw, key, &cfg.Iostat.LatencyMADThreshold)
	case "iostat.latency_iqr_multiplier":
		return parseFloat(raw, key, &cfg.Iostat.LatencyIQRMultiplier)

	case "meminfo.enabled":
		return parseBool(raw, key, &cfg.Meminfo.Enabled)
	case "meminfo.available_warn_pct":
		return parseFloat(raw, key, &cfg.Meminfo.AvailableWarnPct)
	case "meminfo.available_soft_pct":
		return parseFloat(raw, key, &cfg.Meminfo.AvailableSoftPct)
	case "meminfo.available_severe_pct":
		return parseFloat(raw, key, &cfg.Meminfo.AvailableSeverePct)
	case "meminfo.available_severe_mb":
		return parseFloat(raw, key, &cfg.Meminfo.AvailableSevereMB)
	case "meminfo.available_warn_mb":
		return parseFloat(raw, key, &cfg.Meminfo.AvailableWarnMB)
	case "meminfo.anon_leak_hard_mb":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakHardMB)
	case "meminfo.anon_leak_soft_mb":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakSoftMB)
	case "meminfo.anon_leak_delta_mb":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakDeltaMB)
	case "meminfo.anon_leak_hard_rate_mb_per_sample":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakHardRateMBPerSample)
	case "meminfo.anon_leak_soft_rate_mb_per_sample":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakSoftRateMBPerSample)
	case "meminfo.anon_sample_seconds":
		return parseFloat(raw, key, &cfg.Meminfo.AnonSampleSeconds)
	case "meminfo.anon_leak_hard_pct":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakHardPct)
	case "meminfo.anon_leak_soft_pct":
		return parseFloat(raw, key, &cfg.Meminfo.AnonLeakSoftPct)
	case "meminfo.swap_warn_pct":
		return parseFloat(raw, key, &cfg.Meminfo.SwapWarnPct)
	case "meminfo.swap_severe_pct":
		return parseFloat(raw, key, &cfg.Meminfo.SwapSeverePct)
	case "meminfo.swap_growth_soft_mb":
		return parseFloat(raw, key, &cfg.Meminfo.SwapGrowthSoftMB)
	case "meminfo.swap_burst_pct":
		return parseFloat(raw, key, &cfg.Meminfo.SwapBurstPct)
	case "meminfo.commit_warn_pct":
		return parseFloat(raw, key, &cfg.Meminfo.CommitWarnPct)
	case "meminfo.commit_hard_pct":
		return parseFloat(raw, key, &cfg.Meminfo.CommitHardPct)
	case "meminfo.slab_warn_mb":
		return parseFloat(raw, key, &cfg.Meminfo.SlabWarnMB)
	case "meminfo.slab_soft_mb":
		return parseFloat(raw, key, &cfg.Meminfo.SlabSoftMB)
	case "meminfo.slab_warn_pct":
		return parseFloat(raw, key, &cfg.Meminfo.SlabWarnPct)
	case "meminfo.slab_soft_pct":
		return parseFloat(raw, key, &cfg.Meminfo.SlabSoftPct)
	case "meminfo.unreclaim_warn_pct":
		return parseFloat(raw, key, &cfg.Meminfo.UnreclaimWarnPct)
	case "meminfo.unreclaim_soft_pct":
		return parseFloat(raw, key, &cfg.Meminfo.UnreclaimSoftPct)
	case "meminfo.dirty_soft_pct":
		return parseFloat(raw, key, &cfg.Meminfo.DirtySoftPct)
	case "meminfo.dirty_hard_pct":
		return parseFloat(raw, key, &cfg.Meminfo.DirtyHardPct)
	case "meminfo.writeback_soft_pct":
		return parseFloat(raw, key, &cfg.Meminfo.WritebackSoftPct)
	case "meminfo.writeback_hard_pct":
		return parseFloat(raw, key, &cfg.Meminfo.WritebackHardPct)
	case "meminfo.writeback_soft_mb":
		return parseFloat(raw, key, &cfg.Meminfo.WritebackSoftMB)
	case "meminfo.writeback_hard_mb":
		return parseFloat(raw, key, &cfg.Meminfo.WritebackHardMB)
	case "meminfo.anon_window_points":
		return parseInt(raw, key, &cfg.Meminfo.AnonWindowPoints)
	case "meminfo.short_window_points":
		return parseInt(raw, key, &cfg.Meminfo.ShortWindowPoints)
	case "meminfo.long_window_points":
		return parseInt(raw, key, &cfg.Meminfo.LongWindowPoints)
	case "meminfo.slope_burst_mb_per_sample":
		return parseFloat(raw, key, &cfg.Meminfo.SlopeBurstMBPerSample)
	case "meminfo.slab_slope_burst_mb_per_sample":
		return parseFloat(raw, key, &cfg.Meminfo.SlabSlopeBurstMBPerSample)
	case "meminfo.kernel_abs_warn_mb":
		return parseFloat(raw, key, &cfg.Meminfo.KernelAbsWarnMB)
	case "meminfo.kernel_delta_pct_warn":
		return parseFloat(raw, key, &cfg.Meminfo.KernelDeltaPctWarn)
	case "meminfo.v_pattern_drop_mb":
		return parseFloat(raw, key, &cfg.Meminfo.VPatternDropMB)
	case "meminfo.v_pattern_recover_mb":
		return parseFloat(raw, key, &cfg.Meminfo.VPatternRecoverMB)
	case "meminfo.sudden_change_pct":
		return parseFloat(raw, key, &cfg.Meminfo.SuddenChangePct)
	case "meminfo.sudden_change_min_mb":
		return parseFloat(raw, key, &cfg.Meminfo.SuddenChangeMinMB)

	case "top.enabled":
		return parseBool(raw, key, &cfg.Top.Enabled)
	case "top.cpu_idle_hard_pct":
		return parseFloat(raw, key, &cfg.Top.CPUIdleHardPct)
	case "top.cpu_idle_soft_pct":
		return parseFloat(raw, key, &cfg.Top.CPUIdleSoftPct)
	case "top.cpu_wait_hard_pct":
		return parseFloat(raw, key, &cfg.Top.CPUWaitHardPct)
	case "top.cpu_wait_soft_pct":
		return parseFloat(raw, key, &cfg.Top.CPUWaitSoftPct)
	case "top.cpu_steal_hard_pct":
		return parseFloat(raw, key, &cfg.Top.CPUStealHardPct)
	case "top.cpu_steal_soft_pct":
		return parseFloat(raw, key, &cfg.Top.CPUStealSoftPct)
	case "top.load_high_soft":
		return parseFloat(raw, key, &cfg.Top.LoadHighSoft)
	case "top.load_high_hard":
		return parseFloat(raw, key, &cfg.Top.LoadHighHard)
	case "top.load_per_cpu_soft":
		return parseFloat(raw, key, &cfg.Top.LoadPerCPUSoft)
	case "top.load_per_cpu_hard":
		return parseFloat(raw, key, &cfg.Top.LoadPerCPUHard)
	case "top.runnable_per_cpu":
		return parseFloat(raw, key, &cfg.Top.RunnablePerCPU)
	case "top.runnable_soft":
		return parseInt(raw, key, &cfg.Top.RunnableSoft)
	case "top.cpu_idle_high_pct":
		return parseFloat(raw, key, &cfg.Top.CPUIdleHighPct)
	case "top.high_cpu_process_pct":
		return parseFloat(raw, key, &cfg.Top.HighCPUProcessPct)
	case "top.high_memory_process_pct":
		return parseFloat(raw, key, &cfg.Top.HighMemoryProcessPct)

	case "ai.enabled":
		return parseBool(raw, key, &cfg.AI.Enabled)
	case "ai.default_output_format":
		return parseString(raw, key, &cfg.AI.DefaultOutputFormat)
	case "ai.timeout_seconds":
		return parseInt(raw, key, &cfg.AI.TimeoutSeconds)
	default:
		return fmt.Errorf("unknown config key %s", key)
	}
}

func parseString(raw, key string, dst *string) error {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return fmt.Errorf("%s must be a quoted string: %s", key, raw)
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return fmt.Errorf("%s has invalid string value %s: %w", key, raw, err)
	}
	*dst = value
	return nil
}

func parseBool(raw, key string, dst *bool) error {
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("%s has invalid bool value %s", key, raw)
	}
	*dst = value
	return nil
}

func parseFloat(raw, key string, dst *float64) error {
	if strings.HasPrefix(raw, "\"") {
		return fmt.Errorf("%s must be numeric: %s", key, raw)
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fmt.Errorf("%s has invalid numeric value %s", key, raw)
	}
	*dst = value
	return nil
}

func parseInt(raw, key string, dst *int) error {
	if strings.HasPrefix(raw, "\"") {
		return fmt.Errorf("%s must be integer: %s", key, raw)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("%s has invalid integer value %s", key, raw)
	}
	*dst = value
	return nil
}
