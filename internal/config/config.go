package config

import "fmt"

// Config is the future application-level configuration entrypoint.
// Phase P0 only establishes the shape; legacy processor thresholds stay in place.
type Config struct {
	General GeneralConfig
	Iostat  IostatConfig
	Meminfo MeminfoConfig
	Top     TopConfig
	AI      AIConfig
}

// GeneralConfig contains cross-module defaults shared by rule and AI entrypoints.
type GeneralConfig struct {
	DefaultOutputFormat string
	TimeZone            string
}

// IostatConfig reserves the iostat module switch before threshold migration.
type IostatConfig struct {
	Enabled                bool
	QueueHard              float64
	QueueSoft              float64
	CPUWaitHardPct         float64
	CPUWaitSoftPct         float64
	LatencyIOPSSoft        float64
	UtilHardPct            float64
	UtilSoftPct            float64
	UtilMinSamples         int
	NVMeLatencyHardMS      float64
	NVMeLatencySoftMS      float64
	DefaultLatencyHardMS   float64
	DefaultLatencySoftMS   float64
	LatencyZScoreThreshold float64
	LatencyMADThreshold    float64
	LatencyIQRMultiplier   float64
}

// MeminfoConfig reserves the meminfo module switch before threshold migration.
type MeminfoConfig struct {
	Enabled                     bool
	AvailableWarnPct            float64
	AvailableSoftPct            float64
	AvailableSeverePct          float64
	AvailableSevereMB           float64
	AvailableWarnMB             float64
	AnonLeakHardMB              float64
	AnonLeakSoftMB              float64
	AnonLeakDeltaMB             float64
	AnonLeakHardRateMBPerSample float64
	AnonLeakSoftRateMBPerSample float64
	AnonSampleSeconds           float64
	AnonLeakHardPct             float64
	AnonLeakSoftPct             float64
	SwapWarnPct                 float64
	SwapSeverePct               float64
	SwapGrowthSoftMB            float64
	SwapBurstPct                float64
	CommitWarnPct               float64
	CommitHardPct               float64
	SlabWarnMB                  float64
	SlabSoftMB                  float64
	SlabWarnPct                 float64
	SlabSoftPct                 float64
	UnreclaimWarnPct            float64
	UnreclaimSoftPct            float64
	DirtySoftPct                float64
	DirtyHardPct                float64
	WritebackSoftPct            float64
	WritebackHardPct            float64
	WritebackSoftMB             float64
	WritebackHardMB             float64
	AnonWindowPoints            int
	ShortWindowPoints           int
	LongWindowPoints            int
	SlopeBurstMBPerSample       float64
	SlabSlopeBurstMBPerSample   float64
	KernelAbsWarnMB             float64
	KernelDeltaPctWarn          float64
	VPatternDropMB              float64
	VPatternRecoverMB           float64
	SuddenChangePct             float64
	SuddenChangeMinMB           float64
}

// TopConfig reserves the top module switch before threshold migration.
type TopConfig struct {
	Enabled              bool
	CPUIdleHardPct       float64
	CPUIdleSoftPct       float64
	CPUWaitHardPct       float64
	CPUWaitSoftPct       float64
	CPUStealHardPct      float64
	CPUStealSoftPct      float64
	LoadHighSoft         float64
	LoadHighHard         float64
	LoadPerCPUSoft       float64
	LoadPerCPUHard       float64
	RunnablePerCPU       float64
	RunnableSoft         int
	CPUIdleHighPct       float64
	HighCPUProcessPct    float64
	HighMemoryProcessPct float64
}

// AIConfig contains stable AI defaults only; runtime paths stay in CLI options for now.
type AIConfig struct {
	Enabled             bool
	DefaultOutputFormat string
	TimeoutSeconds      int
}

// Validate checks only the stable P0 config contract.
func (c Config) Validate() error {
	if !isSupportedOutputFormat(c.General.DefaultOutputFormat) {
		return fmt.Errorf("general.default_output_format is unsupported: %s", c.General.DefaultOutputFormat)
	}
	if c.General.TimeZone == "" {
		return fmt.Errorf("general.time_zone is required")
	}
	if !c.Iostat.Enabled && !c.Meminfo.Enabled && !c.Top.Enabled {
		return fmt.Errorf("at least one module must be enabled")
	}
	if !isSupportedOutputFormat(c.AI.DefaultOutputFormat) {
		return fmt.Errorf("ai.default_output_format is unsupported: %s", c.AI.DefaultOutputFormat)
	}
	if c.AI.TimeoutSeconds < 0 {
		return fmt.Errorf("ai.timeout_seconds must be non-negative")
	}
	if err := c.Iostat.Validate(); err != nil {
		return err
	}
	if err := c.Meminfo.Validate(); err != nil {
		return err
	}
	if err := c.Top.Validate(); err != nil {
		return err
	}
	return nil
}

func (c IostatConfig) WithDefaults() IostatConfig {
	if c == (IostatConfig{}) {
		return Default().Iostat
	}
	return c
}

func (c MeminfoConfig) WithDefaults() MeminfoConfig {
	if c == (MeminfoConfig{}) {
		return Default().Meminfo
	}
	return c
}

func (c TopConfig) WithDefaults() TopConfig {
	if c == (TopConfig{}) {
		return Default().Top
	}
	return c
}

func (c IostatConfig) Validate() error {
	c = c.WithDefaults()
	if err := validateUpperPair("iostat.queue_hard", c.QueueHard, "iostat.queue_soft", c.QueueSoft); err != nil {
		return err
	}
	if err := validateUpperPair("iostat.cpu_wait_hard_pct", c.CPUWaitHardPct, "iostat.cpu_wait_soft_pct", c.CPUWaitSoftPct); err != nil {
		return err
	}
	if err := validateUpperPair("iostat.util_hard_pct", c.UtilHardPct, "iostat.util_soft_pct", c.UtilSoftPct); err != nil {
		return err
	}
	if err := validateUpperPair("iostat.nvme_latency_hard_ms", c.NVMeLatencyHardMS, "iostat.nvme_latency_soft_ms", c.NVMeLatencySoftMS); err != nil {
		return err
	}
	if err := validateUpperPair("iostat.default_latency_hard_ms", c.DefaultLatencyHardMS, "iostat.default_latency_soft_ms", c.DefaultLatencySoftMS); err != nil {
		return err
	}
	for key, value := range map[string]float64{
		"iostat.cpu_wait_hard_pct": c.CPUWaitHardPct, "iostat.cpu_wait_soft_pct": c.CPUWaitSoftPct,
		"iostat.util_hard_pct": c.UtilHardPct, "iostat.util_soft_pct": c.UtilSoftPct,
	} {
		if err := validatePct(key, value); err != nil {
			return err
		}
	}
	for key, value := range map[string]float64{
		"iostat.queue_hard": c.QueueHard, "iostat.queue_soft": c.QueueSoft,
		"iostat.latency_iops_soft":    c.LatencyIOPSSoft,
		"iostat.nvme_latency_hard_ms": c.NVMeLatencyHardMS, "iostat.nvme_latency_soft_ms": c.NVMeLatencySoftMS,
		"iostat.default_latency_hard_ms": c.DefaultLatencyHardMS, "iostat.default_latency_soft_ms": c.DefaultLatencySoftMS,
		"iostat.latency_z_score_threshold": c.LatencyZScoreThreshold,
		"iostat.latency_mad_threshold":     c.LatencyMADThreshold,
		"iostat.latency_iqr_multiplier":    c.LatencyIQRMultiplier,
	} {
		if err := validatePositive(key, value); err != nil {
			return err
		}
	}
	if c.UtilMinSamples <= 0 {
		return fmt.Errorf("iostat.util_min_samples must be positive: %d", c.UtilMinSamples)
	}
	return nil
}

func (c MeminfoConfig) Validate() error {
	c = c.WithDefaults()
	if !(c.AvailableSeverePct < c.AvailableWarnPct && c.AvailableWarnPct < c.AvailableSoftPct) {
		return fmt.Errorf("meminfo.available_severe_pct=%v must be < available_warn_pct=%v < available_soft_pct=%v", c.AvailableSeverePct, c.AvailableWarnPct, c.AvailableSoftPct)
	}
	if !(c.AvailableSevereMB < c.AvailableWarnMB) {
		return fmt.Errorf("meminfo.available_severe_mb=%v must be < available_warn_mb=%v", c.AvailableSevereMB, c.AvailableWarnMB)
	}
	for key, value := range map[string]float64{
		"meminfo.available_warn_pct": c.AvailableWarnPct, "meminfo.available_soft_pct": c.AvailableSoftPct,
		"meminfo.available_severe_pct": c.AvailableSeverePct, "meminfo.anon_leak_hard_pct": c.AnonLeakHardPct,
		"meminfo.anon_leak_soft_pct": c.AnonLeakSoftPct, "meminfo.swap_warn_pct": c.SwapWarnPct,
		"meminfo.swap_severe_pct": c.SwapSeverePct, "meminfo.commit_warn_pct": c.CommitWarnPct,
		"meminfo.commit_hard_pct": c.CommitHardPct, "meminfo.slab_warn_pct": c.SlabWarnPct,
		"meminfo.slab_soft_pct": c.SlabSoftPct, "meminfo.unreclaim_warn_pct": c.UnreclaimWarnPct,
		"meminfo.unreclaim_soft_pct": c.UnreclaimSoftPct, "meminfo.dirty_soft_pct": c.DirtySoftPct,
		"meminfo.dirty_hard_pct": c.DirtyHardPct, "meminfo.writeback_soft_pct": c.WritebackSoftPct,
		"meminfo.writeback_hard_pct": c.WritebackHardPct, "meminfo.swap_burst_pct": c.SwapBurstPct,
		"meminfo.kernel_delta_pct_warn": c.KernelDeltaPctWarn, "meminfo.sudden_change_pct": c.SuddenChangePct,
	} {
		if err := validatePct(key, value); err != nil {
			return err
		}
	}
	if err := validateUpperPair("meminfo.commit_hard_pct", c.CommitHardPct, "meminfo.commit_warn_pct", c.CommitWarnPct); err != nil {
		return err
	}
	if err := validateUpperPair("meminfo.dirty_hard_pct", c.DirtyHardPct, "meminfo.dirty_soft_pct", c.DirtySoftPct); err != nil {
		return err
	}
	if err := validateUpperPair("meminfo.writeback_hard_pct", c.WritebackHardPct, "meminfo.writeback_soft_pct", c.WritebackSoftPct); err != nil {
		return err
	}
	for key, value := range map[string]float64{
		"meminfo.available_severe_mb": c.AvailableSevereMB, "meminfo.available_warn_mb": c.AvailableWarnMB,
		"meminfo.anon_leak_hard_mb": c.AnonLeakHardMB, "meminfo.anon_leak_soft_mb": c.AnonLeakSoftMB,
		"meminfo.anon_leak_delta_mb": c.AnonLeakDeltaMB, "meminfo.anon_leak_hard_rate_mb_per_sample": c.AnonLeakHardRateMBPerSample,
		"meminfo.anon_leak_soft_rate_mb_per_sample": c.AnonLeakSoftRateMBPerSample, "meminfo.anon_sample_seconds": c.AnonSampleSeconds,
		"meminfo.swap_growth_soft_mb": c.SwapGrowthSoftMB, "meminfo.slab_warn_mb": c.SlabWarnMB,
		"meminfo.slab_soft_mb": c.SlabSoftMB, "meminfo.writeback_soft_mb": c.WritebackSoftMB,
		"meminfo.writeback_hard_mb": c.WritebackHardMB, "meminfo.slope_burst_mb_per_sample": c.SlopeBurstMBPerSample,
		"meminfo.slab_slope_burst_mb_per_sample": c.SlabSlopeBurstMBPerSample, "meminfo.kernel_abs_warn_mb": c.KernelAbsWarnMB,
		"meminfo.v_pattern_drop_mb": c.VPatternDropMB, "meminfo.v_pattern_recover_mb": c.VPatternRecoverMB,
		"meminfo.sudden_change_min_mb": c.SuddenChangeMinMB,
	} {
		if err := validatePositive(key, value); err != nil {
			return err
		}
	}
	for key, value := range map[string]int{
		"meminfo.anon_window_points": c.AnonWindowPoints, "meminfo.short_window_points": c.ShortWindowPoints,
		"meminfo.long_window_points": c.LongWindowPoints,
	} {
		if value <= 0 {
			return fmt.Errorf("%s must be positive: %d", key, value)
		}
	}
	if c.ShortWindowPoints > c.LongWindowPoints {
		return fmt.Errorf("meminfo.short_window_points=%d must be <= meminfo.long_window_points=%d", c.ShortWindowPoints, c.LongWindowPoints)
	}
	return nil
}

func (c TopConfig) Validate() error {
	c = c.WithDefaults()
	if err := validateLowerPair("top.cpu_idle_hard_pct", c.CPUIdleHardPct, "top.cpu_idle_soft_pct", c.CPUIdleSoftPct); err != nil {
		return err
	}
	if err := validateUpperPair("top.cpu_wait_hard_pct", c.CPUWaitHardPct, "top.cpu_wait_soft_pct", c.CPUWaitSoftPct); err != nil {
		return err
	}
	if err := validateUpperPair("top.cpu_steal_hard_pct", c.CPUStealHardPct, "top.cpu_steal_soft_pct", c.CPUStealSoftPct); err != nil {
		return err
	}
	if err := validateUpperPair("top.load_high_hard", c.LoadHighHard, "top.load_high_soft", c.LoadHighSoft); err != nil {
		return err
	}
	if err := validateUpperPair("top.load_per_cpu_hard", c.LoadPerCPUHard, "top.load_per_cpu_soft", c.LoadPerCPUSoft); err != nil {
		return err
	}
	for key, value := range map[string]float64{
		"top.cpu_idle_hard_pct": c.CPUIdleHardPct, "top.cpu_idle_soft_pct": c.CPUIdleSoftPct,
		"top.cpu_wait_hard_pct": c.CPUWaitHardPct, "top.cpu_wait_soft_pct": c.CPUWaitSoftPct,
		"top.cpu_steal_hard_pct": c.CPUStealHardPct, "top.cpu_steal_soft_pct": c.CPUStealSoftPct,
		"top.cpu_idle_high_pct": c.CPUIdleHighPct, "top.high_cpu_process_pct": c.HighCPUProcessPct,
		"top.high_memory_process_pct": c.HighMemoryProcessPct,
	} {
		if err := validatePct(key, value); err != nil {
			return err
		}
	}
	for key, value := range map[string]float64{
		"top.load_high_soft": c.LoadHighSoft, "top.load_high_hard": c.LoadHighHard,
		"top.load_per_cpu_soft": c.LoadPerCPUSoft, "top.load_per_cpu_hard": c.LoadPerCPUHard,
		"top.runnable_per_cpu": c.RunnablePerCPU,
	} {
		if err := validatePositive(key, value); err != nil {
			return err
		}
	}
	if c.RunnableSoft <= 0 {
		return fmt.Errorf("top.runnable_soft must be positive: %d", c.RunnableSoft)
	}
	return nil
}

func validatePct(key string, value float64) error {
	if value < 0 || value > 100 {
		return fmt.Errorf("%s must be between 0 and 100: %v", key, value)
	}
	return nil
}

func validatePositive(key string, value float64) error {
	if value <= 0 {
		return fmt.Errorf("%s must be positive: %v", key, value)
	}
	return nil
}

func validateUpperPair(hardKey string, hard float64, softKey string, soft float64) error {
	if hard < soft {
		return fmt.Errorf("%s=%v must be >= %s=%v", hardKey, hard, softKey, soft)
	}
	return nil
}

func validateLowerPair(hardKey string, hard float64, softKey string, soft float64) error {
	if hard > soft {
		return fmt.Errorf("%s=%v must be <= %s=%v", hardKey, hard, softKey, soft)
	}
	return nil
}

// isSupportedOutputFormat deliberately mirrors the current CLI surface.
// Keep this list in sync with main.go and cmd/oswbb-analyse-ai/main.go.
func isSupportedOutputFormat(format string) bool {
	switch format {
	case "report", "csv", "json", "ml", "html":
		return true
	default:
		return false
	}
}
