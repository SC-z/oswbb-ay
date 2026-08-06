package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultThresholdsMatchLegacyValues(t *testing.T) {
	cfg := Default()

	if cfg.Iostat.CPUWaitSoftPct != 10 || cfg.Iostat.CPUWaitHardPct != 20 ||
		cfg.Iostat.QueueSoft != 0.3 || cfg.Iostat.QueueHard != 1.0 ||
		cfg.Iostat.NVMeLatencyHardMS != 8 || cfg.Iostat.DefaultLatencyHardMS != 50 {
		t.Fatalf("iostat defaults changed: %+v", cfg.Iostat)
	}
	if cfg.Meminfo.AvailableWarnPct != 20 || cfg.Meminfo.AvailableSoftPct != 30 ||
		cfg.Meminfo.AvailableSeverePct != 10 || cfg.Meminfo.AnonWindowPoints != 36 ||
		cfg.Meminfo.ShortWindowPoints != 36 || cfg.Meminfo.LongWindowPoints != 720 {
		t.Fatalf("meminfo defaults changed: %+v", cfg.Meminfo)
	}
	if cfg.Top.CPUIdleHardPct != 10 || cfg.Top.CPUIdleSoftPct != 20 ||
		cfg.Top.CPUWaitHardPct != 20 || cfg.Top.LoadPerCPUSoft != 0.70 ||
		cfg.Top.HighCPUProcessPct != 50 {
		t.Fatalf("top defaults changed: %+v", cfg.Top)
	}
}

func TestLoadConfigPartialOverrideKeepsDefaults(t *testing.T) {
	path := writeConfig(t, `
[iostat]
cpu_wait_soft_pct = 12

[meminfo]
available_warn_pct = 25

[top]
load_per_cpu_soft = 0.9
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	if cfg.Iostat.CPUWaitSoftPct != 12 || cfg.Iostat.CPUWaitHardPct != 20 {
		t.Fatalf("iostat partial override failed: %+v", cfg.Iostat)
	}
	if cfg.Meminfo.AvailableWarnPct != 25 || cfg.Meminfo.AvailableSeverePct != 10 {
		t.Fatalf("meminfo partial override failed: %+v", cfg.Meminfo)
	}
	if cfg.Top.LoadPerCPUSoft != 0.9 || cfg.Top.LoadPerCPUHard != 1.0 {
		t.Fatalf("top partial override failed: %+v", cfg.Top)
	}
}

func TestLoadConfigRejectsUnknownKey(t *testing.T) {
	path := writeConfig(t, `
[iostat]
unknown_threshold = 1
`)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "iostat.unknown_threshold") {
		t.Fatalf("unknown key should mention full key, got: %v", err)
	}
}

func TestValidateRejectsInvalidThresholds(t *testing.T) {
	cfg := Default()
	cfg.Iostat.CPUWaitSoftPct = 120
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "iostat.cpu_wait_soft_pct") {
		t.Fatalf("invalid iostat percent should fail with key, got: %v", err)
	}

	cfg = Default()
	cfg.Meminfo.AvailableSeverePct = 25
	cfg.Meminfo.AvailableWarnPct = 20
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "meminfo.available_severe_pct") {
		t.Fatalf("invalid meminfo ordering should fail with key, got: %v", err)
	}

	cfg = Default()
	cfg.Top.CPUIdleHardPct = 30
	cfg.Top.CPUIdleSoftPct = 20
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "top.cpu_idle_hard_pct") {
		t.Fatalf("invalid top idle ordering should fail with key, got: %v", err)
	}
}

func TestLoadConfigExplicitMissingFileFails(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil {
		t.Fatalf("explicit missing config should fail")
	}
}

func TestDefaultTOMLMatchesDefault(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "configs", "default.toml"))
	if err != nil {
		t.Fatalf("load configs/default.toml: %v", err)
	}
	if cfg != Default() {
		t.Fatalf("configs/default.toml drifted from Default():\nfile=%+v\ndefault=%+v", cfg, Default())
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
