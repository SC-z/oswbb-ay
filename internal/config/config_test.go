package config

import "testing"

func TestDefaultConfigValid(t *testing.T) {
	cfg := Default()

	if cfg.General.DefaultOutputFormat != "report" {
		t.Fatalf("default output format = %q, want report", cfg.General.DefaultOutputFormat)
	}
	if !cfg.Iostat.Enabled || !cfg.Meminfo.Enabled || !cfg.Top.Enabled {
		t.Fatalf("default config should keep iostat/meminfo/top enabled: %+v", cfg)
	}
	if cfg.AI.DefaultOutputFormat != "ml" {
		t.Fatalf("default AI output format = %q, want ml", cfg.AI.DefaultOutputFormat)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestConfigValidateRejectsUnsupportedOutputFormat(t *testing.T) {
	cfg := Default()
	cfg.General.DefaultOutputFormat = "xml"

	if err := cfg.Validate(); err == nil {
		t.Fatalf("unsupported output format should fail validation")
	}
}

func TestConfigValidateRejectsMissingTimeZone(t *testing.T) {
	cfg := Default()
	cfg.General.TimeZone = ""

	if err := cfg.Validate(); err == nil {
		t.Fatalf("missing time zone should fail validation")
	}
}

func TestConfigValidateRejectsNoEnabledModules(t *testing.T) {
	cfg := Default()
	cfg.Iostat.Enabled = false
	cfg.Meminfo.Enabled = false
	cfg.Top.Enabled = false

	if err := cfg.Validate(); err == nil {
		t.Fatalf("config with all modules disabled should fail validation")
	}
}

func TestConfigValidateRejectsUnsupportedAIOutputFormat(t *testing.T) {
	cfg := Default()
	cfg.AI.DefaultOutputFormat = "xml"

	if err := cfg.Validate(); err == nil {
		t.Fatalf("unsupported AI output format should fail validation")
	}
}

func TestConfigValidateRejectsNegativeAITimeout(t *testing.T) {
	cfg := Default()
	cfg.AI.TimeoutSeconds = -1

	if err := cfg.Validate(); err == nil {
		t.Fatalf("negative AI timeout should fail validation")
	}
}
