package aitypes

import (
	"oswbb-analyse/pkg/findings"
	"time"
)

const DefaultModelFile = "Qwen3-0.6B-Q8_0.gguf"

func DefaultModelName() string {
	return DefaultModelFile
}

type Options struct {
	Enabled     bool
	Debug       bool
	ModelPath   string
	RuntimePath string
	Timeout     time.Duration
}

type MLSection struct {
	ID           string
	Module       string
	Format       string
	FilePath     string
	Description  string
	Data         string
	TotalRows    int
	SelectedRows int
	BatchIndex   int
	BatchTotal   int
	RowStart     int
	RowEnd       int
}

type MLPromptInput struct {
	Hostname  string
	StartTime string
	EndTime   string
	Findings  []findings.Finding
	Sections  []MLSection
}

func (input MLPromptInput) EvidenceIDs() map[string]struct{} {
	ids := map[string]struct{}{
		"ml-format": {},
	}
	for _, section := range input.Sections {
		if section.ID != "" {
			ids[section.ID] = struct{}{}
		}
	}
	for _, finding := range input.Findings {
		if finding.RuleID != "" {
			ids[finding.RuleID] = struct{}{}
		}
	}
	return ids
}
