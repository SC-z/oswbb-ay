package top

import (
	internalconfig "oswbb-analyse/internal/config"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacytop "oswbb-analyse/pkg/top"
	"time"
)

type Config = internalconfig.TopConfig

// ParsedData is the structured parser result for the top module.
// Log reuses pkg/top.TopLog to preserve current parsing behavior.
type ParsedData struct {
	Log         *legacytop.TopLog
	Files       []string
	ParseErrors []error
}

func (p *ParsedData) ModuleName() modulebase.ModuleName {
	return modulebase.ModuleTop
}

// Analysis is the side-effect-free top analyzer result.
type Analysis struct {
	Start      time.Time
	End        time.Time
	DataPoints int
	Summary    []reportbase.SummaryItem
	Sections   []reportbase.Section
	Tables     []reportbase.Table
	Findings   []legacyfindings.Finding
	Diagnosis  diagnosis.AIResult
}

func (a *Analysis) ModuleName() modulebase.ModuleName {
	return modulebase.ModuleTop
}
