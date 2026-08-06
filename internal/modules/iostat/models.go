package iostat

import (
	internalconfig "oswbb-analyse/internal/config"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacyiostat "oswbb-analyse/pkg/iostat"
	"time"
)

type Config = internalconfig.IostatConfig

// ParsedData is the structured parser result for the iostat module.
// Log deliberately reuses pkg/iostat.IOStatLog to avoid changing parser semantics.
type ParsedData struct {
	Log         *legacyiostat.IOStatLog
	Files       []string
	ParseErrors []error
}

func (p *ParsedData) ModuleName() modulebase.ModuleName {
	return modulebase.ModuleIostat
}

// Analysis is the structured analyzer result for iostat.
// Findings are produced by pkg/findings so existing thresholds stay authoritative.
type Analysis struct {
	Start      time.Time
	End        time.Time
	Devices    []string
	DataPoints int
	Tables     []reportbase.Table
	Findings   []legacyfindings.Finding
	Diagnosis  diagnosis.AIResult
}

func (a *Analysis) ModuleName() modulebase.ModuleName {
	return modulebase.ModuleIostat
}
