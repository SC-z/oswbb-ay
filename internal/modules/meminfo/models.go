package meminfo

import (
	internalconfig "oswbb-analyse/internal/config"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacymeminfo "oswbb-analyse/pkg/meminfo"
	"time"
)

type Config = internalconfig.MeminfoConfig

// ParsedData is the structured parser result for the meminfo module.
// It reuses pkg/meminfo.MemInfoLog so parser semantics remain unchanged.
type ParsedData struct {
	Log         *legacymeminfo.MemInfoLog
	Files       []string
	ParseErrors []error
}

func (p *ParsedData) ModuleName() modulebase.ModuleName {
	return modulebase.ModuleMeminfo
}

// Analysis is the side-effect-free meminfo analyzer result.
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
	return modulebase.ModuleMeminfo
}
