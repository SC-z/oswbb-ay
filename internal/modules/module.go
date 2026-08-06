package modules

// ModuleName is the stable identifier used by internal module boundaries.
type ModuleName string

const (
	ModuleIostat  ModuleName = "iostat"
	ModuleMeminfo ModuleName = "meminfo"
	ModuleTop     ModuleName = "top"
)

// Module is intentionally small so legacy packages can adopt it gradually.
type Module interface {
	Name() ModuleName
}

// ParseResult marks parser outputs without forcing old packages to change.
type ParseResult interface {
	ModuleName() ModuleName
}

// AnalysisResult marks analyzer outputs without introducing a plugin system.
type AnalysisResult interface {
	ModuleName() ModuleName
}
