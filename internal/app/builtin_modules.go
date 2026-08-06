package app

import (
	"context"

	"oswbb-analyse/internal/apperr"
	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/modules"
	moduleiostat "oswbb-analyse/internal/modules/iostat"
	modulememinfo "oswbb-analyse/internal/modules/meminfo"
	moduletop "oswbb-analyse/internal/modules/top"
	"oswbb-analyse/internal/report"
)

func NewBuiltinRegistry() (*Registry, error) {
	registry := NewRegistry()
	for _, d := range BuiltinModuleDescriptors() {
		if err := registry.Register(d); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func BuiltinModuleDescriptors() []ModuleDescriptor {
	return []ModuleDescriptor{
		{Name: modules.ModuleIostat, FileTypes: []core.FileType{core.FileTypeIOStat}, Runner: iostatRunner{}},
		{Name: modules.ModuleMeminfo, FileTypes: []core.FileType{core.FileTypeMeminfo}, Runner: meminfoRunner{}},
		{Name: modules.ModuleTop, FileTypes: []core.FileType{core.FileTypeTop}, Runner: topRunner{}},
	}
}

type iostatRunner struct{}

func (iostatRunner) Name() modules.ModuleName { return modules.ModuleIostat }
func (iostatRunner) FileTypes() []core.FileType {
	return []core.FileType{core.FileTypeIOStat}
}
func (iostatRunner) Run(ctx context.Context, req ModuleRequest) (*report.Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Bundle == nil || req.Bundle.IOStat == nil {
		return nil, apperr.New(apperr.KindAnalysis, string(modules.ModuleIostat), "iostat bundle is empty")
	}
	cfg := effectiveConfig(req.Config).Iostat
	analysis, err := moduleiostat.NewAnalyzer(cfg).AnalyzeRange(&moduleiostat.ParsedData{Log: req.Bundle.IOStat}, req.TimeRange.Start, req.TimeRange.End)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindAnalysis, string(modules.ModuleIostat), "analyze iostat", err)
	}
	analysis.Diagnosis = req.Diagnosis
	r, err := moduleiostat.BuildReport(analysis)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindAnalysis, string(modules.ModuleIostat), "build iostat report", err)
	}
	return r, nil
}

type meminfoRunner struct{}

func (meminfoRunner) Name() modules.ModuleName { return modules.ModuleMeminfo }
func (meminfoRunner) FileTypes() []core.FileType {
	return []core.FileType{core.FileTypeMeminfo}
}
func (meminfoRunner) Run(ctx context.Context, req ModuleRequest) (*report.Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Bundle == nil || req.Bundle.Meminfo == nil {
		return nil, apperr.New(apperr.KindAnalysis, string(modules.ModuleMeminfo), "meminfo bundle is empty")
	}
	cfg := effectiveConfig(req.Config).Meminfo
	analysis, err := modulememinfo.NewAnalyzer(cfg).AnalyzeRange(&modulememinfo.ParsedData{Log: req.Bundle.Meminfo}, req.TimeRange.Start, req.TimeRange.End)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindAnalysis, string(modules.ModuleMeminfo), "analyze meminfo", err)
	}
	analysis.Diagnosis = req.Diagnosis
	r, err := modulememinfo.BuildReport(analysis)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindAnalysis, string(modules.ModuleMeminfo), "build meminfo report", err)
	}
	return r, nil
}

type topRunner struct{}

func (topRunner) Name() modules.ModuleName { return modules.ModuleTop }
func (topRunner) FileTypes() []core.FileType {
	return []core.FileType{core.FileTypeTop}
}
func (topRunner) Run(ctx context.Context, req ModuleRequest) (*report.Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Bundle == nil || req.Bundle.Top == nil {
		return nil, apperr.New(apperr.KindAnalysis, string(modules.ModuleTop), "top bundle is empty")
	}
	cfg := effectiveConfig(req.Config).Top
	analysis, err := moduletop.NewAnalyzer(cfg).AnalyzeRange(&moduletop.ParsedData{Log: req.Bundle.Top}, req.TimeRange.Start, req.TimeRange.End)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindAnalysis, string(modules.ModuleTop), "analyze top", err)
	}
	analysis.Diagnosis = req.Diagnosis
	r, err := moduletop.BuildReport(analysis)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindAnalysis, string(modules.ModuleTop), "build top report", err)
	}
	return r, nil
}
