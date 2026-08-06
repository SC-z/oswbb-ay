package app

import (
	"context"
	"oswbb-analyse/internal/apperr"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/modules"
	"oswbb-analyse/internal/report"
	legacyiostat "oswbb-analyse/pkg/iostat"
	legacymeminfo "oswbb-analyse/pkg/meminfo"
	legacytop "oswbb-analyse/pkg/top"
	"strings"
	"testing"
	"time"
)

type stubModuleRunner struct {
	name modules.ModuleName
	req  ModuleRequest
}

func (r *stubModuleRunner) Name() modules.ModuleName { return r.name }

func (r *stubModuleRunner) FileTypes() []core.FileType { return []core.FileType{core.FileTypeIOStat} }

func (r *stubModuleRunner) Run(_ context.Context, req ModuleRequest) (*report.Report, error) {
	r.req = req
	return &report.Report{Module: string(r.name)}, nil
}

func TestRegistryRegisterResolveAndList(t *testing.T) {
	registry := NewRegistry()
	runner := &stubModuleRunner{name: modules.ModuleIostat}

	if err := registry.Register(ModuleDescriptor{
		Name:      modules.ModuleIostat,
		FileTypes: []core.FileType{core.FileTypeIOStat},
		Runner:    runner,
	}); err != nil {
		t.Fatalf("register iostat: %v", err)
	}

	got, err := registry.Get(modules.ModuleIostat)
	if err != nil || got.Runner != runner {
		t.Fatalf("get iostat = %+v, %v", got, err)
	}
	resolved, err := registry.Resolve(core.FileTypeIOStat)
	if err != nil || resolved.Name != modules.ModuleIostat {
		t.Fatalf("resolve iostat = %+v, %v", resolved, err)
	}
	list := registry.List()
	if len(list) != 1 || list[0].Name != modules.ModuleIostat {
		t.Fatalf("list not stable: %+v", list)
	}
}

func TestRegistryRejectsDuplicateNameAndFileType(t *testing.T) {
	registry := NewRegistry()
	first := ModuleDescriptor{Name: modules.ModuleIostat, FileTypes: []core.FileType{core.FileTypeIOStat}, Runner: &stubModuleRunner{name: modules.ModuleIostat}}
	if err := registry.Register(first); err != nil {
		t.Fatalf("register first: %v", err)
	}
	if err := registry.Register(first); err == nil {
		t.Fatalf("duplicate module name should fail")
	}
	if err := registry.Register(ModuleDescriptor{
		Name:      modules.ModuleMeminfo,
		FileTypes: []core.FileType{core.FileTypeIOStat},
		Runner:    &stubModuleRunner{name: modules.ModuleMeminfo},
	}); err == nil {
		t.Fatalf("duplicate file type should fail")
	}
}

func TestRegistryUnknownModuleAndFileType(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.Get(modules.ModuleTop); err == nil {
		t.Fatalf("unknown module should fail")
	}
	if _, err := registry.Resolve(core.FileTypeTop); err == nil {
		t.Fatalf("unknown file type should fail")
	}
}

func TestBuiltinRegistryRegistersStableModules(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("builtin registry: %v", err)
	}

	list := registry.List()
	want := []modules.ModuleName{modules.ModuleIostat, modules.ModuleMeminfo, modules.ModuleTop}
	if len(list) != len(want) {
		t.Fatalf("builtin module count = %d, want %d", len(list), len(want))
	}
	for i, name := range want {
		if list[i].Name != name {
			t.Fatalf("builtin module[%d] = %s, want %s", i, list[i].Name, name)
		}
	}
	for _, fileType := range []core.FileType{core.FileTypeIOStat, core.FileTypeMeminfo, core.FileTypeTop} {
		if _, err := registry.Resolve(fileType); err != nil {
			t.Fatalf("resolve builtin %s: %v", fileType, err)
		}
	}
}

func TestBuiltinTopRunnerUsesRequestConfigAndTimeRange(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("builtin registry: %v", err)
	}
	desc, err := registry.Get(modules.ModuleTop)
	if err != nil {
		t.Fatalf("get top: %v", err)
	}

	at := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.Top.CPUIdleHardPct = 60
	cfg.Top.CPUIdleSoftPct = 70
	got, err := desc.Runner.Run(context.Background(), ModuleRequest{
		Bundle: &core.AnalysisBundle{Top: &legacytop.TopLog{Snapshots: []legacytop.TopSnapshot{{
			Timestamp: at,
			CpuIdle:   50,
		}}}},
		TimeRange: core.TimeRange{Start: at, End: at},
		Config:    cfg,
	})
	if err != nil {
		t.Fatalf("run top: %v", err)
	}
	if len(got.Findings) == 0 || got.Findings[0].Severity != "高" {
		t.Fatalf("custom config did not affect findings: %+v", got.Findings)
	}
	if len(got.Summary) == 0 || !strings.Contains(got.Summary[0].Value, "2026-06-24 10:00:00 ~ 2026-06-24 10:00:00") {
		t.Fatalf("time range not reflected in summary: %+v", got.Summary)
	}
}

func TestBuiltinModuleRunnersBuildReportsWithRawTables(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("builtin registry: %v", err)
	}
	at := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	req := ModuleRequest{
		TimeRange: core.TimeRange{Start: at, End: at},
		Config:    config.Default(),
	}

	cases := []struct {
		name      modules.ModuleName
		tableName string
		bundle    *core.AnalysisBundle
	}{
		{
			name:      modules.ModuleIostat,
			tableName: "iostat",
			bundle: &core.AnalysisBundle{IOStat: &legacyiostat.IOStatLog{Data: []legacyiostat.IOStatData{{
				Timestamp: at,
				CPU:       legacyiostat.CPUStats{Idle: 95},
				Devices: []legacyiostat.DeviceStats{{
					Device:         "nvme0n1",
					ReadReqPerSec:  1,
					WriteReqPerSec: 2,
				}},
			}}}},
		},
		{
			name:      modules.ModuleMeminfo,
			tableName: "meminfo",
			bundle: &core.AnalysisBundle{Meminfo: &legacymeminfo.MemInfoLog{Data: []legacymeminfo.MemStatData{{
				Timestamp: at,
				MemStats:  legacymeminfo.MemStats{MemTotal: 1024, MemAvailable: 512},
			}}}},
		},
		{
			name:      modules.ModuleTop,
			tableName: "top",
			bundle: &core.AnalysisBundle{Top: &legacytop.TopLog{Snapshots: []legacytop.TopSnapshot{{
				Timestamp: at,
				Load1:     1,
				CpuIdle:   90,
			}}}},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.name), func(t *testing.T) {
			desc, err := registry.Get(tc.name)
			if err != nil {
				t.Fatalf("get module: %v", err)
			}
			req.Bundle = tc.bundle
			got, err := desc.Runner.Run(context.Background(), req)
			if err != nil {
				t.Fatalf("run module: %v", err)
			}
			if len(got.Tables) == 0 || got.Tables[0].Title != tc.tableName || len(got.Tables[0].Rows) == 0 {
				t.Fatalf("report raw table = %#v, want non-empty %s table", got.Tables, tc.tableName)
			}
		})
	}
}

func TestBuiltinModuleRunnersClassifyEmptyBundleErrors(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("builtin registry: %v", err)
	}

	for _, name := range []modules.ModuleName{modules.ModuleIostat, modules.ModuleMeminfo, modules.ModuleTop} {
		t.Run(string(name), func(t *testing.T) {
			desc, err := registry.Get(name)
			if err != nil {
				t.Fatalf("get module: %v", err)
			}
			_, err = desc.Runner.Run(context.Background(), ModuleRequest{Config: config.Default()})
			if err == nil {
				t.Fatalf("empty bundle should fail")
			}
			if apperr.KindOf(err) != apperr.KindAnalysis {
				t.Fatalf("kind = %q, want analysis: %v", apperr.KindOf(err), err)
			}
			if apperr.ModuleOf(err) != string(name) {
				t.Fatalf("module = %q, want %q", apperr.ModuleOf(err), name)
			}
		})
	}
}
