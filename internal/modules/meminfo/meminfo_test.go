package meminfo

import (
	"os"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacymeminfo "oswbb-analyse/pkg/meminfo"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParserParseFilesMergesTypicalMemInfoFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeMemInfoFixture(t, dir, "host_meminfo_26.04.21.0300.dat", []string{
		meminfoSnapshot("03:00:04", 8*1024*1024, 6*1024*1024, 512*1024),
	})
	second := writeMemInfoFixture(t, dir, "host_meminfo_26.04.21.0301.dat", []string{
		meminfoSnapshot("03:00:06", 8*1024*1024, 5*1024*1024, 640*1024),
	})

	parsed, err := NewParser().ParseFiles([]string{second, first})
	if err != nil {
		t.Fatalf("ParseFiles returned error: %v", err)
	}

	if parsed.ModuleName() != modulebase.ModuleMeminfo {
		t.Fatalf("parsed module name = %q, want %q", parsed.ModuleName(), modulebase.ModuleMeminfo)
	}
	if got, want := len(parsed.Log.Data), 2; got != want {
		t.Fatalf("snapshot count = %d, want %d", got, want)
	}
	if !parsed.Log.Data[0].Timestamp.Before(parsed.Log.Data[1].Timestamp) {
		t.Fatalf("snapshots should be sorted by timestamp: %#v", parsed.Log.Data)
	}
	if got := parsed.Log.Data[0].MemStats.MemTotal; got != 8*1024*1024 {
		t.Fatalf("MemTotal = %d, want fixture value", got)
	}
}

func TestParserParseFilesRejectsInvalidMemInfoInputs(t *testing.T) {
	if _, err := NewParser().ParseFiles(nil); err == nil || !strings.Contains(err.Error(), "meminfo 文件列表不能为空") {
		t.Fatalf("expected empty input error, got %v", err)
	}
	if _, err := NewParser().ParseFiles([]string{filepath.Join(t.TempDir(), "missing_meminfo.dat")}); err == nil || !strings.Contains(err.Error(), "解析 meminfo 文件失败") {
		t.Fatalf("expected missing file error, got %v", err)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty_meminfo.dat")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty fixture: %v", err)
	}
	if _, err := NewParser().ParseFiles([]string{empty}); err == nil || !strings.Contains(err.Error(), "没有有效的 meminfo 数据") {
		t.Fatalf("expected empty data error, got %v", err)
	}

	bad := filepath.Join(dir, "bad_meminfo.dat")
	if err := os.WriteFile(bad, []byte("not a meminfo log\n"), 0o644); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	if _, err := NewParser().ParseFiles([]string{bad}); err == nil || !strings.Contains(err.Error(), "没有有效的 meminfo 数据") {
		t.Fatalf("expected bad data error, got %v", err)
	}
}

func TestAnalyzerReusesLegacyMemInfoFindingLogic(t *testing.T) {
	log := highPressureMemInfoLog()
	start, end := log.GetTimeRange()
	expected := legacyfindings.BuildMemInfoFindings(log, start, end)
	if len(expected) == 0 {
		t.Fatal("test fixture must trigger legacy meminfo findings")
	}

	analysis, err := NewAnalyzer(Config{}).Analyze(&ParsedData{Log: log})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if analysis.ModuleName() != modulebase.ModuleMeminfo {
		t.Fatalf("analysis module name = %q, want %q", analysis.ModuleName(), modulebase.ModuleMeminfo)
	}
	if !reflect.DeepEqual(analysis.Findings, expected) {
		t.Fatalf("analysis findings diverged from legacy logic:\ngot=%#v\nwant=%#v", analysis.Findings, expected)
	}
	if got, want := analysis.DataPoints, len(log.Data); got != want {
		t.Fatalf("data points = %d, want %d", got, want)
	}
}

func TestAnalyzerRejectsNilOrEmptyMemInfoData(t *testing.T) {
	if _, err := NewAnalyzer(Config{}).Analyze(nil); err == nil {
		t.Fatal("Analyze(nil) should return an error")
	}
	if _, err := NewAnalyzer(Config{}).Analyze(&ParsedData{}); err == nil {
		t.Fatal("Analyze without log should return an error")
	}
	if _, err := NewAnalyzer(Config{}).Analyze(&ParsedData{Log: &legacymeminfo.MemInfoLog{}}); err == nil {
		t.Fatal("Analyze without snapshots should return an error")
	}
}

func TestReporterBuildsStructuredMemInfoReport(t *testing.T) {
	analysis := &Analysis{
		Start:      fixedTime("03:00:04"),
		End:        fixedTime("03:00:06"),
		DataPoints: 3,
		Summary: []reportbase.SummaryItem{
			{Name: "时间范围", Value: "2026-04-21 03:00:04 ~ 2026-04-21 03:00:06"},
			{Name: "采样数量", Value: "3"},
		},
		Sections: []reportbase.Section{{
			Title: "📈 系统指标摘要",
			Body:  "[概览]\n- 可用内存: 75.0%\n",
		}},
		Tables: []reportbase.Table{{
			Title:   "内存指标",
			Headers: []string{"指标", "当前"},
			Rows:    [][]string{{"MemAvailable", "75.0%"}},
		}},
		Findings: []legacyfindings.Finding{{
			Source:   "meminfo",
			Severity: legacyfindings.SeverityHigh,
			Nature:   legacyfindings.FindingNatureRisk,
			Title:    "可用内存偏低",
			Summary:  "可用内存低于阈值",
			Target:   "system",
		}},
		Diagnosis: diagnosis.ActiveResult("local", "/tmp/model", "summary", []diagnosis.Incident{{
			Classification: "meminfo pressure",
			NextChecks:     []string{"检查匿名页增长"},
		}}, 1),
	}

	report, err := BuildReport(analysis)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}

	if report.Module != string(modulebase.ModuleMeminfo) {
		t.Fatalf("report module = %q, want %q", report.Module, modulebase.ModuleMeminfo)
	}
	if _, ok := any(report).(*reportbase.Report); !ok {
		t.Fatalf("report should use internal/report.Report, got %T", report)
	}
	if len(report.Summary) != 2 || report.Summary[0].Name != "时间范围" || report.Summary[1].Name != "采样数量" {
		t.Fatalf("unexpected report summary: %#v", report.Summary)
	}
	if len(report.Sections) != 1 || !strings.Contains(report.Sections[0].Body, "可用内存") {
		t.Fatalf("report should contain sections: %#v", report)
	}
	if len(report.Tables) != 1 || !reflect.DeepEqual(report.Tables[0].Headers, []string{"指标", "当前"}) {
		t.Fatalf("report should preserve table shape: %#v", report.Tables)
	}
	if len(report.Findings) != 1 || report.Findings[0].Severity != "高" || report.Findings[0].Nature != "风险信号" || !strings.Contains(report.Findings[0].Evidence, "对象=system") {
		t.Fatalf("report findings should preserve severity/nature/evidence: %#v", report.Findings)
	}
	if len(report.Suggestions) != 1 || report.Suggestions[0].Detail != "检查匿名页增长" {
		t.Fatalf("report should convert diagnosis next checks: %#v", report.Suggestions)
	}
}

func TestReporterRejectsNilMemInfoAnalysis(t *testing.T) {
	if _, err := BuildReport(nil); err == nil {
		t.Fatal("BuildReport(nil) should return an error")
	}
}

func writeMemInfoFixture(t *testing.T, dir, name string, snapshots []string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Join(snapshots, "\n")), 0o644); err != nil {
		t.Fatalf("write meminfo fixture: %v", err)
	}
	return path
}

func meminfoSnapshot(clock string, memTotal, memAvailable, anonPages int64) string {
	return strings.Join([]string{
		"zzz ***Tue Apr 21 " + clock + " CST 2026",
		"MemTotal:       " + formatInt(memTotal) + " kB",
		"MemFree:        " + formatInt(memAvailable/2) + " kB",
		"MemAvailable:   " + formatInt(memAvailable) + " kB",
		"Buffers:        1024 kB",
		"Cached:         2048 kB",
		"SwapTotal:      1048576 kB",
		"SwapFree:       1048576 kB",
		"AnonPages:      " + formatInt(anonPages) + " kB",
		"Slab:           1024 kB",
		"SReclaimable:   512 kB",
		"SUnreclaim:     512 kB",
		"CommitLimit:    " + formatInt(memTotal) + " kB",
		"Committed_AS:   " + formatInt(memTotal/2) + " kB",
		"",
	}, "\n")
}

func highPressureMemInfoLog() *legacymeminfo.MemInfoLog {
	total := int64(8 * 1024 * 1024)
	return &legacymeminfo.MemInfoLog{
		Data: []legacymeminfo.MemStatData{
			highPressureMemInfoData("03:00:04", total, 900*1024, 512*1024),
			highPressureMemInfoData("03:00:05", total, 700*1024, 768*1024),
			highPressureMemInfoData("03:00:06", total, 600*1024, 1024*1024),
		},
	}
}

func highPressureMemInfoData(clock string, total, available, anonPages int64) legacymeminfo.MemStatData {
	return legacymeminfo.MemStatData{
		Timestamp: fixedTime(clock),
		MemStats: legacymeminfo.MemStats{
			MemTotal:        total,
			MemFree:         available / 2,
			MemAvailable:    available,
			Buffers:         1024,
			Cached:          2048,
			SwapTotal:       1024 * 1024,
			SwapFree:        1024 * 1024,
			SwapFreePresent: true,
			AnonPages:       anonPages,
			Slab:            1024,
			SReclaimable:    512,
			SUnreclaim:      512,
			CommitLimit:     total,
			Committed:       total / 2,
		},
	}
}

func fixedTime(clock string) time.Time {
	value, err := time.ParseInLocation("2006-01-02 15:04:05", "2026-04-21 "+clock, time.FixedZone("CST", 8*3600))
	if err != nil {
		panic(err)
	}
	return value
}

func formatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
