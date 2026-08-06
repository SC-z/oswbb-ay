package iostat

import (
	"os"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacyiostat "oswbb-analyse/pkg/iostat"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParserParseFilesMergesTypicalIOStatFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeIOStatFixture(t, dir, "rdsmaster1_iostat_26.04.21.0300.dat", []string{
		iostatSnapshot("03:00:04", 1.00, "nvme0n1", 1.00, 20.00, 0.10, 1.00),
	})
	second := writeIOStatFixture(t, dir, "rdsmaster1_iostat_26.04.21.0301.dat", []string{
		iostatSnapshot("03:00:06", 2.00, "nvme0n1", 2.00, 30.00, 0.20, 2.00),
	})

	parsed, err := NewParser().ParseFiles([]string{second, first})
	if err != nil {
		t.Fatalf("ParseFiles returned error: %v", err)
	}

	if parsed.ModuleName() != modulebase.ModuleIostat {
		t.Fatalf("parsed module name = %q, want %q", parsed.ModuleName(), modulebase.ModuleIostat)
	}
	if parsed.Log == nil {
		t.Fatal("parsed log is nil")
	}
	if got, want := parsed.Log.Header, "合并了 2 个文件"; got != want {
		t.Fatalf("merged header = %q, want %q", got, want)
	}
	if got, want := len(parsed.Log.Data), 2; got != want {
		t.Fatalf("snapshot count = %d, want %d", got, want)
	}
	if !parsed.Log.Data[0].Timestamp.Before(parsed.Log.Data[1].Timestamp) {
		t.Fatalf("snapshots should be sorted by timestamp: %#v", parsed.Log.Data)
	}
	devices := parsed.Log.GetAllDevices()
	if !reflect.DeepEqual(devices, []string{"nvme0n1"}) {
		t.Fatalf("devices = %#v, want nvme0n1", devices)
	}
}

func TestParserParseFilesRejectsEmptyInput(t *testing.T) {
	_, err := NewParser().ParseFiles(nil)
	if err == nil || !strings.Contains(err.Error(), "iostat 文件列表不能为空") {
		t.Fatalf("expected empty input error, got %v", err)
	}
}

func TestParserParseFilesRejectsMissingFile(t *testing.T) {
	_, err := NewParser().ParseFiles([]string{filepath.Join(t.TempDir(), "missing_iostat.dat")})
	if err == nil || !strings.Contains(err.Error(), "解析 iostat 文件失败") {
		t.Fatalf("expected missing file parse error, got %v", err)
	}
}

func TestParserParseFilesRejectsEmptyAndBadFormatFiles(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty_iostat.dat")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty fixture: %v", err)
	}
	_, emptyErr := NewParser().ParseFiles([]string{empty})
	if emptyErr == nil || !strings.Contains(emptyErr.Error(), "没有有效的 iostat 数据") {
		t.Fatalf("expected empty file error, got %v", emptyErr)
	}

	bad := filepath.Join(dir, "bad_iostat.dat")
	if err := os.WriteFile(bad, []byte("not an iostat log\n"), 0o644); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	_, badErr := NewParser().ParseFiles([]string{bad})
	if badErr == nil || !strings.Contains(badErr.Error(), "没有有效的 iostat 数据") {
		t.Fatalf("expected bad format error, got %v", badErr)
	}
}

func TestAnalyzerReusesLegacyFindingLogic(t *testing.T) {
	log := highPressureIOStatLog()
	start, end := log.GetTimeRange()
	expected := legacyfindings.BuildIOStatFindings(log, start, end)
	if len(expected) == 0 {
		t.Fatal("test fixture must trigger legacy iostat findings")
	}

	analysis, err := NewAnalyzer(Config{}).Analyze(&ParsedData{Log: log})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if analysis.ModuleName() != modulebase.ModuleIostat {
		t.Fatalf("analysis module name = %q, want %q", analysis.ModuleName(), modulebase.ModuleIostat)
	}
	if !reflect.DeepEqual(analysis.Findings, expected) {
		t.Fatalf("analysis findings diverged from legacy logic:\ngot=%#v\nwant=%#v", analysis.Findings, expected)
	}
	if got, want := analysis.DataPoints, len(log.Data); got != want {
		t.Fatalf("data points = %d, want %d", got, want)
	}
}

func TestAnalyzerRejectsNilOrEmptyParsedData(t *testing.T) {
	if _, err := NewAnalyzer(Config{}).Analyze(nil); err == nil {
		t.Fatal("Analyze(nil) should return an error")
	}
	if _, err := NewAnalyzer(Config{}).Analyze(&ParsedData{}); err == nil {
		t.Fatal("Analyze without log should return an error")
	}
	if _, err := NewAnalyzer(Config{}).Analyze(&ParsedData{Log: &legacyiostat.IOStatLog{}}); err == nil {
		t.Fatal("Analyze without snapshots should return an error")
	}
}

func TestReporterBuildsStructuredReport(t *testing.T) {
	analysis := &Analysis{
		Start:      fixedTime("03:00:04"),
		End:        fixedTime("03:00:06"),
		Devices:    []string{"nvme0n1"},
		DataPoints: 3,
		Findings: []legacyfindings.Finding{{
			Source:   "iostat",
			Severity: legacyfindings.SeverityHigh,
			Title:    "iostat 采样中 CPU iowait 偏高",
			Summary:  "iowait 平均 31.0%，峰值 32.0%。",
		}},
	}

	report, err := NewReporter().Build(analysis)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if report.Module != string(modulebase.ModuleIostat) {
		t.Fatalf("report module = %q, want %q", report.Module, modulebase.ModuleIostat)
	}
	if _, ok := any(report).(*reportbase.Report); !ok {
		t.Fatalf("report should use internal/report.Report, got %T", report)
	}
	if len(report.Summary) < 2 || report.Summary[0].Name != "时间范围" || report.Summary[1].Name != "设备总数" {
		t.Fatalf("unexpected report summary: %#v", report.Summary)
	}
	if len(report.Sections) == 0 {
		t.Fatalf("report should contain sections: %#v", report)
	}
	if len(report.Tables) == 0 || report.Tables[0].Rows[0][0] != "nvme0n1" {
		t.Fatalf("report should contain device table: %#v", report.Tables)
	}
	if len(report.Findings) != len(analysis.Findings) || report.Findings[0].Title != analysis.Findings[0].Title {
		t.Fatalf("report findings should preserve analysis finding titles: %#v", report.Findings)
	}
}

func TestBuildReportRejectsNilAnalysis(t *testing.T) {
	if _, err := BuildReport(nil); err == nil {
		t.Fatal("BuildReport(nil) should return an error")
	}
}

func TestReporterRejectsNilAnalysis(t *testing.T) {
	if _, err := NewReporter().Build(nil); err == nil {
		t.Fatal("Build(nil) should return an error")
	}
}

func writeIOStatFixture(t *testing.T, dir, name string, snapshots []string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	content := "Linux OSWbb v7.3.3\n" + strings.Join(snapshots, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write iostat fixture: %v", err)
	}
	return path
}

func iostatSnapshot(clock string, iowait float64, device string, readIOPS, writeIOPS, queue, util float64) string {
	return strings.Join([]string{
		"zzz ***Tue Apr 21 " + clock + " CST 2026",
		"avg-cpu:  %user   %nice %system %iowait  %steal   %idle",
		"           1.00    0.00    1.00    " + formatFloat(iowait) + "    0.00   68.00",
		"",
		"Device r/s w/s rkB/s wkB/s r_await w_await aqu-sz %util",
		device + " " + formatFloat(readIOPS) + " " + formatFloat(writeIOPS) + " 800.00 4800.00 120.00 250.00 " + formatFloat(queue) + " " + formatFloat(util),
		"",
	}, "\n")
}

func highPressureIOStatLog() *legacyiostat.IOStatLog {
	return &legacyiostat.IOStatLog{
		Header: "Linux OSWbb v7.3.3",
		Data: []legacyiostat.IOStatData{
			highPressureIOStatData("03:00:04", 30.0, 2.50, 99.0),
			highPressureIOStatData("03:00:05", 32.0, 2.80, 99.5),
			highPressureIOStatData("03:00:06", 31.0, 2.60, 99.2),
		},
	}
}

func highPressureIOStatData(clock string, iowait, queue, util float64) legacyiostat.IOStatData {
	return legacyiostat.IOStatData{
		Timestamp: fixedTime(clock),
		CPU: legacyiostat.CPUStats{
			User:   1.0,
			System: 1.0,
			IOWait: iowait,
			Idle:   68.0,
		},
		Devices: []legacyiostat.DeviceStats{{
			Device:         "nvme0n1",
			ReadReqPerSec:  20.0,
			WriteReqPerSec: 120.0,
			ReadKBPerSec:   800.0,
			WriteKBPerSec:  4800.0,
			ReadAwait:      120.0,
			WriteAwait:     250.0,
			AvgQueueSize:   queue,
			Utilization:    util,
		}},
	}
}

func fixedTime(clock string) time.Time {
	value, err := time.ParseInLocation("2006-01-02 15:04:05", "2026-04-21 "+clock, time.FixedZone("CST", 8*3600))
	if err != nil {
		panic(err)
	}
	return value
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}
