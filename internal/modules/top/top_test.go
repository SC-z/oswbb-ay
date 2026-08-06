package top

import (
	"os"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacytop "oswbb-analyse/pkg/top"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParserParseFilesMergesTypicalTopFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeTopFixture(t, dir, "host_top_26.04.21.0300.dat", []string{
		topSnapshot("03:00:04", 4.0, 80.0, 2, 0),
	})
	second := writeTopFixture(t, dir, "host_top_26.04.21.0301.dat", []string{
		topSnapshot("03:00:06", 5.0, 70.0, 3, 0),
	})

	parsed, err := NewParser().ParseFiles([]string{second, first})
	if err != nil {
		t.Fatalf("ParseFiles returned error: %v", err)
	}

	if parsed.ModuleName() != modulebase.ModuleTop {
		t.Fatalf("parsed module name = %q, want %q", parsed.ModuleName(), modulebase.ModuleTop)
	}
	if got, want := len(parsed.Log.Snapshots), 2; got != want {
		t.Fatalf("snapshot count = %d, want %d", got, want)
	}
	if !parsed.Log.Snapshots[0].Timestamp.Before(parsed.Log.Snapshots[1].Timestamp) {
		t.Fatalf("snapshots should be sorted by timestamp: %#v", parsed.Log.Snapshots)
	}
	if got := parsed.Log.Snapshots[0].Load1; got != 4.0 {
		t.Fatalf("Load1 = %.1f, want fixture value", got)
	}
}

func TestParserParseFilesRejectsInvalidTopInputs(t *testing.T) {
	if _, err := NewParser().ParseFiles(nil); err == nil || !strings.Contains(err.Error(), "top 文件列表不能为空") {
		t.Fatalf("expected empty input error, got %v", err)
	}
	if _, err := NewParser().ParseFiles([]string{filepath.Join(t.TempDir(), "missing_top.dat")}); err == nil || !strings.Contains(err.Error(), "解析 top 文件失败") {
		t.Fatalf("expected missing file error, got %v", err)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty_top.dat")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty fixture: %v", err)
	}
	if _, err := NewParser().ParseFiles([]string{empty}); err == nil || !strings.Contains(err.Error(), "没有有效的 top 数据") {
		t.Fatalf("expected empty data error, got %v", err)
	}

	bad := filepath.Join(dir, "bad_top.dat")
	if err := os.WriteFile(bad, []byte("not a top log\n"), 0o644); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	if _, err := NewParser().ParseFiles([]string{bad}); err == nil || !strings.Contains(err.Error(), "没有有效的 top 数据") {
		t.Fatalf("expected bad data error, got %v", err)
	}
}

func TestAnalyzerReusesLegacyTopFindingLogic(t *testing.T) {
	log := highPressureTopLog()
	start, end := log.GetTimeRange()
	expected := legacyfindings.BuildTopFindings(log, start, end)
	if len(expected) == 0 {
		t.Fatal("test fixture must trigger legacy top findings")
	}

	analysis, err := NewAnalyzer(Config{}).Analyze(&ParsedData{Log: log})
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	if analysis.ModuleName() != modulebase.ModuleTop {
		t.Fatalf("analysis module name = %q, want %q", analysis.ModuleName(), modulebase.ModuleTop)
	}
	if !reflect.DeepEqual(analysis.Findings, expected) {
		t.Fatalf("analysis findings diverged from legacy logic:\ngot=%#v\nwant=%#v", analysis.Findings, expected)
	}
	if got, want := analysis.DataPoints, len(log.Snapshots); got != want {
		t.Fatalf("data points = %d, want %d", got, want)
	}
}

func TestAnalyzerRejectsNilOrEmptyTopData(t *testing.T) {
	if _, err := NewAnalyzer(Config{}).Analyze(nil); err == nil {
		t.Fatal("Analyze(nil) should return an error")
	}
	if _, err := NewAnalyzer(Config{}).Analyze(&ParsedData{}); err == nil {
		t.Fatal("Analyze without log should return an error")
	}
	if _, err := NewAnalyzer(Config{}).Analyze(&ParsedData{Log: &legacytop.TopLog{}}); err == nil {
		t.Fatal("Analyze without snapshots should return an error")
	}
}

func TestReporterBuildsStructuredTopReport(t *testing.T) {
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
			Body:  "[Load Average 负载]\n  Load 1min : Min=1.00, Max=3.00, Avg=2.00\n",
		}},
		Tables: []reportbase.Table{{
			Title:   "代表进程候选",
			Headers: []string{"PID", "USER", "STATE", "COMMAND"},
			Rows:    [][]string{{"100", "root", "R", "busy"}},
		}},
		Findings: []legacyfindings.Finding{{
			Source:   "top",
			Severity: legacyfindings.SeverityHigh,
			Nature:   legacyfindings.FindingNatureRisk,
			Title:    "CPU 空闲率偏低",
			Summary:  "CPU idle 低于阈值",
			Target:   "system",
		}},
		Diagnosis: diagnosis.ActiveResult("local", "/tmp/model", "summary", []diagnosis.Incident{{
			Classification: "top pressure",
			NextChecks:     []string{"检查高 CPU 进程"},
		}}, 1),
	}

	report, err := BuildReport(analysis)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}

	if report.Module != string(modulebase.ModuleTop) {
		t.Fatalf("report module = %q, want %q", report.Module, modulebase.ModuleTop)
	}
	if _, ok := any(report).(*reportbase.Report); !ok {
		t.Fatalf("report should use internal/report.Report, got %T", report)
	}
	if len(report.Summary) != 2 || report.Summary[0].Name != "时间范围" || report.Summary[1].Name != "采样数量" {
		t.Fatalf("unexpected report summary: %#v", report.Summary)
	}
	if len(report.Sections) != 1 || !strings.Contains(report.Sections[0].Body, "Load 1min") {
		t.Fatalf("report should contain sections: %#v", report)
	}
	if len(report.Tables) != 1 || !reflect.DeepEqual(report.Tables[0].Headers, []string{"PID", "USER", "STATE", "COMMAND"}) {
		t.Fatalf("report should preserve table shape: %#v", report.Tables)
	}
	if len(report.Findings) != 1 || report.Findings[0].Severity != "高" || report.Findings[0].Nature != "风险信号" || !strings.Contains(report.Findings[0].Evidence, "对象=system") {
		t.Fatalf("report findings should preserve severity/nature/evidence: %#v", report.Findings)
	}
	if len(report.Suggestions) != 1 || report.Suggestions[0].Detail != "检查高 CPU 进程" {
		t.Fatalf("report should convert diagnosis next checks: %#v", report.Suggestions)
	}
}

func TestReporterRejectsNilTopAnalysis(t *testing.T) {
	if _, err := BuildReport(nil); err == nil {
		t.Fatal("BuildReport(nil) should return an error")
	}
}

func writeTopFixture(t *testing.T, dir, name string, snapshots []string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Join(snapshots, "\n")), 0o644); err != nil {
		t.Fatalf("write top fixture: %v", err)
	}
	return path
}

func topSnapshot(clock string, load1, idle float64, running, zombie int) string {
	return strings.Join([]string{
		"zzz ***Tue Apr 21 " + clock + " CST 2026",
		"top - " + clock + " up 1 day,  1 user,  load average: " + formatFloat(load1) + ", " + formatFloat(load1) + ", " + formatFloat(load1),
		"Tasks: 100 total,   " + strconv.Itoa(running) + " running,  98 sleeping,   0 stopped,   " + strconv.Itoa(zombie) + " zombie",
		"%Cpu(s): 90.0 us,  5.0 sy,  0.0 ni, " + formatFloat(idle) + " id,  25.0 wa,  0.0 hi,  0.0 si,  0.0 st",
		"PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND",
		"100 root      20   0  100000  20000   5000 R  95.0  1.0   0:01.00 busy",
		"101 root      20   0  100000  20000   5000 D   1.0  1.0   0:01.00 wait",
		"",
	}, "\n")
}

func highPressureTopLog() *legacytop.TopLog {
	return &legacytop.TopLog{
		Snapshots: []legacytop.TopSnapshot{
			highPressureTopSnapshot("03:00:04", 10.0, 8.0, 25.0, 12, 1),
			highPressureTopSnapshot("03:00:05", 12.0, 6.0, 30.0, 14, 2),
			highPressureTopSnapshot("03:00:06", 11.0, 7.0, 28.0, 13, 2),
		},
	}
}

func highPressureTopSnapshot(clock string, load1, idle, wait float64, running, zombie int) legacytop.TopSnapshot {
	return legacytop.TopSnapshot{
		Timestamp:   fixedTime(clock),
		Load1:       load1,
		Load5:       load1,
		Load15:      load1,
		CPUCount:    8,
		TaskTotal:   100,
		TaskRunning: running,
		TaskZombie:  zombie,
		CpuUser:     90.0,
		CpuSys:      5.0,
		CpuIdle:     idle,
		CpuWait:     wait,
		Processes: []legacytop.ProcessStats{
			{PID: 100, User: "root", State: "R", CPUPercent: 95.0, MemPercent: 1.0, Command: "busy"},
			{PID: 101, User: "root", State: "D", CPUPercent: 1.0, MemPercent: 1.0, Command: "wait"},
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

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}
