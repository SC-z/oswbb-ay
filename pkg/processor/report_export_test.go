package processor

import (
	"context"
	"encoding/csv"
	"os"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/iostat"
	legacyoutput "oswbb-analyse/pkg/output"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingModuleReportRunner struct {
	fileType core.FileType
}

func (r *recordingModuleReportRunner) BuildModuleReport(_ context.Context, fileType core.FileType, _ *core.AnalysisBundle, _ core.TimeRange, _ config.Config, _ diagnosis.AIResult) (*report.Report, error) {
	r.fileType = fileType
	return &report.Report{Tables: []report.Table{{
		Title:   "injected",
		Headers: []string{"source"},
		Rows:    [][]string{{string(fileType)}},
	}}}, nil
}

func TestBuildIOStatReportUsesInjectedModuleReportRunner(t *testing.T) {
	runner := &recordingModuleReportRunner{}
	at := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	opts := analysisOptions{
		iostatConfig: config.Default().Iostat,
		reportRunner: runner,
		reportBundle: &core.AnalysisBundle{},
	}

	got, err := opts.buildIOStatReport(&iostat.IOStatLog{}, at, at)
	if err != nil {
		t.Fatalf("buildIOStatReport returned error: %v", err)
	}
	if runner.fileType != core.FileTypeIOStat {
		t.Fatalf("runner file type = %s, want %s", runner.fileType, core.FileTypeIOStat)
	}
	if len(got.Tables) != 1 || got.Tables[0].Title != "injected" {
		t.Fatalf("report should come from injected runner: %#v", got.Tables)
	}
}

func TestIOStatRawMetricsTableKeepsLegacyCSVSchema(t *testing.T) {
	table := legacyoutput.IOStatRawMetricsTable([]legacyoutput.IOStatRawMetrics{{
		Timestamp:          "2026-04-21 03:00:00",
		Device:             "nvme0n1",
		WriteAwait:         3.25,
		DiscardReqPerSec:   4,
		DiscardKBPerSec:    5,
		DiscardMergePerSec: 6,
		DiscardMergePct:    7,
		DiscardAwait:       8,
		DiscardReqSize:     9,
		CPUIOWait:          10,
		CPUIdle:            90,
	}})

	if strings.Join(table.Headers[:4], ",") != "timestamp,device,read_req_per_sec,write_req_per_sec" {
		t.Fatalf("iostat header order changed: %#v", table.Headers)
	}
	if table.Headers[len(table.Headers)-1] != "utilization" {
		t.Fatalf("iostat last header changed: %#v", table.Headers)
	}
	if table.Rows[0][0] != "2026-04-21 03:00:00" || table.Rows[0][1] != "nvme0n1" {
		t.Fatalf("iostat row identity changed: %#v", table.Rows[0])
	}
}

func TestMemInfoRawMetricsTableKeepsLegacyCSVSchema(t *testing.T) {
	table := legacyoutput.MemInfoRawMetricsTable([]legacyoutput.MemInfoRawMetrics{
		{Timestamp: "t1", MemTotal: 100, MemAvailable: 50, SwapTotal: 100, SwapFree: 90},
		{Timestamp: "t2", MemTotal: 100, MemAvailable: 40, SwapTotal: 100, SwapFree: 80},
	})

	for _, want := range []string{"mem_available_pct", "mem_available_delta", "swap_used_pct", "swap_free_delta"} {
		if !contains(table.Headers, want) {
			t.Fatalf("meminfo header missing %q: %#v", want, table.Headers)
		}
	}
	if table.Rows[1][headerIndex(table.Headers, "mem_available_delta")] != "-10" {
		t.Fatalf("meminfo delta should match legacy CSV behavior: %#v", table.Rows)
	}
}

func TestTopRawMetricsTableKeepsLegacyCSVSchema(t *testing.T) {
	table := legacyoutput.TopRawMetricsTable([]legacyoutput.TopRawMetrics{{
		Timestamp: "t1",
		Load1:     1,
		CPUCount:  4,
		CpuIdle:   88.8,
	}})

	if strings.Join(table.Headers[:6], ",") != "timestamp,load_1,load_5,load_15,cpu_count,load_1_per_cpu" {
		t.Fatalf("top header order changed: %#v", table.Headers)
	}
	if table.Rows[0][headerIndex(table.Headers, "cpu_idle")] != "88.8" {
		t.Fatalf("top row value changed: %#v", table.Rows[0])
	}
}

func TestWriteReportExportUsesInternalCSVFormatter(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "report.csv")
	r := &report.Report{Module: "iostat", Tables: []report.Table{{
		Headers: []string{"name", "note"},
		Rows:    [][]string{{"nvme0n1", "comma, quote \" ok"}},
	}}}

	if err := writeReportExport(filename, "csv", r, nil); err != nil {
		t.Fatalf("writeReportExport returned error: %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("csv should parse: %v\n%s", err, data)
	}
	if records[1][1] != "comma, quote \" ok" {
		t.Fatalf("csv escaping changed: %#v", records)
	}
}

type recordingSink struct {
	reqs []internaloutput.OutputRequest
}

func (s *recordingSink) Write(_ context.Context, req internaloutput.OutputRequest) error {
	s.reqs = append(s.reqs, req)
	return nil
}

func TestWriteReportExportUsesOutputSink(t *testing.T) {
	sink := &recordingSink{}
	r := &report.Report{Module: "iostat", Tables: []report.Table{{
		Headers: []string{"name"},
		Rows:    [][]string{{"nvme0n1"}},
	}}}

	if err := writeReportExport("ignored.csv", "csv", r, sink); err != nil {
		t.Fatalf("writeReportExport returned error: %v", err)
	}
	if len(sink.reqs) != 1 {
		t.Fatalf("sink should receive one export request, got=%d", len(sink.reqs))
	}
	req := sink.reqs[0]
	if req.Path != "ignored.csv" || req.Format != internaloutput.FormatCSV {
		t.Fatalf("sink request metadata = %#v", req)
	}
	if string(req.Data) != "name\nnvme0n1\n" {
		t.Fatalf("sink received unexpected data: %q", req.Data)
	}
}

func TestWriteReportExportWithMessageUsesOutputSink(t *testing.T) {
	sink := &recordingSink{}
	r := &report.Report{Module: "iostat", Tables: []report.Table{{
		Headers: []string{"name"},
		Rows:    [][]string{{"nvme0n1"}},
	}}}

	if err := writeReportExportWithMessage("ignored.csv", "iostat", "csv", r, sink); err != nil {
		t.Fatalf("writeReportExportWithMessage returned error: %v", err)
	}
	if len(sink.reqs) != 2 {
		t.Fatalf("sink should receive export data and message requests, got=%d", len(sink.reqs))
	}
	msg := sink.reqs[1]
	if !msg.ToStdout || msg.Format != internaloutput.FormatText {
		t.Fatalf("message should be written to stdout text sink: %#v", msg)
	}
	if string(msg.Data) != "已将iostat数据写入文件: ignored.csv\n" {
		t.Fatalf("message changed: %q", msg.Data)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func headerIndex(headers []string, name string) int {
	for i, header := range headers {
		if header == name {
			return i
		}
	}
	return -1
}
