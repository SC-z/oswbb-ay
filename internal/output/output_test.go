package output

import (
	"encoding/json"
	"oswbb-analyse/internal/report"
	"strings"
	"testing"
)

func TestTextFormatterRendersReport(t *testing.T) {
	r := sampleReport()

	got, err := TextFormatter{}.Format(r)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	text := string(got)
	for _, want := range []string{
		"OSWbb Analyse Report - iostat",
		"📊 分析概览",
		"时间范围: 2026-04-21 03:00:04 ~ 2026-04-21 03:00:06",
		"📋 设备列表",
		"发现的设备:",
		"=== 异常摘要 ===",
		"[高][风险信号] 写延迟突增",
		"对象=nvme0n1",
		"write_await 高于阈值",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("text report missing %q:\n%s", want, text)
		}
	}
}

func TestJSONFormatterRendersReport(t *testing.T) {
	r := sampleReport()

	got, err := JSONFormatter{}.Format(r)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}

	var decoded report.Report
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("JSON output should decode: %v\n%s", err, got)
	}
	if decoded.Module != "iostat" || decoded.Findings[0].Title != "写延迟突增" {
		t.Fatalf("decoded report mismatch: %+v", decoded)
	}
}

func TestJSONFormatterRendersAllModuleReports(t *testing.T) {
	for _, module := range []string{"iostat", "meminfo", "top"} {
		r := sampleReport()
		r.Module = module

		got, err := JSONFormatter{}.Format(r)
		if err != nil {
			t.Fatalf("Format(%s) returned error: %v", module, err)
		}

		var decoded report.Report
		if err := json.Unmarshal(got, &decoded); err != nil {
			t.Fatalf("%s JSON output should decode: %v\n%s", module, err, got)
		}
		if decoded.Module != module {
			t.Fatalf("decoded module = %q, want %q", decoded.Module, module)
		}
	}
}

func TestFormattersHandleEmptyReport(t *testing.T) {
	if _, err := (TextFormatter{}).Format(&report.Report{}); err != nil {
		t.Fatalf("TextFormatter empty report should not fail: %v", err)
	}
	if _, err := (JSONFormatter{}).Format(&report.Report{}); err != nil {
		t.Fatalf("JSONFormatter empty report should not fail: %v", err)
	}
}

func sampleReport() *report.Report {
	return &report.Report{
		Title:  "OSWbb Analyse Report - iostat",
		Module: "iostat",
		Summary: []report.SummaryItem{{
			Name:  "时间范围",
			Value: "2026-04-21 03:00:04 ~ 2026-04-21 03:00:06",
		}},
		Sections: []report.Section{{
			Title: "📋 设备列表",
			Body:  "发现的设备:\n- nvme0n1\n",
		}},
		Findings: []report.Finding{{
			Severity: "高",
			Nature:   "风险信号",
			Title:    "写延迟突增",
			Detail:   "write_await 高于阈值",
			Evidence: "对象=nvme0n1",
		}},
	}
}
