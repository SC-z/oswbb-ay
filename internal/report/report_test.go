package report

import (
	"oswbb-analyse/pkg/diagnosis"
	"testing"
)

func TestReportObjectCarriesStructuredFields(t *testing.T) {
	r := Report{
		Title:  "OSWbb Analyse Report - iostat",
		Module: "iostat",
		Summary: []SummaryItem{{
			Name:  "设备总数",
			Value: "1",
			Level: "info",
		}},
		Sections: []Section{{
			Title: "设备列表",
			Body:  "- nvme0n1",
		}},
		Tables: []Table{{
			Title:   "设备",
			Headers: []string{"name"},
			Rows:    [][]string{{"nvme0n1"}},
		}},
		Findings: []Finding{{
			Severity: "高",
			Nature:   "风险信号",
			Title:    "写延迟突增",
			Detail:   "write_await 高于阈值",
			Evidence: "对象=nvme0n1",
		}},
		Suggestions: []Suggestion{{
			Title:  "检查存储",
			Detail: "查看后端延迟",
		}},
		Metadata: map[string]string{"host": "rdsmaster1"},
	}

	if r.Module != "iostat" || r.Summary[0].Value != "1" || r.Tables[0].Rows[0][0] != "nvme0n1" {
		t.Fatalf("report fields not preserved: %+v", r)
	}
}

func TestEmptyReportIsSafeToUse(t *testing.T) {
	var r Report
	if len(r.Summary) != 0 || len(r.Sections) != 0 || len(r.Findings) != 0 {
		t.Fatalf("empty report should use zero-value slices safely: %+v", r)
	}
}

func TestSuggestionsFromDiagnosis(t *testing.T) {
	result := diagnosis.ActiveResult("local", "/tmp/model", "summary", []diagnosis.Incident{{
		Classification: "iostat 写延迟",
		NextChecks:     []string{"检查后端存储延迟", "  ", "核对 qdfs IO 队列"},
	}}, 1)

	got := SuggestionsFromDiagnosis(result)
	if len(got) != 2 {
		t.Fatalf("expected 2 suggestions, got %+v", got)
	}
	if got[0].Title != "iostat 写延迟" || got[0].Detail != "检查后端存储延迟" {
		t.Fatalf("unexpected first suggestion: %+v", got[0])
	}
}
