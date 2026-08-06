package output

import (
	"encoding/csv"
	"oswbb-analyse/internal/report"
	"strings"
	"testing"
)

func TestCSVFormatterWritesSelectedTable(t *testing.T) {
	r := &report.Report{
		Tables: []report.Table{{
			Title:   "metrics",
			Headers: []string{"timestamp", "device", "note"},
			Rows: [][]string{{
				"2026-04-21 03:00:00",
				"nvme0n1",
				"comma, quote \" and\nnewline",
			}},
		}},
	}

	got, err := CSVFormatter{}.Format(r)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(string(got))).ReadAll()
	if err != nil {
		t.Fatalf("CSV should parse: %v\n%s", err, got)
	}
	if len(records) != 2 {
		t.Fatalf("expected header+row, got %d: %#v", len(records), records)
	}
	if strings.Join(records[0], "|") != "timestamp|device|note" {
		t.Fatalf("header order changed: %#v", records[0])
	}
	if records[1][2] != "comma, quote \" and\nnewline" {
		t.Fatalf("CSV should preserve escaped field, got %#v", records[1][2])
	}
}

func TestCSVFormatterRejectsAmbiguousTables(t *testing.T) {
	r := &report.Report{Tables: []report.Table{{Title: "a"}, {Title: "b"}}}
	if _, err := (CSVFormatter{}).Format(r); err == nil {
		t.Fatal("multiple tables without TableName should return an error")
	}
}

func TestCSVFormatterSelectsNamedTable(t *testing.T) {
	r := &report.Report{Tables: []report.Table{
		{Title: "a", Headers: []string{"a"}, Rows: [][]string{{"1"}}},
		{Title: "b", Headers: []string{"b"}, Rows: [][]string{{"2"}}},
	}}
	got, err := CSVFormatter{TableName: "b"}.Format(r)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	if !strings.HasPrefix(string(got), "b\n2\n") {
		t.Fatalf("wrong table selected:\n%s", got)
	}
}

func TestCSVFormatterHandlesEmptyReport(t *testing.T) {
	if _, err := (CSVFormatter{}).Format(&report.Report{}); err != nil {
		t.Fatalf("empty report should not fail: %v", err)
	}
}
