package output

import (
	"fmt"
	"testing"
)

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		format Format
		want   string
	}{
		{FormatText, "output.TextFormatter"},
		{FormatJSON, "output.JSONFormatter"},
		{FormatHTML, "output.HTMLFormatter"},
		{FormatCSV, "output.CSVFormatter"},
	}
	for _, tc := range tests {
		formatter, err := NewFormatter(tc.format)
		if err != nil {
			t.Fatalf("NewFormatter(%q) returned error: %v", tc.format, err)
		}
		if got := fmt.Sprintf("%T", formatter); got != tc.want {
			t.Fatalf("NewFormatter(%q) = %s, want %s", tc.format, got, tc.want)
		}
	}
}

func TestNewFormatterRejectsUnknownFormat(t *testing.T) {
	if _, err := NewFormatter("xml"); err == nil {
		t.Fatal("unknown format should return an error")
	}
}
