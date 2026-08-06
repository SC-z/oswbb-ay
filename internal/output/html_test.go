package output

import (
	"oswbb-analyse/internal/report"
	"strings"
	"testing"
)

func TestHTMLFormatterEscapesReportFields(t *testing.T) {
	r := &report.Report{
		Title:  `OSWbb <Report>`,
		Module: "iostat",
		Summary: []report.SummaryItem{{
			Name:  `host<script>`,
			Value: `rdsmaster&1`,
		}},
		Sections: []report.Section{{
			Title: `section <one>`,
			Body:  `body & detail`,
		}},
		Tables: []report.Table{{
			Title:   `table "metrics"`,
			Headers: []string{`device`, `value<ms>`},
			Rows:    [][]string{{`nvme"0`, `3 < 5`}},
		}},
		Findings: []report.Finding{{
			Severity: "高",
			Nature:   "候选线索",
			Title:    `latency <spike>`,
			Detail:   `detail & context`,
			Evidence: `对象=nvme<0>`,
		}},
		Suggestions: []report.Suggestion{{
			Title:  `next <check>`,
			Detail: `check "backend"`,
		}},
	}

	got, err := HTMLFormatter{}.Format(r)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	text := string(got)
	for _, want := range []string{
		"OSWbb &lt;Report&gt;",
		"host&lt;script&gt;",
		"rdsmaster&amp;1",
		"section &lt;one&gt;",
		"body &amp; detail",
		"table &#34;metrics&#34;",
		"value&lt;ms&gt;",
		"3 &lt; 5",
		"latency &lt;spike&gt;",
		"对象=nvme&lt;0&gt;",
		"next &lt;check&gt;",
		"check &#34;backend&#34;",
		`<section class="diagnosis-panel">`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("HTML missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{
		"OSWbb <Report>",
		"host<script>",
		"对象=nvme<0>",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("HTML should escape %q:\n%s", forbidden, text)
		}
	}
}

func TestHTMLFormatterHandlesEmptyReport(t *testing.T) {
	if _, err := (HTMLFormatter{}).Format(&report.Report{}); err != nil {
		t.Fatalf("empty report should not fail: %v", err)
	}
}

func TestHTMLFormatterUsesDashboardMetadataAndEscapesFindings(t *testing.T) {
	r := &report.Report{
		Title:  `OSWbb <IOStat>`,
		Module: "iostat",
		Findings: []report.Finding{{
			Severity: "高",
			Nature:   "风险信号",
			Title:    `latency <spike>`,
			Evidence: `对象=nvme<0>`,
		}},
		Metadata: map[string]string{
			"html.data_type": "iostat",
			"html.raw_data":  `[{"timestamp":"t1","device":"nvme0n1","read_req_per_sec":1}]`,
		},
	}

	got, err := HTMLFormatter{}.Format(r)
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	text := string(got)
	for _, want := range []string{
		`<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>`,
		`const dataType = "iostat";`,
		`const rawData = [{"timestamp":"t1","device":"nvme0n1","read_req_per_sec":1}];`,
		`<section class="diagnosis-panel">`,
		`OSWbb &lt;IOStat&gt;`,
		`latency &lt;spike&gt;`,
		`对象=nvme&lt;0&gt;`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("dashboard HTML missing %q:\n%s", want, text)
		}
	}
}
