package output

import (
	"oswbb-analyse/pkg/findings"
	"strings"
	"testing"
)

func TestRenderTextReportHeaderAndOverview(t *testing.T) {
	header := RenderTextReportHeader("iostat")
	for _, want := range []string{
		"OSWbb Analyse Report - iostat",
		"================================================================================",
	} {
		if !strings.Contains(header, want) {
			t.Fatalf("report header missing %q:\n%s", want, header)
		}
	}

	overview := RenderTextOverview("分析概览", []TextLine{
		{Label: "时间范围", Value: "2026-04-21 03:29:12 ~ 2026-04-21 03:29:12"},
		{Label: "设备总数", Value: "1"},
	})
	for _, want := range []string{
		"📊 分析概览",
		"时间范围: 2026-04-21 03:29:12 ~ 2026-04-21 03:29:12",
		"设备总数: 1",
		"┌",
		"└",
	} {
		if !strings.Contains(overview, want) {
			t.Fatalf("overview missing %q:\n%s", want, overview)
		}
	}
}

func TestRenderFindingsSummaryKeepsRiskAndCandidateLabels(t *testing.T) {
	text := RenderFindingsSummary([]findings.Finding{{
		RuleID:   "top-process-high-cpu",
		Source:   "top",
		Category: "process",
		Severity: findings.SeverityMedium,
		Title:    "高 CPU 进程线索",
		Summary:  "进程 CPU 使用率高，需要结合系统 CPU 压力判断。",
	}})

	for _, want := range []string{
		"📌 规则诊断摘要",
		"=== 异常摘要 ===",
		"- [中][候选线索] 高 CPU 进程线索",
		"来源=top",
		"进程 CPU 使用率高，需要结合系统 CPU 压力判断。",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("findings summary missing %q:\n%s", want, text)
		}
	}
}
