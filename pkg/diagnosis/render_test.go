package diagnosis

import (
	"strings"
	"testing"
)

func TestFormatResultTextFallbackKeepsLegacyText(t *testing.T) {
	got := FormatResultText(FallbackResult("model", "runtime missing", 2))

	for _, want := range []string{
		"=== AI 辅助诊断 ===",
		"AI 诊断未生效，已回退到规则分析：runtime missing",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted fallback missing %q:\n%s", want, got)
		}
	}
}

func TestFormatResultTextActiveKeepsIncidentDetails(t *testing.T) {
	got := FormatResultText(ActiveResult("model", "runtime", "summary ok", []Incident{{
		Classification: "内存压力",
		Severity:       "warning",
		Confidence:     0.86,
		EvidenceIDs:    []string{"meminfo-available", "top-load"},
		NextChecks:     []string{"检查匿名内存增长来源", "检查 top 进程"},
	}}, 2))

	for _, want := range []string{
		"总结：summary ok",
		"1. 内存压力 [warning, confidence=0.86]",
		"证据: meminfo-available, top-load",
		"建议核查: 检查匿名内存增长来源；检查 top 进程",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted active result missing %q:\n%s", want, got)
		}
	}
}

func TestFormatResultTextActiveWithoutDetailsKeepsLegacyText(t *testing.T) {
	got := FormatResultText(ActiveResult("model", "runtime", "", nil, 0))

	if !strings.Contains(got, "模型本次未补充新的高置信结论。") {
		t.Fatalf("formatted active empty result = %q", got)
	}
}
