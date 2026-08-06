package output

import (
	"os"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/findings"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTMLFormatterRendersAIFallbackCard(t *testing.T) {
	formatter := NewHTMLFormatter()
	filename := filepath.Join(t.TempDir(), "top_test.html")

	err := formatter.OutputTopData(TopExport{
		Data: []TopRawMetrics{
			{Timestamp: "2024-09-10 08:00:00", Load1: 3.2, CpuIdle: 18.5},
		},
		AIDiagnosis: diagnosis.AIResult{
			Enabled:        true,
			Status:         diagnosis.AIStatusFallback,
			FallbackReason: "AI 诊断未生效，已回退到规则分析",
		},
	}, filename)
	if err != nil {
		t.Fatalf("OutputTopData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取HTML文件失败: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, "AI 辅助诊断") || !strings.Contains(text, "已回退到规则分析") {
		t.Fatalf("HTML 未渲染 AI 摘要卡片: %s", text)
	}
}

func TestHTMLFormatterIOStatIncludesUtilizationMetric(t *testing.T) {
	formatter := NewHTMLFormatter()
	filename := filepath.Join(t.TempDir(), "iostat_test.html")

	err := formatter.OutputIOStatData(IOStatExport{
		Data: []IOStatRawMetrics{{
			Timestamp:   "2026-04-21 03:00:00",
			Device:      "nvme0n1",
			Utilization: 96.5,
		}},
	}, filename)
	if err != nil {
		t.Fatalf("OutputIOStatData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取HTML文件失败: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, "utilization") || !strings.Contains(text, "设备利用率 (%)") {
		t.Fatalf("HTML 未包含 iostat utilization 指标配置: %s", text)
	}
}

func TestHTMLFormatterRendersFindingsSummary(t *testing.T) {
	formatter := NewHTMLFormatter()
	filename := filepath.Join(t.TempDir(), "iostat_findings.html")

	err := formatter.OutputIOStatData(IOStatExport{
		Data: []IOStatRawMetrics{{
			Timestamp:  "2026-04-21 03:29:12",
			Device:     "nvme11n1",
			WriteAwait: 300.11,
		}},
		Findings: []findings.Finding{{
			RuleID:        "iostat-write-latency-nvme11n1",
			Source:        "iostat",
			Category:      "disk_latency",
			Severity:      findings.SeverityHigh,
			Nature:        findings.FindingNatureCandidate,
			Title:         "nvme11n1 写延迟存在突增",
			Summary:       "峰值时存在 IOPS，但未见队列或 iowait 系统级压力。",
			Target:        "nvme11n1",
			Metric:        "write_await_ms",
			ObservedValue: 300.11,
			Time:          "2026-04-21 03:29:12",
		}},
	}, filename)
	if err != nil {
		t.Fatalf("OutputIOStatData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取HTML文件失败: %v", err)
	}

	text := string(content)
	for _, want := range []string{
		"规则诊断摘要",
		"候选线索",
		"高",
		"nvme11n1 写延迟存在突增",
		"对象=nvme11n1",
		"时间=2026-04-21 03:29:12",
		"峰值时存在 IOPS",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("HTML 未渲染 finding 摘要 %q:\n%s", want, text)
		}
	}
}

func TestHTMLFormatterFindingsSummaryIsCollapsedByDefault(t *testing.T) {
	formatter := NewHTMLFormatter()
	filename := filepath.Join(t.TempDir(), "iostat_collapsible_findings.html")

	err := formatter.OutputIOStatData(IOStatExport{
		Data: []IOStatRawMetrics{{
			Timestamp:  "2026-04-21 03:29:12",
			Device:     "nvme11n1",
			WriteAwait: 300.11,
		}},
		Findings: []findings.Finding{{
			Source:   "iostat",
			Severity: findings.SeverityHigh,
			Nature:   findings.FindingNatureRisk,
			Title:    "sda 队列深度持续偏高",
			Summary:  "队列峰值持续偏高。",
		}},
	}, filename)
	if err != nil {
		t.Fatalf("OutputIOStatData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取HTML文件失败: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, `<details class="findings-summary">`) {
		t.Fatalf("规则诊断摘要应使用 details 作为可折叠容器:\n%s", text)
	}
	if !strings.Contains(text, `<summary>规则诊断摘要</summary>`) {
		t.Fatalf("规则诊断摘要应保留 summary 标题入口:\n%s", text)
	}
	if strings.Contains(text, `<details class="findings-summary" open>`) {
		t.Fatalf("规则诊断摘要默认应收起，不能带 open 属性:\n%s", text)
	}

	panelIndex := strings.Index(text, `<section class="diagnosis-panel">`)
	findingsIndex := strings.Index(text, `<details class="findings-summary">`)
	mainIndex := strings.Index(text, `<div id="main-container">`)
	if panelIndex == -1 || findingsIndex == -1 || mainIndex == -1 || !(panelIndex < findingsIndex && findingsIndex < mainIndex) {
		t.Fatalf("规则诊断摘要应放在 sticky header 之外，避免展开后遮挡监控图:\n%s", text)
	}
}
