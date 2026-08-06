package output

import (
	"fmt"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/pkg/findings"
	"strings"
)

// TextLine is the legacy alias for internal/output.TextLine.
//
// Deprecated: new code should use internal/output.TextLine directly.
type TextLine = internaloutput.TextLine

// RenderTextReportHeader delegates to internal/output.
//
// Deprecated: new code should use internal/output.RenderTextReportHeader.
func RenderTextReportHeader(module string) string {
	return internaloutput.RenderTextReportHeader(module)
}

// RenderTextOverview delegates to internal/output.
//
// Deprecated: new code should use internal/output.RenderTextOverview.
func RenderTextOverview(title string, lines []TextLine) string {
	return internaloutput.RenderTextOverview(title, lines)
}

// RenderTextSectionTitle delegates to internal/output.
//
// Deprecated: new code should use internal/output.RenderTextSectionTitle.
func RenderTextSectionTitle(title string) string {
	return internaloutput.RenderTextSectionTitle(title)
}

// RenderTextBox delegates to internal/output.
//
// Deprecated: new code should use internal/output.RenderTextBox.
func RenderTextBox(title string, lines []string) string {
	return internaloutput.RenderTextBox(title, lines)
}

// RenderFindingsSummary 渲染规则诊断摘要。保留旧标题作为兼容锚点。
//
// Deprecated: new code should build findings into internal/report.Report and
// format it with internal/output.TextFormatter.
func RenderFindingsSummary(items []findings.Finding) string {
	var sb strings.Builder
	sb.WriteString(RenderTextSectionTitle("📌 规则诊断摘要"))
	sb.WriteString("=== 异常摘要 ===\n")

	lines := []string{}
	if len(items) == 0 {
		lines = append(lines, "未发现明显异常")
	} else {
		for index, item := range items {
			if index > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("- [%s][%s] %s",
				findingSeverityLabel(item.Severity),
				findingNatureLabel(item),
				item.Title))
			lines = append(lines, "  "+findingMetaLine(item))
			if item.Summary != "" {
				lines = append(lines, "  "+item.Summary)
			}
		}
	}

	sb.WriteString(RenderTextBox("", lines))
	return sb.String()
}

func findingMetaLine(item findings.Finding) string {
	parts := []string{"来源=" + item.Source}
	if item.Target != "" {
		parts = append(parts, "对象="+item.Target)
	}
	if item.Time != "" {
		parts = append(parts, "时间="+item.Time)
	} else if item.WindowStart != "" || item.WindowEnd != "" {
		parts = append(parts, "时间窗口="+item.WindowStart+"~"+item.WindowEnd)
	}
	if item.Metric != "" {
		parts = append(parts, "指标="+item.Metric)
	}
	if item.Operator != "" {
		parts = append(parts, "条件="+item.Operator)
	}
	if item.ObservedValue != 0 {
		parts = append(parts, fmt.Sprintf("观测=%.2f", item.ObservedValue))
	}
	if item.Threshold != 0 {
		parts = append(parts, fmt.Sprintf("阈值=%.2f", item.Threshold))
	}
	return strings.Join(parts, " ")
}

func findingNatureLabel(item findings.Finding) string {
	nature := item.Nature
	if nature == "" {
		nature = findings.InferFindingNature(item)
	}
	switch nature {
	case findings.FindingNatureCandidate:
		return "候选线索"
	case findings.FindingNatureRisk:
		return "风险信号"
	default:
		return "风险信号"
	}
}

func findingSeverityLabel(severity findings.Severity) string {
	switch severity {
	case findings.SeverityHigh:
		return "高"
	case findings.SeverityMedium:
		return "中"
	case findings.SeverityLow:
		return "低"
	default:
		return "信息"
	}
}
