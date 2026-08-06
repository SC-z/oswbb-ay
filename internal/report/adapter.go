package report

import (
	"fmt"
	legacyfindings "oswbb-analyse/pkg/findings"
	"strings"
)

func FindingsFromLegacy(items []legacyfindings.Finding) []Finding {
	result := make([]Finding, 0, len(items))
	for _, item := range items {
		result = append(result, Finding{
			Severity: severityLabel(item.Severity),
			Nature:   natureLabel(item),
			Title:    item.Title,
			Detail:   item.Summary,
			Evidence: findingEvidence(item),
		})
	}
	return result
}

func severityLabel(severity legacyfindings.Severity) string {
	switch severity {
	case legacyfindings.SeverityHigh:
		return "高"
	case legacyfindings.SeverityMedium:
		return "中"
	case legacyfindings.SeverityLow:
		return "低"
	default:
		return "信息"
	}
}

func natureLabel(item legacyfindings.Finding) string {
	nature := item.Nature
	if nature == "" {
		nature = legacyfindings.InferFindingNature(item)
	}
	if nature == legacyfindings.FindingNatureCandidate {
		return "候选线索"
	}
	return "风险信号"
}

func findingEvidence(item legacyfindings.Finding) string {
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
