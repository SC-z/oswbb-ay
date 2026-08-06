package summary

import (
	"fmt"
	"oswbb-analyse/internal/report"
	legacyfindings "oswbb-analyse/pkg/findings"
	"sort"
	"strings"
)

type Service struct{}

func (Service) Build(input Input) (*report.Report, error) {
	items := append([]Finding{}, input.Findings...)
	for _, r := range input.Reports {
		items = append(items, findingsFromReport(r)...)
	}
	sortFindings(items)

	body := buildBody(items)
	return &report.Report{
		Title:  "主机级结论",
		Module: "host",
		Sections: []report.Section{{
			Title: "主机级结论",
			Body:  body,
		}},
	}, nil
}

func findingsFromReport(r *report.Report) []Finding {
	if r == nil {
		return nil
	}
	items := make([]Finding, 0, len(r.Findings))
	for _, item := range r.Findings {
		items = append(items, Finding{
			Severity: item.Severity,
			Nature:   item.Nature,
			Title:    item.Title,
			Source:   r.Module,
		})
	}
	return items
}

func buildBody(items []Finding) string {
	if len(items) == 0 {
		return "未发现主机级风险信号\n"
	}

	riskCount, candidateCount := countNatures(items)
	var sb strings.Builder
	fmt.Fprintf(&sb, "风险信号=%d 候选线索=%d\n", riskCount, candidateCount)
	sb.WriteString("关键风险/线索:\n")
	limit := minInt(len(items), 3)
	for index := 0; index < limit; index++ {
		item := items[index]
		fmt.Fprintf(&sb, "%d. [%s][%s] %s", index+1, severityLabel(item.Severity), natureLabel(item.Nature), item.Title)
		if item.Target != "" {
			fmt.Fprintf(&sb, " (%s/%s)", item.Source, item.Target)
		} else {
			fmt.Fprintf(&sb, " (%s)", item.Source)
		}
		if item.Time != "" {
			fmt.Fprintf(&sb, " @ %s", item.Time)
		}
		sb.WriteString("\n")
	}
	if targets := priorityTargets(items, 3); len(targets) > 0 {
		fmt.Fprintf(&sb, "建议优先查看: %s\n", strings.Join(targets, ", "))
	}
	return sb.String()
}

func sortFindings(items []Finding) {
	sort.SliceStable(items, func(i, j int) bool {
		if natureRank(items[i].Nature) != natureRank(items[j].Nature) {
			return natureRank(items[i].Nature) < natureRank(items[j].Nature)
		}
		if items[i].Severity != items[j].Severity {
			return severityRank(items[i].Severity) < severityRank(items[j].Severity)
		}
		return items[i].RuleID < items[j].RuleID
	})
}

func sortLegacyFindings(items []legacyfindings.Finding) {
	sort.SliceStable(items, func(i, j int) bool {
		left := Finding{Severity: string(items[i].Severity), Nature: string(resolvedLegacyNature(items[i])), RuleID: items[i].RuleID}
		right := Finding{Severity: string(items[j].Severity), Nature: string(resolvedLegacyNature(items[j])), RuleID: items[j].RuleID}
		if natureRank(left.Nature) != natureRank(right.Nature) {
			return natureRank(left.Nature) < natureRank(right.Nature)
		}
		if left.Severity != right.Severity {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		return left.RuleID < right.RuleID
	})
}

func countNatures(items []Finding) (riskCount, candidateCount int) {
	for _, item := range items {
		if normalizedNature(item.Nature) == "candidate" || item.Nature == "候选线索" {
			candidateCount++
			continue
		}
		riskCount++
	}
	return riskCount, candidateCount
}

func priorityTargets(items []Finding, limit int) []string {
	targets := make([]string, 0, limit)
	seen := make(map[string]struct{})
	for _, item := range items {
		target := item.Source
		if item.Target != "" {
			target += "/" + item.Target
		}
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
		if len(targets) >= limit {
			break
		}
	}
	return targets
}

func natureRank(nature string) int {
	if normalizedNature(nature) == "risk" || nature == "风险信号" || nature == "" {
		return 0
	}
	return 1
}

func severityRank(severity string) int {
	switch normalizedSeverity(severity) {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func severityLabel(severity string) string {
	switch normalizedSeverity(severity) {
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	default:
		return "信息"
	}
}

func natureLabel(nature string) string {
	if normalizedNature(nature) == "candidate" || nature == "候选线索" {
		return "候选线索"
	}
	return "风险信号"
}

func normalizedSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "高":
		return "high"
	case "中":
		return "medium"
	case "低":
		return "low"
	default:
		return strings.ToLower(strings.TrimSpace(severity))
	}
}

func normalizedNature(nature string) string {
	switch strings.TrimSpace(nature) {
	case "风险信号":
		return "risk"
	case "候选线索":
		return "candidate"
	default:
		return strings.ToLower(strings.TrimSpace(nature))
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
