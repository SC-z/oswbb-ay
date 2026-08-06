package summary

import (
	"oswbb-analyse/internal/report"
	legacyfindings "oswbb-analyse/pkg/findings"
)

type Input struct {
	Reports  []*report.Report
	Findings []Finding
}

type Finding struct {
	Severity string
	Nature   string
	RuleID   string
	Title    string
	Source   string
	Target   string
	Time     string
}

func FindingsFromLegacy(items []legacyfindings.Finding) []Finding {
	result := make([]Finding, 0, len(items))
	for _, item := range items {
		result = append(result, Finding{
			Severity: string(item.Severity),
			Nature:   string(resolvedLegacyNature(item)),
			RuleID:   item.RuleID,
			Title:    item.Title,
			Source:   item.Source,
			Target:   item.Target,
			Time:     item.Time,
		})
	}
	return result
}

func SortLegacyFindings(items []legacyfindings.Finding) {
	sortLegacyFindings(items)
}

func resolvedLegacyNature(item legacyfindings.Finding) legacyfindings.FindingNature {
	if item.Nature != "" {
		return item.Nature
	}
	return legacyfindings.InferFindingNature(item)
}
