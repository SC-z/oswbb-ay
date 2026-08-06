package report

import (
	"oswbb-analyse/pkg/diagnosis"
	"strings"
)

type Report struct {
	Title       string            `json:"title,omitempty"`
	Module      string            `json:"module,omitempty"`
	Summary     []SummaryItem     `json:"summary,omitempty"`
	Sections    []Section         `json:"sections,omitempty"`
	Tables      []Table           `json:"tables,omitempty"`
	Findings    []Finding         `json:"findings,omitempty"`
	Suggestions []Suggestion      `json:"suggestions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type SummaryItem struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	Level string `json:"level,omitempty"`
}

type Suggestion struct {
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func SuggestionsFromDiagnosis(result diagnosis.AIResult) []Suggestion {
	var suggestions []Suggestion
	for _, incident := range result.Incidents {
		title := strings.TrimSpace(incident.Classification)
		if title == "" {
			title = "AI 诊断建议"
		}
		for _, check := range incident.NextChecks {
			detail := strings.TrimSpace(check)
			if detail == "" {
				continue
			}
			suggestions = append(suggestions, Suggestion{
				Title:  title,
				Detail: detail,
			})
		}
	}
	return suggestions
}
