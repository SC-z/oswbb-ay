package meminfo

import (
	"fmt"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
)

// Reporter builds a meminfo report object without changing existing output.
type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func BuildReport(analysis *Analysis) (*reportbase.Report, error) {
	return NewReporter().Build(analysis)
}

func (r *Reporter) Build(analysis *Analysis) (*reportbase.Report, error) {
	if analysis == nil {
		return nil, fmt.Errorf("meminfo analysis 不能为空")
	}

	summary := append([]reportbase.SummaryItem(nil), analysis.Summary...)
	if len(summary) == 0 {
		summary = []reportbase.SummaryItem{
			{Name: "时间范围", Value: fmt.Sprintf("%s ~ %s", analysis.Start.Format("2006-01-02 15:04:05"), analysis.End.Format("2006-01-02 15:04:05"))},
			{Name: "采样数量", Value: fmt.Sprintf("%d", analysis.DataPoints)},
			{Name: "诊断摘要", Value: findingsSummaryText(len(analysis.Findings))},
		}
	}

	return &reportbase.Report{
		Title:       "OSWbb Analyse Report - meminfo",
		Module:      string(modulebase.ModuleMeminfo),
		Summary:     summary,
		Sections:    append([]reportbase.Section(nil), analysis.Sections...),
		Tables:      append([]reportbase.Table(nil), analysis.Tables...),
		Findings:    reportbase.FindingsFromLegacy(analysis.Findings),
		Suggestions: reportbase.SuggestionsFromDiagnosis(analysis.Diagnosis),
		Metadata:    map[string]string{"findings_position": "before_sections"},
	}, nil
}

func findingsSummaryText(count int) string {
	if count == 0 {
		return "暂无规则诊断摘要"
	}
	return fmt.Sprintf("共 %d 条规则诊断摘要", count)
}
