package iostat

import (
	"fmt"
	modulebase "oswbb-analyse/internal/modules"
	reportbase "oswbb-analyse/internal/report"
	"strings"
)

// Reporter builds a module-local report object from structured analysis.
type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func BuildReport(analysis *Analysis) (*reportbase.Report, error) {
	return NewReporter().Build(analysis)
}

// Build creates a report object without changing judgement logic.
func (r *Reporter) Build(analysis *Analysis) (*reportbase.Report, error) {
	if analysis == nil {
		return nil, fmt.Errorf("iostat analysis 不能为空")
	}

	tables := append([]reportbase.Table(nil), analysis.Tables...)
	if len(tables) == 0 {
		tables = []reportbase.Table{{
			Title:   "设备列表",
			Headers: []string{"设备"},
			Rows:    deviceRows(analysis.Devices),
		}}
	}

	return &reportbase.Report{
		Title:  "OSWbb Analyse Report - iostat",
		Module: string(modulebase.ModuleIostat),
		Summary: []reportbase.SummaryItem{
			{Name: "时间范围", Value: fmt.Sprintf("%s ~ %s", analysis.Start.Format("2006-01-02 15:04:05"), analysis.End.Format("2006-01-02 15:04:05"))},
			{Name: "设备总数", Value: fmt.Sprintf("%d", len(analysis.Devices))},
			{Name: "采样点", Value: fmt.Sprintf("%d", analysis.DataPoints)},
			{Name: "诊断摘要", Value: findingsSummaryText(len(analysis.Findings))},
		},
		Sections: []reportbase.Section{{
			Title: "📋 设备列表",
			Body:  deviceListBody(analysis.Devices),
		}},
		Tables:      tables,
		Findings:    reportbase.FindingsFromLegacy(analysis.Findings),
		Suggestions: reportbase.SuggestionsFromDiagnosis(analysis.Diagnosis),
	}, nil
}

func findingsSummaryText(count int) string {
	if count == 0 {
		return "暂无规则诊断摘要"
	}
	return fmt.Sprintf("共 %d 条规则诊断摘要", count)
}

func deviceListBody(devices []string) string {
	if len(devices) == 0 {
		return "未发现可用设备\n"
	}
	var sb strings.Builder
	sb.WriteString("发现的设备:\n")
	for _, device := range devices {
		sb.WriteString("- " + device + "\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

func deviceRows(devices []string) [][]string {
	rows := make([][]string, 0, len(devices))
	for _, device := range devices {
		rows = append(rows, []string{device})
	}
	return rows
}
