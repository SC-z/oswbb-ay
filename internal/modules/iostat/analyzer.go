package iostat

import (
	"fmt"
	reportbase "oswbb-analyse/internal/report"
	legacyfindings "oswbb-analyse/pkg/findings"
	legacyoutput "oswbb-analyse/pkg/output"
	"sort"
	"time"
)

// Analyzer converts parsed iostat data into structured analysis.
type Analyzer struct {
	Config Config
}

func NewAnalyzer(cfg Config) *Analyzer {
	return &Analyzer{Config: cfg}
}

// Analyze reuses pkg/findings for judgement logic and keeps this layer side-effect free.
func (a *Analyzer) Analyze(data *ParsedData) (*Analysis, error) {
	if data == nil || data.Log == nil {
		return a.AnalyzeRange(data, time.Time{}, time.Time{})
	}
	start, end := data.Log.GetTimeRange()
	return a.AnalyzeRange(data, start, end)
}

func (a *Analyzer) AnalyzeRange(data *ParsedData, start, end time.Time) (*Analysis, error) {
	if data == nil {
		return nil, fmt.Errorf("iostat parsed data 不能为空")
	}
	if data.Log == nil {
		return nil, fmt.Errorf("iostat parsed log 不能为空")
	}
	if len(data.Log.Data) == 0 {
		return nil, fmt.Errorf("iostat parsed log 没有采样数据")
	}

	if start.IsZero() && end.IsZero() {
		start, end = data.Log.GetTimeRange()
	}
	devices := data.Log.GetAllDevices()
	sort.Strings(devices)

	return &Analysis{
		Start:      start,
		End:        end,
		Devices:    devices,
		DataPoints: len(data.Log.Data),
		Tables: []reportbase.Table{
			legacyoutput.IOStatRawMetricsTable(legacyoutput.ConvertIOStatData(data.Log, start, end)),
		},
		Findings: legacyfindings.BuildIOStatFindingsWithConfig(data.Log, start, end, a.Config),
	}, nil
}
