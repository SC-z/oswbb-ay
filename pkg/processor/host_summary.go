package processor

import (
	"fmt"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/summary"
	"oswbb-analyse/pkg/findings"
	"strings"
	"time"
)

type hostSummaryTimeRangeProvider interface {
	GetTimeRange() (time.Time, time.Time)
}

func printHostLevelSummary(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location, cfg config.Config) {
	text, err := renderHostLevelSummaryText(bundle, startTimeStr, endTimeStr, cst, cfg)
	if err != nil {
		fmt.Printf("主机级结论生成失败: %v\n", err)
		return
	}
	fmt.Print(text)
}

func renderHostLevelSummaryText(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location, cfg config.Config) (string, error) {
	items := collectBundleFindings(bundle, startTimeStr, endTimeStr, cst, cfg)
	report, err := (summary.Service{}).Build(summary.Input{Findings: summary.FindingsFromLegacy(items)})
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("\n=== 主机级结论 ===\n")
	for _, section := range report.Sections {
		b.WriteString(section.Body)
	}
	return b.String(), nil
}

func collectBundleFindings(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location, cfg config.Config) []findings.Finding {
	if bundle == nil {
		return nil
	}
	if cfg == (config.Config{}) {
		cfg = config.Default()
	}

	var items []findings.Finding
	if bundle.IOStat != nil {
		if start, end, err := moduleTimeRange(bundle.IOStat, startTimeStr, endTimeStr, cst); err == nil {
			items = append(items, findings.BuildIOStatFindingsWithConfig(bundle.IOStat, start, end, cfg.Iostat)...)
		}
	}
	if bundle.MemInfo != nil {
		if start, end, err := moduleTimeRange(bundle.MemInfo, startTimeStr, endTimeStr, cst); err == nil {
			items = append(items, findings.BuildMemInfoFindingsWithConfig(bundle.MemInfo, start, end, cfg.Meminfo)...)
		}
	}
	if bundle.Top != nil {
		if start, end, err := moduleTimeRange(bundle.Top, startTimeStr, endTimeStr, cst); err == nil {
			items = append(items, findings.BuildTopFindingsWithConfig(bundle.Top, start, end, cfg.Top)...)
		}
	}

	summary.SortLegacyFindings(items)
	return items
}

func moduleTimeRange(log hostSummaryTimeRangeProvider, startTimeStr, endTimeStr string, cst *time.Location) (time.Time, time.Time, error) {
	start, end, _, err := resolveTimeRange(log, startTimeStr, endTimeStr, cst)
	return start, end, err
}
