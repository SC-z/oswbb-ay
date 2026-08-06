package processor

import (
	"context"
	"fmt"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/logging"
	moduletop "oswbb-analyse/internal/modules/top"
	reportbase "oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/findings"
	"oswbb-analyse/pkg/output"
	"oswbb-analyse/pkg/top"
	"sort"
	"strings"
	"time"
)

// analyzeTopLog 根据配置分析 top 日志
func analyzeTopLog(log *top.TopLog, opts analysisOptions) error {
	opts = withDefaultAnalysisConfigs(opts)
	return executeAnalysisTemplate(log, opts,
		func(start, end time.Time) {
			printTopReport(log, start, end, opts.topConfig)
		},
		func(start, end time.Time, formatter output.OutputFormatter) error {
			rawMetrics := output.ConvertTopData(log, start, end)

			ext := outputFileExt(opts.outputFormat)
			filename := analysisOutputFilename("top", opts.hostname, ext)
			if useReportFormatterForExport(opts.outputFormat) {
				report, err := opts.buildTopReport(log, start, end)
				if err != nil {
					return err
				}
				report.Title = "OSWbb Top 分析报告"
				if opts.outputFormat == "html" {
					if err := prepareHTMLExportReport(report, "top", rawMetrics, opts.aiDiagnosis); err != nil {
						return err
					}
				}
				return writeReportExportWithMessage(filename, "top", opts.outputFormat, report, opts.outputSink)
			}
			topFindings := findings.BuildTopFindingsWithConfig(log, start, end, opts.topConfig)
			return formatter.OutputTopData(output.TopExport{
				Data:        rawMetrics,
				AIDiagnosis: opts.aiDiagnosis,
				Findings:    topFindings,
			}, filename)
		},
	)
}

func (opts analysisOptions) buildTopReport(log *top.TopLog, start, end time.Time) (*reportbase.Report, error) {
	if opts.reportRunner != nil && opts.reportBundle != nil {
		return opts.reportRunner.BuildModuleReport(context.Background(), core.FileTypeTop, opts.reportBundle, core.TimeRange{Start: start, End: end}, opts.reportConfig(), opts.aiDiagnosis)
	}
	analysis, err := moduletop.NewAnalyzer(opts.topConfig).AnalyzeRange(&moduletop.ParsedData{Log: log}, start, end)
	if err != nil {
		return nil, err
	}
	analysis.Diagnosis = opts.aiDiagnosis
	return moduletop.BuildReport(analysis)
}

// printTopReport 打印 top 报告模式详情
func printTopReport(log *top.TopLog, startTime, endTime time.Time, cfgs ...config.TopConfig) {
	cfg := config.Default().Top
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}
	data := filterTopRange(log.Snapshots, startTime, endTime)
	if len(data) == 0 {
		logging.Default().Infof("指定时间范围内无 top 数据")
		return
	}

	// 统计 Load Average
	load1Stats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.Load1 })
	load5Stats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.Load5 })
	load15Stats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.Load15 })

	// 统计 CPU
	cpuUserStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.CpuUser })
	cpuSysStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.CpuSys })
	cpuIdleStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.CpuIdle })
	cpuWaitStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.CpuWait })
	cpuStealStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return s.CpuSteal })

	// 统计 Tasks
	taskRunningStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return float64(s.TaskRunning) })
	taskZombieStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return float64(s.TaskZombie) })

	var body strings.Builder
	body.WriteString("[Load Average 负载]\n")
	fmt.Fprintf(&body, "  Load 1min : Min=%.2f, Max=%.2f, Avg=%.2f\n", load1Stats.Min, load1Stats.Max, load1Stats.Avg)
	fmt.Fprintf(&body, "  Load 5min : Min=%.2f, Max=%.2f, Avg=%.2f\n", load5Stats.Min, load5Stats.Max, load5Stats.Avg)
	fmt.Fprintf(&body, "  Load 15min: Min=%.2f, Max=%.2f, Avg=%.2f\n", load15Stats.Min, load15Stats.Max, load15Stats.Avg)

	body.WriteString("\n[CPU 使用率 %\n")
	fmt.Fprintf(&body, "  User : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuUserStats.Min, cpuUserStats.Max, cpuUserStats.Avg)
	fmt.Fprintf(&body, "  Sys  : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuSysStats.Min, cpuSysStats.Max, cpuSysStats.Avg)
	fmt.Fprintf(&body, "  Idle : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuIdleStats.Min, cpuIdleStats.Max, cpuIdleStats.Avg)
	fmt.Fprintf(&body, "  Wait : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuWaitStats.Min, cpuWaitStats.Max, cpuWaitStats.Avg)
	fmt.Fprintf(&body, "  Steal: Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuStealStats.Min, cpuStealStats.Max, cpuStealStats.Avg)

	body.WriteString("\n[Tasks 进程状态]\n")
	fmt.Fprintf(&body, "  Running : Min=%.0f, Max=%.0f, Avg=%.1f\n", taskRunningStats.Min, taskRunningStats.Max, taskRunningStats.Avg)
	if taskZombieStats.Max > 0 {
		fmt.Fprintf(&body, "  Zombie  : Min=%.0f, Max=%.0f, Avg=%.1f (存在僵尸进程)\n", taskZombieStats.Min, taskZombieStats.Max, taskZombieStats.Avg)
	} else {
		body.WriteString("  Zombie  : 无僵尸进程\n")
	}

	body.WriteString(formatTopProcessCandidates(data))

	// 查找高负载时刻
	body.WriteString(formatHighLoadMoments(data))

	topFindings := findings.BuildTopFindingsWithConfig(log, startTime, endTime, cfg)
	// Compatibility path: detailed top text body stays here until the legacy
	// console report is retired or moved wholesale into the module.
	report, err := moduletop.BuildReport(&moduletop.Analysis{
		Start:      startTime,
		End:        endTime,
		DataPoints: len(data),
		Summary: []reportbase.SummaryItem{
			{Name: "时间范围", Value: fmt.Sprintf("%s ~ %s", startTime.Format(TimeLayout), endTime.Format(TimeLayout))},
			{Name: "采样数量", Value: fmt.Sprintf("%d", len(data))},
		},
		Sections: []reportbase.Section{{
			Title: "📈 系统指标摘要",
			Body:  body.String(),
		}},
		Tables:   []reportbase.Table{topProcessCandidateTable(data)},
		Findings: topFindings,
	})
	if err != nil {
		fmt.Println("生成 top 报告失败")
		return
	}
	textReport := *report
	textReport.Tables = nil
	if !printReportText(&textReport) {
		fmt.Println("生成 top 报告失败")
	}
}

type topReportProcessCandidate struct {
	at       time.Time
	process  top.ProcessStats
	reason   string
	priority int
}

func printTopProcessCandidates(data []top.TopSnapshot) {
	fmt.Print(formatTopProcessCandidates(data))
}

func formatTopProcessCandidates(data []top.TopSnapshot) string {
	candidates := collectTopProcessCandidates(data)
	if len(candidates) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n[代表进程候选]\n")
	sb.WriteString("  以下进程仅为候选线索，需要结合上方 CPU/load/memory/D/Z 状态证据判断。\n")
	for _, candidate := range candidates {
		process := candidate.process
		fmt.Fprintf(&sb, "  %s: %d/%s/%s/%s cpu=%.1f%% mem=%.1f%% res=%.1fMB reason=%s\n",
			candidate.at.Format(TimeShortLayout),
			process.PID,
			process.User,
			process.State,
			process.Command,
			process.CPUPercent,
			process.MemPercent,
			float64(process.ResKB)/1024.0,
			candidate.reason)
	}
	return sb.String()
}

func topProcessCandidateTable(data []top.TopSnapshot) reportbase.Table {
	candidates := collectTopProcessCandidates(data)
	rows := make([][]string, 0, len(candidates))
	for _, candidate := range candidates {
		process := candidate.process
		rows = append(rows, []string{
			candidate.at.Format(TimeShortLayout),
			fmt.Sprintf("%d", process.PID),
			process.User,
			process.State,
			process.Command,
			fmt.Sprintf("%.1f", process.CPUPercent),
			fmt.Sprintf("%.1f", process.MemPercent),
			fmt.Sprintf("%.1f", float64(process.ResKB)/1024.0),
			candidate.reason,
		})
	}
	return reportbase.Table{
		Title:   "代表进程候选",
		Headers: []string{"时间", "PID", "USER", "STATE", "COMMAND", "CPU%", "MEM%", "RES(MB)", "reason"},
		Rows:    rows,
	}
}

func collectTopProcessCandidates(data []top.TopSnapshot) []topReportProcessCandidate {
	var candidates []topReportProcessCandidate
	for _, snap := range data {
		for _, process := range snap.Processes {
			reason, priority, selected := topReportProcessReason(process)
			if !selected {
				continue
			}
			candidates = append(candidates, topReportProcessCandidate{
				at:       snap.Timestamp,
				process:  process,
				reason:   reason,
				priority: priority,
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		if candidates[i].process.CPUPercent != candidates[j].process.CPUPercent {
			return candidates[i].process.CPUPercent > candidates[j].process.CPUPercent
		}
		if candidates[i].process.MemPercent != candidates[j].process.MemPercent {
			return candidates[i].process.MemPercent > candidates[j].process.MemPercent
		}
		if !candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].at.Before(candidates[j].at)
		}
		return candidates[i].process.PID < candidates[j].process.PID
	})
	if len(candidates) > 5 {
		candidates = candidates[:5]
	}
	return candidates
}

func topReportProcessReason(process top.ProcessStats) (string, int, bool) {
	switch {
	case process.State == "D":
		return "d_state", 400, true
	case process.State == "Z":
		return "zombie", 300, true
	case process.CPUPercent >= 50:
		return "high_cpu", 200, true
	case process.MemPercent >= 5:
		return "high_mem", 100, true
	default:
		return "", 0, false
	}
}

// simpleStats 简单统计结构
type simpleStats struct {
	Min, Max, Avg float64
}

// calculateTopStats 计算统计信息
func calculateTopStats(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64) simpleStats {
	if len(data) == 0 {
		return simpleStats{}
	}

	minVal := extractor(data[0])
	maxVal := minVal
	sum := 0.0

	for _, d := range data {
		val := extractor(d)
		if val < minVal {
			minVal = val
		}
		if val > maxVal {
			maxVal = val
		}
		sum += val
	}

	return simpleStats{
		Min: minVal,
		Max: maxVal,
		Avg: sum / float64(len(data)),
	}
}

// printHighLoadMoments 打印负载最高的几个时刻
func printHighLoadMoments(data []top.TopSnapshot) {
	fmt.Print(formatHighLoadMoments(data))
}

func formatHighLoadMoments(data []top.TopSnapshot) string {
	// 复制一份数据用于排序
	sortedData := make([]top.TopSnapshot, len(data))
	copy(sortedData, data)

	// 按 Load1 降序排序
	sort.Slice(sortedData, func(i, j int) bool {
		return sortedData[i].Load1 > sortedData[j].Load1
	})

	count := 3
	if len(sortedData) < count {
		count = len(sortedData)
	}

	var sb strings.Builder
	sb.WriteString("\n[Load 1min 最高时刻 Top 3]\n")
	for i := 0; i < count; i++ {
		d := sortedData[i]
		fmt.Fprintf(&sb, "  %s: Load1=%.2f, User=%.1f%%, Sys=%.1f%%, Wait=%.1f%%\n",
			d.Timestamp.Format(TimeShortLayout), d.Load1, d.CpuUser, d.CpuSys, d.CpuWait)
	}
	return sb.String()
}

// filterTopRange 过滤时间范围
func filterTopRange(data []top.TopSnapshot, start, end time.Time) []top.TopSnapshot {
	var result []top.TopSnapshot
	for _, d := range data {
		if (d.Timestamp.Equal(start) || d.Timestamp.After(start)) && (d.Timestamp.Equal(end) || d.Timestamp.Before(end)) {
			result = append(result, d)
		}
	}
	return result
}

// AnalyzeTopFile 分析单个top文件
func AnalyzeTopFile(filename, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	parser := top.NewTopParser()
	log, err := parser.ParseFile(filename)
	if err != nil {
		return fmt.Errorf("解析top文件失败: %v", err)
	}

	opts := analysisOptions{
		outputFormat: outputFormat,
		startTimeStr: startTimeStr,
		endTimeStr:   endTimeStr,
		location:     cst,
		introLines: []string{
			"成功解析top日志",
			fmt.Sprintf("总共 %d 个数据点", len(log.Snapshots)),
		},
		rangeScope: "文件",
	}

	return analyzeTopLog(log, opts)
}

// AnalyzeMergedTopFiles 合并分析多个top文件
func AnalyzeMergedTopFiles(filenames []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	parser := top.NewTopParser()

	var allSnapshots []top.TopSnapshot
	var parseErrs []error

	for _, filename := range filenames {
		log, err := parser.ParseFile(filename)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("解析文件失败 %s: %v", filename, err))
			continue
		}
		allSnapshots = append(allSnapshots, log.Snapshots...)
	}

	if len(parseErrs) > 0 {
		logParseErrors(parseErrs)
	}

	if len(allSnapshots) == 0 {
		return fmt.Errorf("没有有效的数据可以分析")
	}

	// 按时间排序
	sort.Slice(allSnapshots, func(i, j int) bool {
		return allSnapshots[i].Timestamp.Before(allSnapshots[j].Timestamp)
	})

	mergedLog := &top.TopLog{Snapshots: allSnapshots}

	opts := analysisOptions{
		outputFormat:      outputFormat,
		startTimeStr:      startTimeStr,
		endTimeStr:        endTimeStr,
		location:          cst,
		introLines:        []string{fmt.Sprintf("成功合并 %d 个文件，总共 %d 个数据点", len(filenames), len(mergedLog.Snapshots))},
		leadingBlankIntro: true,
		rangeScope:        "合并数据",
	}

	return analyzeTopLog(mergedLog, opts)
}
