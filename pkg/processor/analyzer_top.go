package processor

import (
	"fmt"
	"oswbb-analyse/pkg/output"
	"oswbb-analyse/pkg/top"
	"sort"
	"time"
)

// analyzeTopLog 根据配置分析 top 日志
func analyzeTopLog(log *top.TopLog, opts analysisOptions) error {
	return executeAnalysisTemplate(log, opts,
		func(start, end time.Time) {
			printTopReport(log, start, end)
		},
		func(start, end time.Time, formatter output.OutputFormatter) error {
			rawMetrics := output.ConvertTopData(log, start, end)

			ext := outputFileExt(opts.outputFormat)
			filename := fmt.Sprintf("top_%s.%s", time.Now().Format("20060102150405"), ext)
			return formatter.OutputTopData(rawMetrics, filename)
		},
	)
}

// printTopReport 打印 top 报告模式详情
func printTopReport(log *top.TopLog, startTime, endTime time.Time) {
	data := filterTopRange(log.Snapshots, startTime, endTime)
	if len(data) == 0 {
		fmt.Println("指定时间范围内无 top 数据")
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

	// 统计 Tasks
	taskRunningStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return float64(s.TaskRunning) })
	taskZombieStats := calculateTopStats(data, func(s top.TopSnapshot) float64 { return float64(s.TaskZombie) })

	fmt.Printf("\nOSWbb Top 监控报告\n")
	fmt.Printf("时间范围: %s ~ %s (共 %d 个采样点)\n", startTime.Format(TimeLayout), endTime.Format(TimeLayout), len(data))

	fmt.Println("\n[Load Average 负载]")
	fmt.Printf("  Load 1min : Min=%.2f, Max=%.2f, Avg=%.2f\n", load1Stats.Min, load1Stats.Max, load1Stats.Avg)
	fmt.Printf("  Load 5min : Min=%.2f, Max=%.2f, Avg=%.2f\n", load5Stats.Min, load5Stats.Max, load5Stats.Avg)
	fmt.Printf("  Load 15min: Min=%.2f, Max=%.2f, Avg=%.2f\n", load15Stats.Min, load15Stats.Max, load15Stats.Avg)

	fmt.Println("\n[CPU 使用率 %")
	fmt.Printf("  User : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuUserStats.Min, cpuUserStats.Max, cpuUserStats.Avg)
	fmt.Printf("  Sys  : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuSysStats.Min, cpuSysStats.Max, cpuSysStats.Avg)
	fmt.Printf("  Idle : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuIdleStats.Min, cpuIdleStats.Max, cpuIdleStats.Avg)
	fmt.Printf("  Wait : Min=%.1f, Max=%.1f, Avg=%.1f\n", cpuWaitStats.Min, cpuWaitStats.Max, cpuWaitStats.Avg)

	// CPU 异常检测
	if cpuIdleStats.Avg < 10.0 {
		fmt.Printf("  [警告] CPU 平均空闲率极低 (%.1f%%)，系统可能存在 CPU 瓶颈\n", cpuIdleStats.Avg)
	}
	if cpuWaitStats.Max > 20.0 {
		fmt.Printf("  [警告] CPU IO等待峰值较高 (%.1f%%)，可能存在磁盘 I/O 问题\n", cpuWaitStats.Max)
	}

	fmt.Println("\n[Tasks 进程状态]")
	fmt.Printf("  Running : Min=%.0f, Max=%.0f, Avg=%.1f\n", taskRunningStats.Min, taskRunningStats.Max, taskRunningStats.Avg)
	if taskZombieStats.Max > 0 {
		fmt.Printf("  Zombie  : Min=%.0f, Max=%.0f, Avg=%.1f (存在僵尸进程)\n", taskZombieStats.Min, taskZombieStats.Max, taskZombieStats.Avg)
	} else {
		fmt.Printf("  Zombie  : 无僵尸进程\n")
	}

	// 查找高负载时刻
	printHighLoadMoments(data)
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

	fmt.Println("\n[Load 1min 最高时刻 Top 3]")
	for i := 0; i < count; i++ {
		d := sortedData[i]
		fmt.Printf("  %s: Load1=%.2f, User=%.1f%%, Sys=%.1f%%, Wait=%.1f%%\n",
			d.Timestamp.Format(TimeShortLayout), d.Load1, d.CpuUser, d.CpuSys, d.CpuWait)
	}
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
		for _, err := range parseErrs {
			fmt.Println(err)
		}
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
