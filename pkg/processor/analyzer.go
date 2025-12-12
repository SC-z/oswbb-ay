package processor

import (
	"fmt"
	"math"
	"oswbb-analyse/pkg/common"
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/output"
	"sort"
	"time"
)

const (
	// TimeLayout 统一的时间格式布局
	TimeLayout = "2006-01-02 15:04:05"
	// TimeShortLayout 短时间格式布局
	TimeShortLayout = "15:04:05"
	// outputFormatReport 报告模式常量
	outputFormatReport = "report"

	// meminfo 分析窗口配置
	memShortWindow = 36  // 短窗口采样点数
	memLongWindow  = 720 // 长窗口采样点数

	// meminfo 阈值配置
	memAvailWarnPct         = 20.0
	memAvailSeverePct       = 10.0 // 更新为 10%
	memAvailSevereMB        = 8192.0  // 8GB
	memAvailWarnMB          = 16384.0 // 16GB

	memSwapSeverePct        = 10.0
	memUnreclaimPctThresh   = 2.0

	// Slab 告警配置
	memSlabWarnMB           = 20480.0 // 20GB
	memSlabWarnPct          = 8.0

	memAnonLeakDeltaMB      = 200.0
	memAnonLeakRateMBPerSample = 50.0
	
	memSwapBurstPct         = 20.0
	memSlopeBurstMBPerSample = 500.0
	memKernelAbsWarnMB      = 500.0
	memKernelDeltaPctWarn   = 50.0

	// V型波动检测配置
	memVPatternDropMB       = 4096.0 // 4GB
	memVPatternRecoverMB    = 2048.0 // 2GB

	// 突变检测配置
	memSuddenChangePct      = 2.0    // 2%
	memSuddenChangeMinMB    = 2048.0 // 2GB
)

// timeRangedLog 定义能够提供时间范围的日志接口
type timeRangedLog interface {
	GetTimeRange() (time.Time, time.Time)
}

// analysisOptions 通用分析配置
type analysisOptions struct {
	outputFormat      string
	startTimeStr      string
	endTimeStr        string
	location          *time.Location
	introLines        []string
	leadingBlankIntro bool
	rangeScope        string
}

// resolveTimeRange 解析时间范围，如果未指定则使用默认范围
func resolveTimeRange(log timeRangedLog, startTimeStr, endTimeStr string, cst *time.Location) (time.Time, time.Time, bool, error) {
	if log == nil {
		return time.Time{}, time.Time{}, false, fmt.Errorf("日志实例不能为空")
	}

	defaultStart, defaultEnd := log.GetTimeRange()

	if startTimeStr == "" || endTimeStr == "" {
		return defaultStart, defaultEnd, true, nil
	}

	startTime, err := time.ParseInLocation(TimeLayout, startTimeStr, cst)
	if err != nil {
		return time.Time{}, time.Time{}, false, fmt.Errorf("开始时间格式错误: %v", err)
	}

	endTime, err := time.ParseInLocation(TimeLayout, endTimeStr, cst)
	if err != nil {
		return time.Time{}, time.Time{}, false, fmt.Errorf("结束时间格式错误: %v", err)
	}

	return startTime, endTime, false, nil
}

// printTimeRangeNotice 输出时间范围提示
func printTimeRangeNotice(scope string, usedDefault bool, startTime, endTime time.Time) {
	if scope == "" {
		scope = "文件"
	}

	if usedDefault {
		fmt.Printf("使用%s完整时间范围: %s 到 %s\n",
			scope,
			startTime.Format(TimeLayout),
			endTime.Format(TimeLayout))
		return
	}

	fmt.Printf("使用指定时间范围: %s 到 %s\n",
		startTime.Format(TimeLayout),
		endTime.Format(TimeLayout))
}

// printIntro 输出报告开头信息
func printIntro(lines []string, leadingBlank bool) {
	if len(lines) == 0 {
		return
	}

	if leadingBlank {
		fmt.Println()
	}

	for _, line := range lines {
		fmt.Println(line)
	}
	fmt.Println()
}

// executeAnalysisTemplate 执行通用的分析流程
func executeAnalysisTemplate(
	log timeRangedLog,
	opts analysisOptions,
	reportAction func(start, end time.Time),
	exportAction func(start, end time.Time, formatter output.OutputFormatter) error,
) error {
	startTime, endTime, usedDefault, err := resolveTimeRange(log, opts.startTimeStr, opts.endTimeStr, opts.location)
	if err != nil {
		return err
	}

	if opts.outputFormat == outputFormatReport {
		printTimeRangeNotice(opts.rangeScope, usedDefault, startTime, endTime)
		printIntro(opts.introLines, opts.leadingBlankIntro)
		reportAction(startTime, endTime)
		return nil
	}

	formatter, err := output.CreateFormatter(opts.outputFormat)
	if err != nil {
		return err
	}

	return exportAction(startTime, endTime, formatter)
}

// analyzeIOStatLog 根据配置分析 iostat 日志
func analyzeIOStatLog(log *iostat.IOStatLog, opts analysisOptions) error {
	return executeAnalysisTemplate(log, opts,
		func(start, end time.Time) {
			printIOStatReport(log, start, end)
		},
		func(start, end time.Time, formatter output.OutputFormatter) error {
			rawMetrics := output.ConvertIOStatData(log, start, end)

			ext := "csv"
			if opts.outputFormat == "html" {
				ext = "html"
			}

			filename := fmt.Sprintf("iostat_%s.%s", time.Now().Format("20060102150405"), ext)
			return formatter.OutputIOStatData(rawMetrics, filename)
		},
	)
}


// printIOStatReport 打印 iostat 报告模式详情
func printIOStatReport(log *iostat.IOStatLog, startTime, endTime time.Time) {
	devices := log.GetAllDevices()
	if len(devices) == 0 {
		fmt.Println("未发现可用设备")
		return
	}

	sort.Strings(devices)

	fmt.Println("发现的设备:")
	for _, device := range devices {
		fmt.Printf("- %s\n", device)
	}
	fmt.Println()

	fmt.Println("\n=== 活跃设备分析 ===")
	activeDevices := collectActiveDevices(log, devices, startTime, endTime)

	fmt.Println("=== 延迟异常检测 ===")
	printIOStatAnomalies(log, activeDevices, startTime, endTime)
}

// collectActiveDevices 输出活跃设备统计并返回设备列表
func collectActiveDevices(log *iostat.IOStatLog, devices []string, startTime, endTime time.Time) []string {
	var activeDevices []string

	for _, device := range devices {
		iops := log.GetIOPSTrend(device, startTime, endTime)
		if len(iops) == 0 {
			continue
		}

		maxIops := iops.Max()
		if maxIops.Value <= 0 {
			continue
		}

		activeDevices = append(activeDevices, device)
		printDeviceStats(device, log, startTime, endTime)
	}

	return activeDevices
}

// printIOStatAnomalies 打印延迟异常详情
func printIOStatAnomalies(log *iostat.IOStatLog, activeDevices []string, startTime, endTime time.Time) {
	hasAnomalies := false

	for _, device := range activeDevices {
		readLatencyStats := log.GetReadLatencyStats(device, startTime, endTime)
		if len(readLatencyStats.Anomalies) > 0 {
			hasAnomalies = true
			printAnomalyStats(device, readLatencyStats, "读")
		}

		writeLatencyStats := log.GetWriteLatencyStats(device, startTime, endTime)
		if len(writeLatencyStats.Anomalies) > 0 {
			hasAnomalies = true
			printAnomalyStats(device, writeLatencyStats, "写")
		}
	}

	if !hasAnomalies {
		fmt.Println("未检测到明显的延迟异常 (所有异常点延迟 < 8μs)")
	}
}

// mergeIOStatFiles 解析并合并多个 iostat 文件
func mergeIOStatFiles(filenames []string, parser *iostat.IOStatParser) (*iostat.IOStatLog, []error) {
	var allData []iostat.IOStatData
	var parseErrs []error

	for _, filename := range filenames {
		log, err := parser.ParseFile(filename)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("解析文件失败 %s: %v", filename, err))
			continue
		}
		allData = append(allData, log.Data...)
	}

	if len(allData) == 0 {
		return nil, parseErrs
	}

	return &iostat.IOStatLog{
		Header: fmt.Sprintf("合并了 %d 个文件", len(filenames)),
		Data:   allData,
	}, parseErrs
}

// logParseErrors 输出解析错误
func logParseErrors(errs []error) {
	for _, err := range errs {
		fmt.Println(err)
	}
}

// analyzeMemInfoLog 根据配置分析 meminfo 日志
func analyzeMemInfoLog(log *meminfo.MemInfoLog, opts analysisOptions, timeLayout string) error {
	return executeAnalysisTemplate(log, opts,
		func(start, end time.Time) {
			printMemInfoReport(log, start, end, timeLayout)
		},
		func(start, end time.Time, formatter output.OutputFormatter) error {
			rawMetrics := output.ConvertMemInfoData(log, start, end)

			ext := "csv"
			if opts.outputFormat == "html" {
				ext = "html"
			}

			filename := fmt.Sprintf("meminfo_%s.%s", time.Now().Format("20060102150405"), ext)
			return formatter.OutputMemInfoData(rawMetrics, filename)
		},
	)
}

// printMemInfoReport 打印 meminfo 报告模式详情（短期/长期窗口对比 + 突变检测）
func printMemInfoReport(log *meminfo.MemInfoLog, startTime, endTime time.Time, timeLayout string) {
	data := filterMemInfoRange(log.Data, startTime, endTime)
	if len(data) == 0 {
		fmt.Println("指定时间范围内无 meminfo 数据")
		return
	}

	shortWin := tailMemInfoWindow(data, memShortWindow)
	longWin := tailMemInfoWindow(data, memLongWindow)
	latest := data[len(data)-1]
	memTotalKB := float64(latest.MemStats.MemTotal)
	if memTotalKB == 0 {
		fmt.Println("meminfo 数据缺少 MemTotal 字段，无法生成报告")
		return
	}

	availStats := buildSeriesStats(shortWin, longWin, func(ms meminfo.MemStats) float64 { return float64(ms.MemAvailable) })
	anonStats := buildSeriesStats(shortWin, longWin, func(ms meminfo.MemStats) float64 { return float64(ms.AnonPages) })
	slabStats := buildSeriesStats(shortWin, longWin, func(ms meminfo.MemStats) float64 { return float64(ms.Slab) })
	swapStats := buildSeriesStats(shortWin, longWin, func(ms meminfo.MemStats) float64 { return float64(ms.SwapFree) })

	availPct := pct(availStats.current, memTotalKB)
	swapPct := 0.0
	if latest.MemStats.SwapTotal > 0 {
		swapUsed := float64(latest.MemStats.SwapTotal - latest.MemStats.SwapFree)
		swapPct = pct(swapUsed, float64(latest.MemStats.SwapTotal))
	}
	unreclaimPct := pct(float64(latest.MemStats.SUnreclaim), memTotalKB)

	memTotalMBVal := memTotalKB / 1024.0

	availStatus := classifyAvail(availPct, kbToMB(availStats.current))
	availAnomalies := findSignificantTrendChange(data, func(ms meminfo.MemStats) float64 { return float64(ms.MemAvailable) }, memSlopeBurstMBPerSample, memTotalMBVal)
	vPatternAnomalies := detectVPattern(data, func(ms meminfo.MemStats) float64 { return float64(ms.MemAvailable) })
	availAnomalies = append(availAnomalies, vPatternAnomalies...)
	// 重新排序
	sort.Slice(availAnomalies, func(i, j int) bool {
		return availAnomalies[i].Value > availAnomalies[j].Value
	})

	anonDeltaMB := deltaMB(shortWin, func(ms meminfo.MemStats) float64 { return float64(ms.AnonPages) })
	anonRateMB := anonStats.slopeShort
	anonStatus := classifyAnon(anonDeltaMB, anonRateMB, availStats.slopeShort)
	anonAnomalies := findSignificantTrendChange(data, func(ms meminfo.MemStats) float64 { return float64(ms.AnonPages) }, memSlopeBurstMBPerSample, memTotalMBVal)

	slabAnomalies := findSignificantTrendChange(data, func(ms meminfo.MemStats) float64 { return float64(ms.Slab) }, 200, memTotalMBVal)
	
	slabMB := kbToMB(float64(latest.MemStats.Slab))
	slabPct := pct(float64(latest.MemStats.Slab), memTotalKB)
	slabStatus := classifySlab(slabMB, slabPct)
	unreclaimStatus := classifyUnreclaim(unreclaimPct, slabStats.slopeShort)
	
	swapUsageStatus := classifySwapUsage(latest.MemStats.SwapFree, latest.MemStats.SwapTotal, swapPct, availPct)
	deltaSwapPct := swapDeltaPct(shortWin, latest.MemStats.SwapTotal)
	
	// Swap 异常检测
	var swapAnomalies []common.TrendAnomaly
	swapBurst := "无"
	var swapChangeTime time.Time
	
	if latest.MemStats.SwapTotal > 0 {
		swapTotalMB := float64(latest.MemStats.SwapTotal) / 1024.0
		swapThreshold := (swapTotalMB * (memSwapBurstPct / 100.0)) / float64(memShortWindow)
		swapAnomalies = findSignificantTrendChange(data, func(ms meminfo.MemStats) float64 { return float64(ms.SwapFree) }, swapThreshold, memTotalMBVal)
		
		for _, anomaly := range swapAnomalies {
			if anomaly.Type == "骤降(单点)" || anomaly.Type == "骤降(趋势)" {
				swapBurst = "Swap 激增"
				swapChangeTime = anomaly.Time
				break // 只记录最严重的
			}
		}
	}

	kernelStatus, kernelDelta := classifyKernelOverhead(shortWin)

	fmt.Printf("\nOSWbb Meminfo 监控报告\n")
	fmt.Printf("时间范围: %s ~ %s (短窗 %d 点, 长窗 %d 点)\n", startTime.Format(timeLayout), endTime.Format(timeLayout), memShortWindow, memLongWindow)
	fmt.Printf("主机: %s\n\n", extractHostnameIfPossible(data))

	fmt.Println("[概览]")
	fmt.Printf("- 可用内存: %.1f%% (当前 %.2f GB / 总 %.2f GB)\n", availPct, kbToGB(availStats.current), kbToGB(memTotalKB))
	swapMin, swapMax, swapAvg, hasSwap := summarizeSeries(data, func(ms meminfo.MemStats) float64 { return float64(ms.SwapFree) })
	anonMin, anonMax, anonAvg, hasAnon := summarizeSeries(data, func(ms meminfo.MemStats) float64 { return float64(ms.AnonPages) })
	fmt.Printf("- Swap: %.2f/%.2f GB (使用率 %.1f%%)", kbToGB(float64(latest.MemStats.SwapTotal-latest.MemStats.SwapFree)), kbToGB(float64(latest.MemStats.SwapTotal)), swapPct)
	if hasSwap {
		fmt.Printf("；可用范围 %.2f~%.2f GB，平均 %.2f GB\n", kbToGB(swapMin), kbToGB(swapMax), kbToGB(swapAvg))
	} else {
		fmt.Println()
	}
	fmt.Printf("- 匿名页(AnonPages): %.2f GB", kbToGB(anonStats.current))
	if hasAnon {
		fmt.Printf("；范围 %.2f~%.2f GB，平均 %.2f GB\n", kbToGB(anonMin), kbToGB(anonMax), kbToGB(anonAvg))
	} else {
		fmt.Println()
	}
	fmt.Printf("- Slab: %.2f GB (不可回收 %.2f GB，可回收 %.2f GB)\n", kbToGB(float64(latest.MemStats.Slab)), kbToGB(float64(latest.MemStats.SUnreclaim)), kbToGB(float64(latest.MemStats.SReclaimable)))
	fmt.Printf("- 内核栈/PageTables/Percpu: %.2f/%.2f/%.2f MB\n\n", kbToMB(float64(latest.MemStats.KernelStack)), kbToMB(float64(latest.MemStats.PageTables)), kbToMB(float64(latest.MemStats.Percpu)))

	fmt.Println("[告警与趋势]")
	fmt.Printf("- 可用内存: %s；短期斜率 %.1f MB/点，Δs=%.1f；Z=%.2f；突变: %s\n",
		availStatus, availStats.slopeShort, availStats.slopeShort-availStats.slopeLong, availStats.zScore, formatAnomalies(availAnomalies, timeLayout))
	fmt.Printf("- 匿名页: %s；短窗增量 %.1f MB，平均变化 %.1f MB/点；突变: %s\n",
		anonStatus, anonDeltaMB, anonRateMB, formatAnomalies(anonAnomalies, timeLayout))
	fmt.Printf("- Slab/Unreclaim: %s / %s；SUnreclaim占比 %.2f %%; 突变: %s\n",
		slabStatus, unreclaimStatus, unreclaimPct, formatAnomalies(slabAnomalies, timeLayout))
	fmt.Printf("- Swap 使用: %s；SwapPct=%.1f%%；短窗变化 %.1f%%；突发: %s @ %s\n",
		swapUsageStatus, swapPct, deltaSwapPct, swapBurst, formatTimeOrDash(swapChangeTime, timeLayout))
	fmt.Printf("- 内核栈/页表/Percpu: %s；短窗增幅( MB ): %.1f/%.1f/%.1f\n",
		kernelStatus, kernelDelta.kernelStackMB, kernelDelta.pageTablesMB, kernelDelta.percpuMB)
	fmt.Printf("- 大页: Total=%d, Free=%d, Size=%d kB\n\n", latest.MemStats.HugePagesTotal, latest.MemStats.HugePagesFree, latest.MemStats.Hugepagesize)

	fmt.Println("[详细指标]")
	fmt.Println("1) 可用内存")
	fmt.Printf("   当前: %.2f GB (%.1f%%)\n", kbToGB(availStats.current), availPct)
	fmt.Printf("   短/长期均值: %.2f / %.2f GB\n", kbToGB(availStats.meanShort), kbToGB(availStats.meanLong))
	fmt.Printf("   斜率: s_short=%.1f MB/点, s_long=%.1f MB/点, Δs=%.1f\n", availStats.slopeShort, availStats.slopeLong, availStats.slopeShort-availStats.slopeLong)
	fmt.Printf("   Z=%.2f, MAD=%.2f (KB)\n\n", availStats.zScore, availStats.mad)

	fmt.Println("2) 匿名页 (AnonPages)")
	fmt.Printf("   当前: %.2f GB；短窗增量 %.1f MB；平均变化 %.1f MB/点\n\n", kbToGB(anonStats.current), anonDeltaMB, anonRateMB)

	fmt.Println("3) Slab")
	fmt.Printf("   Slab: %.2f GB；SUnreclaim %.2f GB (%.2f%%)；SReclaimable %.2f GB\n\n", kbToGB(float64(latest.MemStats.Slab)), kbToGB(float64(latest.MemStats.SUnreclaim)), unreclaimPct, kbToGB(float64(latest.MemStats.SReclaimable)))

	fmt.Println("4) Swap")
	fmt.Printf("   当前: %.2f/%.2f GB (%.1f%%)\n", kbToGB(swapStats.current), kbToGB(float64(latest.MemStats.SwapTotal)), swapPct)
	fmt.Printf("   短窗变化: %.1f%% (%.2f GB)\n\n", deltaSwapPct, kbToGB(deltaSwapKB(shortWin)))

	fmt.Println("5) 内核栈 / PageTables / Percpu")
	fmt.Printf("   当前: %.2f/%.2f/%.2f MB\n", kbToMB(float64(latest.MemStats.KernelStack)), kbToMB(float64(latest.MemStats.PageTables)), kbToMB(float64(latest.MemStats.Percpu)))
	fmt.Printf("   短窗增幅: %.1f/%.1f/%.1f MB\n", kernelDelta.kernelStackMB, kernelDelta.pageTablesMB, kernelDelta.percpuMB)
	fmt.Println("   说明: KernelStack=线程/协程栈，PageTables=内存映射页表，Percpu=每CPU局部缓存")

	fmt.Println("6) 大页信息（仅报告）")
	fmt.Printf("   HugePages_Total: %d, HugePages_Free: %d, Hugepagesize: %d kB\n", latest.MemStats.HugePagesTotal, latest.MemStats.HugePagesFree, latest.MemStats.Hugepagesize)

	// 打印详细异常列表
	anomalyCategories := make(map[string][]common.TrendAnomaly)
	anomalyCategories["可用内存 (Available)"] = availAnomalies
	anomalyCategories["匿名页 (AnonPages)"] = anonAnomalies
	anomalyCategories["Slab"] = slabAnomalies
	anomalyCategories["Swap"] = swapAnomalies

	printAnomalyDetailList(anomalyCategories, timeLayout)

}

// mergeMemInfoFiles 解析并合并多个 meminfo 文件
func mergeMemInfoFiles(filenames []string, parser *meminfo.MemInfoParser) (*meminfo.MemInfoLog, []error) {
	var allData []meminfo.MemStatData
	var parseErrs []error

	for _, filename := range filenames {
		log, err := parser.ParseFile(filename)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("解析文件失败 %s: %v", filename, err))
			continue
		}
		allData = append(allData, log.Data...)
	}

	if len(allData) == 0 {
		return nil, parseErrs
	}

	return &meminfo.MemInfoLog{
		Data: allData,
	}, parseErrs
}

// printDeviceStats 输出设备统计信息
func printDeviceStats(device string, iostatLog *iostat.IOStatLog, startTime, endTime time.Time) {
	iops := iostatLog.GetIOPSTrend(device, startTime, endTime)
	if len(iops) == 0 {
		return
	}

	maxIops := iops.Max()
	if maxIops.Value <= 0 {
		return
	}

	// 获取性能统计
	readMax, writeMax, readAvg, writeAvg := iostatLog.GetThroughputStats(device, startTime, endTime)
	avgQueueDepth := iostatLog.GetAverageQueueDepth(device, startTime, endTime)
	readLatencyStats := iostatLog.GetReadLatencyStats(device, startTime, endTime)
	writeLatencyStats := iostatLog.GetWriteLatencyStats(device, startTime, endTime)

	fmt.Printf("%s:\n", device)
	fmt.Printf("  IOPS: 最大=%.1f (时间:%s) 平均=%.1f\n",
		maxIops.Value, maxIops.Time.Format(TimeShortLayout), iops.Average())
	fmt.Printf("  吞吐量(KB/s): 读最大=%.1f 写最大=%.1f 读平均=%.1f 写平均=%.1f\n",
		readMax, writeMax, readAvg, writeAvg)
	fmt.Printf("  延迟(μs): 读平均=%.1f 写平均=%.1f\n",
		readLatencyStats.Mean, writeLatencyStats.Mean)
	fmt.Printf("  平均队列深度: %.2f\n", avgQueueDepth)
	fmt.Println()
}

// printAnomalyStats 输出延迟异常统计
func printAnomalyStats(device string, latencyStats iostat.LatencyStats, latencyType string) {
	if len(latencyStats.Anomalies) == 0 {
		return
	}

	maxAnomaly := findMaxAnomaly(latencyStats.Anomalies)
	fmt.Printf("%s %s延迟:\n", device, latencyType)
	fmt.Printf("  统计: μ=%.1fμs σ=%.1f MAD=%.1f P50=%.1f P95=%.1f P99=%.1f\n",
		latencyStats.Mean, latencyStats.StdDev, latencyStats.MAD,
		latencyStats.P50, latencyStats.P95, latencyStats.P99)
	fmt.Printf("  异常: %d个突增点, 最严重=%.1fμs @ %s",
		len(latencyStats.Anomalies), maxAnomaly.Value, maxAnomaly.Timestamp.Format(TimeLayout))

	if maxAnomaly.Method == "z-score" {
		fmt.Printf(" (%.1fσ)\n", maxAnomaly.ZScore)
	} else if maxAnomaly.Method == "mad" {
		fmt.Printf(" (MAD×%.0f)\n", maxAnomaly.MADScore)
	} else {
		fmt.Printf(" (IQR)\n")
	}
	fmt.Println()
}

// findMaxAnomaly 找到最严重的异常点
func findMaxAnomaly(anomalies []iostat.AnomalyPoint) iostat.AnomalyPoint {
	if len(anomalies) == 0 {
		return iostat.AnomalyPoint{}
	}

	maxAnomaly := anomalies[0]
	for _, anomaly := range anomalies[1:] {
		if anomaly.Value > maxAnomaly.Value {
			maxAnomaly = anomaly
		}
	}
	return maxAnomaly
}

// AnalyzeIOStatFile 分析单个iostat文件
func AnalyzeIOStatFile(filename, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	parser := &iostat.IOStatParser{}
	iostatLog, err := parser.ParseFile(filename)
	if err != nil {
		return fmt.Errorf("解析iostat文件失败: %v", err)
	}

	opts := analysisOptions{
		outputFormat: outputFormat,
		startTimeStr: startTimeStr,
		endTimeStr:   endTimeStr,
		location:     cst,
		introLines: []string{
			fmt.Sprintf("成功解析iostat日志: %s", iostatLog.Header),
			fmt.Sprintf("总共 %d 个数据点", len(iostatLog.Data)),
		},
		rangeScope: "文件",
	}

	return analyzeIOStatLog(iostatLog, opts)
}

// AnalyzeMergedIOStatFiles 合并分析多个iostat文件
func AnalyzeMergedIOStatFiles(filenames []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	parser := &iostat.IOStatParser{}
	mergedLog, parseErrs := mergeIOStatFiles(filenames, parser)

	if len(parseErrs) > 0 && outputFormat == outputFormatReport {
		logParseErrors(parseErrs)
	}

	if mergedLog == nil || len(mergedLog.Data) == 0 {
		return fmt.Errorf("没有有效的数据可以分析")
	}

	opts := analysisOptions{
		outputFormat:      outputFormat,
		startTimeStr:      startTimeStr,
		endTimeStr:        endTimeStr,
		location:          cst,
		introLines:        []string{fmt.Sprintf("成功合并 %d 个文件，总共 %d 个数据点", len(filenames), len(mergedLog.Data))},
		leadingBlankIntro: true,
		rangeScope:        "合并数据",
	}

	return analyzeIOStatLog(mergedLog, opts)
}

// AnalyzeMemInfoFile 分析单个meminfo文件
func AnalyzeMemInfoFile(filename, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	parser := &meminfo.MemInfoParser{}
	memLog, err := parser.ParseFile(filename)
	if err != nil {
		return fmt.Errorf("解析meminfo文件失败: %v", err)
	}

	opts := analysisOptions{
		outputFormat: outputFormat,
		startTimeStr: startTimeStr,
		endTimeStr:   endTimeStr,
		location:     cst,
		introLines: []string{
			"成功解析meminfo日志",
			fmt.Sprintf("总共 %d 个数据点", len(memLog.Data)),
		},
		rangeScope: "文件",
	}

	return analyzeMemInfoLog(memLog, opts, TimeShortLayout)
}

// AnalyzeMergedMemInfoFiles 合并分析多个meminfo文件
func AnalyzeMergedMemInfoFiles(filenames []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	parser := &meminfo.MemInfoParser{}
	mergedLog, parseErrs := mergeMemInfoFiles(filenames, parser)

	if len(parseErrs) > 0 && outputFormat == outputFormatReport {
		logParseErrors(parseErrs)
	}

	if mergedLog == nil || len(mergedLog.Data) == 0 {
		return fmt.Errorf("没有有效的数据可以分析")
	}

	opts := analysisOptions{
		outputFormat:      outputFormat,
		startTimeStr:      startTimeStr,
		endTimeStr:        endTimeStr,
		location:          cst,
		introLines:        []string{fmt.Sprintf("成功合并 %d 个文件，总共 %d 个数据点", len(filenames), len(mergedLog.Data))},
		leadingBlankIntro: true,
		rangeScope:        "合并数据",
	}

	return analyzeMemInfoLog(mergedLog, opts, TimeLayout)
}

// ==== meminfo 报告辅助类型与函数 ====

// memSeriesStats 记录短/长期窗口统计
type memSeriesStats struct {
	current    float64
	meanShort  float64
	meanLong   float64
	slopeShort float64
	slopeLong  float64
	zScore     float64
	mad        float64
}

// kernelDelta 记录内核开销变化
type kernelDelta struct {
	kernelStackMB float64
	pageTablesMB  float64
	percpuMB      float64
}

// filterMemInfoRange 过滤时间范围内的数据
func filterMemInfoRange(data []meminfo.MemStatData, start, end time.Time) []meminfo.MemStatData {
	var result []meminfo.MemStatData
	for _, d := range data {
		if (d.Timestamp.Equal(start) || d.Timestamp.After(start)) && (d.Timestamp.Equal(end) || d.Timestamp.Before(end)) {
			result = append(result, d)
		}
	}
	return result
}

// tailMemInfoWindow 截取结尾窗口数据
func tailMemInfoWindow(data []meminfo.MemStatData, window int) []meminfo.MemStatData {
	if window <= 0 || len(data) <= window {
		return data
	}
	return data[len(data)-window:]
}

// buildSeriesStats 构建短/长期窗口统计，单位以 KB 为基准，斜率转换为 MB/分钟
func buildSeriesStats(shortWin, longWin []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) memSeriesStats {
	stats := memSeriesStats{}
	if len(longWin) == 0 {
		return stats
	}

	stats.current = extractor(longWin[len(longWin)-1].MemStats)
	stats.meanShort = meanOfWindow(shortWin, extractor)
	stats.meanLong = meanOfWindow(longWin, extractor)
	stats.slopeShort = computeSlopeMBPerSample(shortWin, extractor)
	stats.slopeLong = computeSlopeMBPerSample(longWin, extractor)
	stats.zScore = zScore(longWin, extractor, stats.current)
	stats.mad = madValue(longWin, extractor)
	return stats
}

// computeSlopeMBPerSample 根据窗口首尾计算斜率 (MB/点)
func computeSlopeMBPerSample(win []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) float64 {
	if len(win) < 2 {
		return 0
	}
	first := extractor(win[0].MemStats)
	last := extractor(win[len(win)-1].MemStats)
	deltaKB := last - first
	count := float64(len(win) - 1)
	if count <= 0 {
		return 0
	}
	return (deltaKB / 1024.0) / count
}

// meanOfWindow 计算窗口平均
func meanOfWindow(win []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) float64 {
	if len(win) == 0 {
		return 0
	}
	sum := 0.0
	for _, d := range win {
		sum += extractor(d.MemStats)
	}
	return sum / float64(len(win))
}

// zScore 基于长期窗口计算 Z 分数
func zScore(win []meminfo.MemStatData, extractor func(meminfo.MemStats) float64, current float64) float64 {
	values := extractValues(win, extractor)
	if len(values) == 0 {
		return 0
	}
	mean := meanFloat(values)
	std := stdDev(values, mean)
	if std == 0 {
		return 0
	}
	return (current - mean) / std
}

// madValue 计算中位绝对偏差
func madValue(win []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) float64 {
	values := extractValues(win, extractor)
	if len(values) == 0 {
		return 0
	}
	median := percentile(values, 50)
	devs := make([]float64, len(values))
	for i, v := range values {
		devs[i] = math.Abs(v - median)
	}
	return percentile(devs, 50)
}

// extractValues 提取窗口的数值切片
func extractValues(win []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) []float64 {
	values := make([]float64, 0, len(win))
	for _, d := range win {
		values = append(values, extractor(d.MemStats))
	}
	sort.Float64s(values)
	return values
}

// percentile 百分位计算
func percentile(sortedValues []float64, p float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}
	if p <= 0 {
		return sortedValues[0]
	}
	if p >= 100 {
		return sortedValues[len(sortedValues)-1]
	}
	index := p / 100.0 * float64(len(sortedValues)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))
	if lower == upper {
		return sortedValues[lower]
	}
	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

// meanFloat 简单平均
func meanFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// stdDev 标准差
func stdDev(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		diff := v - mean
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(values)))
}

// detectVPattern 检测 V 型波动 (跌落后回升)
func detectVPattern(data []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) []common.TrendAnomaly {
	var anomalies []common.TrendAnomaly
	if len(data) < 5 {
		return anomalies
	}

	for i := 2; i < len(data)-2; i++ {
		// 计算窗口均值 (单位: MB)
		prev1 := extractor(data[i-1].MemStats) / 1024.0
		prev2 := extractor(data[i-2].MemStats) / 1024.0
		prevAvg := (prev1 + prev2) / 2.0

		curr := extractor(data[i].MemStats) / 1024.0

		next1 := extractor(data[i+1].MemStats) / 1024.0
		next2 := extractor(data[i+2].MemStats) / 1024.0
		nextAvg := (next1 + next2) / 2.0

		drop := prevAvg - curr
		recover := nextAvg - curr

		if drop > memVPatternDropMB && recover > memVPatternRecoverMB {
			anomalies = append(anomalies, common.TrendAnomaly{
				Type:      "V型波动",
				Time:      data[i].Timestamp,
				Value:     drop, // 记录跌落幅度
				IsSudden:  true,
				StartVal:  prevAvg,
				EndVal:    curr,
				Threshold: memVPatternDropMB,
				RuleName:  "V型跌落回升",
			})
		}
	}
	
	// 按跌落幅度降序排序
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Value > anomalies[j].Value
	})

	return anomalies
}

// findSignificantTrendChange 全局扫描寻找所有显著的趋势突变点
func findSignificantTrendChange(data []meminfo.MemStatData, extractor func(meminfo.MemStats) float64, thresholdSlope float64, memTotalMB float64) []common.TrendAnomaly {
	var anomalies []common.TrendAnomaly
	if len(data) < 2 {
		return anomalies
	}

	// 1. 动态计算突变阈值
	// 规则: 取系统总内存的 2%，如果不足 2GB 则按 2GB 计算
	suddenChangeThresholdMB := memTotalMB * (memSuddenChangePct / 100.0)
	if suddenChangeThresholdMB < memSuddenChangeMinMB {
		suddenChangeThresholdMB = memSuddenChangeMinMB
	}

	// 遍历数据进行检测
	for i := 1; i < len(data); i++ {
		valCurrent := extractor(data[i].MemStats)
		valPrev := extractor(data[i-1].MemStats)
		
		// --- 检测 A: 相邻点骤变 (针对单点异常) ---
		deltaMB := (valCurrent - valPrev) / 1024.0
		absDelta := math.Abs(deltaMB)
		
		if absDelta > suddenChangeThresholdMB {
			anomaly := common.TrendAnomaly{
				Time:      data[i].Timestamp,
				Value:     absDelta,
				IsSudden:  true,
				StartVal:  valPrev / 1024.0,
				EndVal:    valCurrent / 1024.0,
				Threshold: suddenChangeThresholdMB,
				RuleName:  "相邻点突变",
			}
			if deltaMB > 0 {
				anomaly.Type = "骤升(单点)"
			} else {
				anomaly.Type = "骤降(单点)"
			}
			anomalies = append(anomalies, anomaly)
			continue // 如果发现了剧烈骤变，就不需要再看趋势了
		}

		// 如果数据不够长窗口，跳过趋势计算
		if i < memLongWindow {
			continue
		}

		// --- 检测 B: 趋势斜率变化 (针对缓慢泄漏) ---
		longStartIdx := i - memLongWindow
		shortStartIdx := i - memShortWindow
		if shortStartIdx < 0 { shortStartIdx = 0 }

		valLongStart := extractor(data[longStartIdx].MemStats)
		valShortStart := extractor(data[shortStartIdx].MemStats)

		// 计算斜率 (MB/采样点)
		slopeLong := (valCurrent - valLongStart) / 1024.0 / float64(memLongWindow)
		slopeShort := (valCurrent - valShortStart) / 1024.0 / float64(memShortWindow)

		diff := slopeShort - slopeLong
		absDiff := math.Abs(diff)

		if absDiff > thresholdSlope {
			anomaly := common.TrendAnomaly{
				Time:      data[shortStartIdx].Timestamp,
				Value:     absDiff,
				IsSudden:  false,
				StartVal:  slopeLong,
				EndVal:    slopeShort,
				Threshold: thresholdSlope,
				RuleName:  "趋势斜率差异",
			}
			if diff > 0 {
				anomaly.Type = "骤升(趋势)"
			} else {
				anomaly.Type = "骤降(趋势)"
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	// 按严重程度（Value）降序排序
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Value > anomalies[j].Value
	})

	return anomalies
}


// deltaMB 计算窗口首尾差值 (MB)
func deltaMB(win []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) float64 {
	if len(win) < 2 {
		return 0
	}
	first := extractor(win[0].MemStats)
	last := extractor(win[len(win)-1].MemStats)
	return (last - first) / 1024.0
}

// deltaSwapKB 计算 Swap 首尾变化 (KB)，正数表示消耗
func deltaSwapKB(win []meminfo.MemStatData) float64 {
	if len(win) < 2 {
		return 0
	}
	first := float64(win[0].MemStats.SwapFree)
	last := float64(win[len(win)-1].MemStats.SwapFree)
	return first - last
}

// swapDeltaPct 计算 Swap 百分比变化，正数表示消耗
func swapDeltaPct(win []meminfo.MemStatData, swapTotal int64) float64 {
	if len(win) < 2 || swapTotal == 0 {
		return 0
	}
	delta := deltaSwapKB(win)
	return (delta / float64(swapTotal)) * 100
}

// classifyAvail 按可用内存占比和绝对值判定
func classifyAvail(availPct, availMB float64) string {
	if availMB < memAvailSevereMB || availPct < memAvailSeverePct {
		return "严重"
	}
	if availMB < memAvailWarnMB || availPct < memAvailWarnPct {
		return "警告"
	}
	return "正常"
}

// classifySlab 判定 Slab 状态
func classifySlab(slabMB, slabPct float64) string {
	if slabMB > memSlabWarnMB && slabPct > memSlabWarnPct {
		return "警告 (高占用)"
	}
	return "正常"
}

// classifyAnon 判定匿名页趋势
func classifyAnon(deltaMB, rateMB, availSlope float64) string {
	if deltaMB > memAnonLeakDeltaMB && rateMB > memAnonLeakRateMBPerSample {
		return "疑似泄漏"
	}
	if deltaMB > memAnonLeakDeltaMB && availSlope < 0 {
		return "疑似泄漏"
	}
	return "正常"
}

// classifyUnreclaim 判定不可回收 Slab 状态
func classifyUnreclaim(unreclaimPct, slope float64) string {
	if unreclaimPct > memUnreclaimPctThresh {
		return "告警"
	}
	if slope > 0 {
		return "告警"
	}
	return "正常"
}

// classifySwapUsage 判定 Swap 状态
func classifySwapUsage(swapFree, swapTotal int64, swapPct, availPct float64) string {
	if swapTotal == 0 {
		return "无 Swap"
	}
	if swapFree < swapTotal {
		if swapPct < memSwapSeverePct && availPct < memAvailSeverePct {
			return "严重"
		}
		return "已使用 Swap"
	}
	return "未使用"
}

// classifyKernelOverhead 检测内核开销突增
func classifyKernelOverhead(win []meminfo.MemStatData) (string, kernelDelta) {
	if len(win) < 2 {
		return "正常", kernelDelta{}
	}
	first := win[0].MemStats
	last := win[len(win)-1].MemStats
	delta := kernelDelta{
		kernelStackMB: kbToMB(float64(last.KernelStack - first.KernelStack)),
		pageTablesMB:  kbToMB(float64(last.PageTables - first.PageTables)),
		percpuMB:      kbToMB(float64(last.Percpu - first.Percpu)),
	}

	status := "正常"
	if exceedsKernel(delta.kernelStackMB, first.KernelStack) || exceedsKernel(delta.pageTablesMB, first.PageTables) || exceedsKernel(delta.percpuMB, first.Percpu) {
		status = "线程/映射异常"
	}
	return status, delta
}

func exceedsKernel(deltaMB float64, baseKB int64) bool {
	if math.Abs(deltaMB) > memKernelAbsWarnMB {
		return true
	}
	if baseKB == 0 {
		return false
	}
	baseMB := kbToMB(float64(baseKB))
	if baseMB == 0 {
		return false
	}
	return (deltaMB/baseMB)*100 > memKernelDeltaPctWarn
}

// pct 计算百分比
func pct(num, den float64) float64 {
	if den == 0 {
		return 0
	}
	return num / den * 100
}

// kbToGB KB 转 GB
func kbToGB(kb float64) float64 { return kb / 1024.0 / 1024.0 }

// kbToMB KB 转 MB
func kbToMB(kb float64) float64 { return kb / 1024.0 }

// formatTimeOrDash 格式化时间
func formatTimeOrDash(t time.Time, layout string) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(layout)
}

// windowStart 返回窗口起始时间
func windowStart(win []meminfo.MemStatData) time.Time {
	if len(win) == 0 {
		return time.Time{}
	}
	return win[0].Timestamp
}

// extractHostnameIfPossible 占位，meminfo 数据不含主机名
func extractHostnameIfPossible(_ []meminfo.MemStatData) string {
	return "-"
}

// summarizeSeries 统计序列的极值与平均
func summarizeSeries(data []meminfo.MemStatData, extractor func(meminfo.MemStats) float64) (min, max, avg float64, ok bool) {
	if len(data) == 0 {
		return 0, 0, 0, false
	}
	minVal := extractor(data[0].MemStats)
	maxVal := minVal
	sum := 0.0
	for _, d := range data {
		val := extractor(d.MemStats)
		if val < minVal {
			minVal = val
		}
		if val > maxVal {
			maxVal = val
		}
		sum += val
	}
	return minVal, maxVal, sum / float64(len(data)), true
}

// formatKBValue 根据大小选择 GB 或 MB 输出
func formatKBValue(kb float64) string {
	if kb <= 0 {
		return "0 MB"
	}
	if kb >= 1024*1024 {
		return fmt.Sprintf("%.2f GB", kbToGB(kb))
	}
	return fmt.Sprintf("%.2f MB", kbToMB(kb))
}

// formatAnomalies 格式化异常列表
func formatAnomalies(anomalies []common.TrendAnomaly, layout string) string {
	if len(anomalies) == 0 {
		return "无"
	}

	// 最多显示前3个
	count := 3
	if len(anomalies) < count {
		count = len(anomalies)
	}

	var result string
	for i := 0; i < count; i++ {
		if i > 0 {
			result += "; "
		}
		result += fmt.Sprintf("%s @ %s", anomalies[i].Type, anomalies[i].Time.Format(layout))
	}
	return result
}

// printAnomalyDetailList 打印详细异常列表
func printAnomalyDetailList(categories map[string][]common.TrendAnomaly, layout string) {
	fmt.Println("[异常点列表]")
	
	// 按固定顺���输出
	keys := []string{"可用内存 (Available)", "匿名页 (AnonPages)", "Slab", "Swap"}
	
	index := 1
	for _, key := range keys {
		anomalies, exists := categories[key]
		if !exists || len(anomalies) == 0 {
			fmt.Printf("\n%d. %s\n   - 无异常\n", index, key)
			index++
			continue
		}

		fmt.Printf("\n%d. %s\n", index, key)
		
		// 限制显示数量，防止刷屏 (例如前 10 个)
		limit := 10
		if len(anomalies) > limit {
			fmt.Printf("   (共 %d 个异常，仅显示前 %d 个最严重的)\n", len(anomalies), limit)
			anomalies = anomalies[:limit]
		}

		for _, a := range anomalies {
			fmt.Printf("   - 时间: %s\n", a.Time.Format(layout))
			fmt.Printf("     类型: %s\n", a.Type)
			
			// 根据类型格式化详情
			if a.Type == "V型波动" {
				fmt.Printf("     详情: 跌落 %.2f GB (%.2f -> %.2f GB)\n", a.Value, kbToGB(a.StartVal*1024), kbToGB(a.EndVal*1024))
			} else if a.RuleName == "趋势斜率差异" {
				fmt.Printf("     详情: 斜率变化 %.2f MB/点 (长期 %.2f -> 短期 %.2f)\n", a.Value, a.StartVal, a.EndVal)
			} else {
				fmt.Printf("     详情: %.2f -> %.2f GB (变化量: %.2f GB)\n", kbToGB(a.StartVal*1024), kbToGB(a.EndVal*1024), a.Value/1024.0) // a.Value 是 MB
			}
			
			fmt.Printf("     规则: 命中\"%s\"\n", a.RuleName)
			
			// 格式化阈值显示
			threshStr := ""
			if a.RuleName == "趋势斜率差异" {
				threshStr = fmt.Sprintf("%.2f MB/点", a.Threshold)
			} else {
				threshStr = fmt.Sprintf("%.2f GB", a.Threshold/1024.0) // Threshold 是 MB
			}
			fmt.Printf("     阈值: %s\n", threshStr)
			fmt.Println()
		}
		index++
	}
	fmt.Println()
}
