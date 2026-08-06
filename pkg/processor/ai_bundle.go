package processor

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/pkg/aitypes"
	"oswbb-analyse/pkg/common"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/findings"
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/output"
	"oswbb-analyse/pkg/top"
	"sort"
	"strings"
	"time"
)

type AIConfig struct {
	Enabled     bool
	Debug       bool
	ModelPath   string
	RuntimePath string
	Timeout     time.Duration
}

type AIDiagnoser = diagnosis.Provider

type analysisBundle struct {
	Hostname string
	Merged   bool

	IOStat      *iostat.IOStatLog
	IOStatFiles int

	MemInfo      *meminfo.MemInfoLog
	MemInfoFiles int

	Top      *top.TopLog
	TopFiles int

	ParseErrs []error
}

func NewFileProcessor() *FileProcessor {
	return &FileProcessor{cfg: config.Default()}
}

// NewFileProcessorWithService keeps legacy callers working.
//
// Deprecated: new code should pass diagnosis.Provider through app.Options.
func NewFileProcessorWithService(aiService AIDiagnoser) *FileProcessor {
	return NewFileProcessorWithServiceAndConfig(aiService, config.Default())
}

func NewFileProcessorWithConfig(cfg config.Config) *FileProcessor {
	return NewFileProcessorWithServiceAndConfig(nil, cfg)
}

// NewFileProcessorWithServiceAndConfig keeps legacy callers working.
//
// Deprecated: new code should pass diagnosis.Provider through app.Options.
func NewFileProcessorWithServiceAndConfig(aiService AIDiagnoser, cfg config.Config) *FileProcessor {
	if cfg == (config.Config{}) {
		cfg = config.Default()
	}
	return &FileProcessor{aiService: aiService, cfg: cfg}
}

func detectFileType(filename string) (string, error) {
	fileName := strings.ToLower(filename)
	switch {
	case strings.Contains(fileName, "iostat"):
		return "iostat", nil
	case strings.Contains(fileName, "meminfo"):
		return "meminfo", nil
	case strings.Contains(fileName, "top"):
		return "top", nil
	default:
		return "", fmt.Errorf("无法识别文件类型，文件名应包含 'iostat', 'meminfo' 或 'top'")
	}
}

func parseSingleBundle(filename string) (*analysisBundle, error) {
	fileType, err := detectFileType(filename)
	if err != nil {
		return nil, err
	}

	bundle := &analysisBundle{
		Hostname: extractHostname(filename),
	}

	// Compatibility path: parser selection stays here for legacy public APIs
	// and existing file/AI side effects; new Report construction is delegated
	// through ModuleReportRunner when app.Runner injects one.
	switch fileType {
	case "iostat":
		parser := &iostat.IOStatParser{}
		log, err := parser.ParseFile(filename)
		if err != nil {
			return nil, fmt.Errorf("解析iostat文件失败: %v", err)
		}
		bundle.IOStat = log
		bundle.IOStatFiles = 1
	case "meminfo":
		parser := &meminfo.MemInfoParser{}
		log, err := parser.ParseFile(filename)
		if err != nil {
			return nil, fmt.Errorf("解析meminfo文件失败: %v", err)
		}
		bundle.MemInfo = log
		bundle.MemInfoFiles = 1
	case "top":
		parser := top.NewTopParser()
		log, err := parser.ParseFile(filename)
		if err != nil {
			return nil, fmt.Errorf("解析top文件失败: %v", err)
		}
		bundle.Top = log
		bundle.TopFiles = 1
	}

	return bundle, nil
}

func parseMergedBundle(hostname string, fileTypes map[string][]string) (*analysisBundle, error) {
	bundle := &analysisBundle{
		Hostname: hostname,
		Merged:   true,
	}

	if files := fileTypes["iostat"]; len(files) > 0 {
		log, errs := mergeIOStatFiles(files, &iostat.IOStatParser{})
		bundle.ParseErrs = append(bundle.ParseErrs, errs...)
		bundle.IOStat = log
		bundle.IOStatFiles = len(files)
	}

	if files := fileTypes["meminfo"]; len(files) > 0 {
		log, errs := mergeMemInfoFiles(files, &meminfo.MemInfoParser{})
		bundle.ParseErrs = append(bundle.ParseErrs, errs...)
		bundle.MemInfo = log
		bundle.MemInfoFiles = len(files)
	}

	if files := fileTypes["top"]; len(files) > 0 {
		log, errs := mergeTopFiles(files, top.NewTopParser())
		bundle.ParseErrs = append(bundle.ParseErrs, errs...)
		bundle.Top = log
		bundle.TopFiles = len(files)
	}
	if files := fileTypes["mpstat"]; len(files) > 0 {
		cpuCount, errs := parseMPStatCPUCountFiles(files)
		bundle.ParseErrs = append(bundle.ParseErrs, errs...)
		if cpuCount > 0 && bundle.Top != nil {
			applyTopCPUCount(bundle.Top, cpuCount)
		}
	}

	if !bundle.hasData() {
		return nil, fmt.Errorf("没有有效的数据可以分析")
	}

	return bundle, nil
}

func mergeTopFiles(filenames []string, parser *top.TopParser) (*top.TopLog, []error) {
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

	if len(allSnapshots) == 0 {
		return nil, parseErrs
	}

	sort.Slice(allSnapshots, func(i, j int) bool {
		return allSnapshots[i].Timestamp.Before(allSnapshots[j].Timestamp)
	})

	return &top.TopLog{Snapshots: allSnapshots}, parseErrs
}

func applyTopCPUCount(log *top.TopLog, cpuCount int) {
	if log == nil || cpuCount <= 0 {
		return
	}
	for i := range log.Snapshots {
		log.Snapshots[i].CPUCount = cpuCount
	}
}

func (bundle *analysisBundle) hasData() bool {
	return (bundle.IOStat != nil && len(bundle.IOStat.Data) > 0) ||
		(bundle.MemInfo != nil && len(bundle.MemInfo.Data) > 0) ||
		(bundle.Top != nil && len(bundle.Top.Snapshots) > 0)
}

func (bundle *analysisBundle) coreBundle() *core.AnalysisBundle {
	if bundle == nil {
		return nil
	}
	return &core.AnalysisBundle{
		Hostname: bundle.Hostname,
		IOStat:   bundle.IOStat,
		Meminfo:  bundle.MemInfo,
		Top:      bundle.Top,
	}
}

func (fp *FileProcessor) executeBundle(bundle *analysisBundle, startTimeStr, endTimeStr, outputFormat string, cst *time.Location, aiConfig AIConfig) error {
	if bundle == nil || !bundle.hasData() {
		return fmt.Errorf("没有有效的数据可以分析")
	}

	if len(bundle.ParseErrs) > 0 && outputFormat == outputFormatReport {
		logParseErrors(bundle.ParseErrs)
	}

	// Compatibility path: legacy "ml" output with AI enabled writes prompt CSV
	// sections before calling the diagnosis provider. Rules-only "ml" keeps the
	// old module CSV export path below.
	if outputFormat == outputFormatML && aiConfig.Enabled {
		aiResult := fp.buildMLAIDiagnosis(bundle, startTimeStr, endTimeStr, cst, aiConfig)
		if err := fp.writeAIDiagnosisReport(aiResult); err != nil {
			return err
		}
		if aiResult.Status == diagnosis.AIStatusFallback {
			if err := fp.writeFindingsSummary(collectBundleFindings(bundle, startTimeStr, endTimeStr, cst, fp.cfg)); err != nil {
				return err
			}
		}
		return nil
	}

	aiResult := fp.buildAIDiagnosis(bundle, startTimeStr, endTimeStr, cst, aiConfig)

	if outputFormat == outputFormatReport && bundle.Merged {
		if err := fp.writeHostLevelSummary(bundle, startTimeStr, endTimeStr, cst); err != nil {
			return err
		}
	}

	// Compatibility path: processor still owns parse errors, host summary, AI
	// and output side effects. Module Report data is delegated to the injected
	// ModuleReportRunner when available, otherwise old public APIs use the
	// module analyzer fallback.
	coreBundle := bundle.coreBundle()
	if bundle.IOStat != nil {
		opts := buildIOStatOptions(bundle, outputFormat, startTimeStr, endTimeStr, cst, aiResult, fp.cfg)
		opts.reportRunner = fp.reportRunner
		opts.reportBundle = coreBundle
		opts.outputSink = fp.effectiveOutputSink()
		if err := analyzeIOStatLog(bundle.IOStat, opts); err != nil {
			return err
		}
	}
	if bundle.MemInfo != nil {
		opts := buildMemInfoOptions(bundle, outputFormat, startTimeStr, endTimeStr, cst, aiResult, fp.cfg)
		opts.reportRunner = fp.reportRunner
		opts.reportBundle = coreBundle
		opts.outputSink = fp.effectiveOutputSink()
		if err := analyzeMemInfoLog(bundle.MemInfo, opts, chooseMemInfoLayout(bundle)); err != nil {
			return err
		}
	}
	if bundle.Top != nil {
		opts := buildTopOptions(bundle, outputFormat, startTimeStr, endTimeStr, cst, aiResult, fp.cfg)
		opts.reportRunner = fp.reportRunner
		opts.reportBundle = coreBundle
		opts.outputSink = fp.effectiveOutputSink()
		if err := analyzeTopLog(bundle.Top, opts); err != nil {
			return err
		}
	}

	if outputFormat == outputFormatReport && aiConfig.Enabled {
		if err := fp.writeAIDiagnosisReport(aiResult); err != nil {
			return err
		}
	}

	return nil
}

func (fp *FileProcessor) buildAIDiagnosis(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location, aiConfig AIConfig) diagnosis.AIResult {
	start, end, err := resolveBundleTimeRange(bundle, startTimeStr, endTimeStr, cst)
	if err != nil {
		return diagnosis.FallbackResult(aitypes.DefaultModelName(), fmt.Sprintf("时间范围解析失败: %v", err), 0)
	}

	contextInput := diagnosis.BuildContext(diagnosis.BuildInput{
		Hostname: bundle.Hostname,
		Start:    start,
		End:      end,
		IOStat:   bundle.IOStat,
		MemInfo:  bundle.MemInfo,
		Top:      bundle.Top,
		Config:   fp.cfg,
	})

	return diagnosis.Run(context.Background(), fp.aiService, aitypes.Options{
		Enabled:     aiConfig.Enabled,
		Debug:       aiConfig.Debug,
		ModelPath:   aiConfig.ModelPath,
		RuntimePath: aiConfig.RuntimePath,
		Timeout:     aiConfig.Timeout,
	}, contextInput)
}

func (fp *FileProcessor) buildMLAIDiagnosis(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location, aiConfig AIConfig) diagnosis.AIResult {
	start, end, err := resolveBundleTimeRange(bundle, startTimeStr, endTimeStr, cst)
	if err != nil {
		return diagnosis.FallbackResult(aitypes.DefaultModelName(), fmt.Sprintf("时间范围解析失败: %v", err), 0)
	}

	mlInput, err := exportMLCSVPromptInput(bundle, start, end, fp.cfg)
	if err != nil {
		return diagnosis.FallbackResult(aitypes.DefaultModelName(), err.Error(), 0)
	}

	return diagnosis.RunML(context.Background(), fp.aiService, aitypes.Options{
		Enabled:     aiConfig.Enabled,
		Debug:       aiConfig.Debug,
		ModelPath:   aiConfig.ModelPath,
		RuntimePath: aiConfig.RuntimePath,
		Timeout:     aiConfig.Timeout,
	}, mlInput)
}

func exportMLCSVPromptInput(bundle *analysisBundle, start, end time.Time, cfg config.Config) (aitypes.MLPromptInput, error) {
	if cfg == (config.Config{}) {
		cfg = config.Default()
	}
	input := aitypes.MLPromptInput{
		Hostname:  bundle.Hostname,
		StartTime: start.Format(TimeLayout),
		EndTime:   end.Format(TimeLayout),
	}
	formatter := output.NewCSVFormatter()
	aiDiagnosis := diagnosis.DisabledResult()

	if bundle.IOStat != nil {
		rows := output.ConvertIOStatData(bundle.IOStat, start, end)
		input.Findings = append(input.Findings, findings.BuildIOStatFindingsWithConfig(bundle.IOStat, start, end, cfg.Iostat)...)
		filename := analysisOutputFilename("iostat", bundle.Hostname, "csv")
		if err := formatter.OutputIOStatData(output.IOStatExport{Data: rows, AIDiagnosis: aiDiagnosis}, filename); err != nil {
			return aitypes.MLPromptInput{}, err
		}
		section, err := buildCSVMLSection("ml-iostat-data", "iostat", filename)
		if err != nil {
			return aitypes.MLPromptInput{}, err
		}
		input.Sections = append(input.Sections, section)
	}

	if bundle.MemInfo != nil {
		rows := output.ConvertMemInfoData(bundle.MemInfo, start, end)
		input.Findings = append(input.Findings, findings.BuildMemInfoFindingsWithConfig(bundle.MemInfo, start, end, cfg.Meminfo)...)
		filename := analysisOutputFilename("meminfo", bundle.Hostname, "csv")
		if err := formatter.OutputMemInfoData(output.MemInfoExport{Data: rows, AIDiagnosis: aiDiagnosis}, filename); err != nil {
			return aitypes.MLPromptInput{}, err
		}
		section, err := buildCSVMLSection("ml-meminfo-data", "meminfo", filename)
		if err != nil {
			return aitypes.MLPromptInput{}, err
		}
		input.Sections = append(input.Sections, section)
	}

	if bundle.Top != nil {
		rows := output.ConvertTopData(bundle.Top, start, end)
		input.Findings = append(input.Findings, findings.BuildTopFindingsWithConfig(bundle.Top, start, end, cfg.Top)...)
		filename := analysisOutputFilename("top", bundle.Hostname, "csv")
		if err := formatter.OutputTopData(output.TopExport{Data: rows, AIDiagnosis: aiDiagnosis}, filename); err != nil {
			return aitypes.MLPromptInput{}, err
		}
		section, err := buildCSVMLSection("ml-top-data", "top", filename)
		if err != nil {
			return aitypes.MLPromptInput{}, err
		}
		input.Sections = append(input.Sections, section)

		processCSV, processRows, err := formatTopProcessCSV(bundle.Top, start, end)
		if err != nil {
			return aitypes.MLPromptInput{}, err
		}
		if processRows > 0 {
			processFilename := analysisOutputFilename("top_processes", bundle.Hostname, "csv")
			if err := os.WriteFile(processFilename, []byte(processCSV+"\n"), 0o644); err != nil {
				return aitypes.MLPromptInput{}, fmt.Errorf("写入 top process CSV 文件失败: %v", err)
			}
			processSection, err := buildCSVMLSectionWithFormat(
				"ml-top-processes",
				"top",
				"top_process_csv",
				processFilename,
				"从 top 进程表提取的完整进程行；包含 PID/USER/STATE/CPU/MEM/COMMAND，AI 阶段按原始快照顺序分批输入。",
			)
			if err != nil {
				return aitypes.MLPromptInput{}, err
			}
			input.Sections = append(input.Sections, processSection)
		}
	}

	if len(input.Sections) == 0 {
		return aitypes.MLPromptInput{}, fmt.Errorf("没有可供模型使用的 ML CSV 数据")
	}
	return input, nil
}

func buildCSVMLSection(id, module, filename string) (aitypes.MLSection, error) {
	return buildCSVMLSectionWithFormat(id, module, module+"_csv", filename, "从本地 ml CSV 读取的完整表格数据；AI 阶段按原始顺序分批输入。")
}

func buildCSVMLSectionWithFormat(id, module, format, filename, description string) (aitypes.MLSection, error) {
	records, err := readCSVRecords(filename)
	if err != nil {
		return aitypes.MLSection{}, err
	}
	if len(records) == 0 {
		return aitypes.MLSection{}, fmt.Errorf("CSV 文件为空: %s", filename)
	}

	header := records[0]
	rows := records[1:]
	data, err := formatCSVRecords(header, rows)
	if err != nil {
		return aitypes.MLSection{}, err
	}

	return aitypes.MLSection{
		ID:           id,
		Module:       module,
		Format:       format,
		FilePath:     filename,
		Description:  description,
		Data:         data,
		TotalRows:    len(rows),
		SelectedRows: len(rows),
	}, nil
}

func formatTopProcessCSV(log *top.TopLog, start, end time.Time) (string, int, error) {
	if log == nil {
		return "", 0, nil
	}

	header := []string{"timestamp", "pid", "user", "state", "cpu_percent", "mem_percent", "virt_kb", "res_kb", "shr_kb", "command"}
	var rows [][]string
	for _, snap := range log.Snapshots {
		if snap.Timestamp.Before(start) || snap.Timestamp.After(end) {
			continue
		}
		timestamp := snap.Timestamp.Format(TimeLayout)
		for _, process := range snap.Processes {
			rows = append(rows, []string{
				timestamp,
				fmt.Sprintf("%d", process.PID),
				process.User,
				process.State,
				fmt.Sprintf("%.1f", process.CPUPercent),
				fmt.Sprintf("%.1f", process.MemPercent),
				fmt.Sprintf("%d", process.VirtKB),
				fmt.Sprintf("%d", process.ResKB),
				fmt.Sprintf("%d", process.ShrKB),
				process.Command,
			})
		}
	}
	if len(rows) == 0 {
		return "", 0, nil
	}

	data, err := formatCSVRecords(header, rows)
	if err != nil {
		return "", 0, err
	}
	return data, len(rows), nil
}

func readCSVRecords(filename string) ([][]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取 ML CSV 文件失败 %s: %v", filename, err)
	}
	reader := csv.NewReader(bytes.NewReader(content))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("解析 ML CSV 文件失败 %s: %v", filename, err)
	}
	return records, nil
}

func formatCSVRecords(header []string, rows [][]string) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.Write(header); err != nil {
		return "", err
	}
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func buildMLDiagnosisContext(bundle *analysisBundle, start, end time.Time) diagnosis.Context {
	contextInput := diagnosis.BuildContext(diagnosis.BuildInput{
		Hostname: bundle.Hostname,
		Start:    start,
		End:      end,
		IOStat:   bundle.IOStat,
		MemInfo:  bundle.MemInfo,
		Top:      bundle.Top,
	})
	contextInput.Notes = append(contextInput.Notes,
		"ml 模式会输入工具提取后的摘要和异常候选点；模型需要判断是否构成异常以及异常时间点。",
		"若只有 summary 证据而没有 anomaly 证据，应谨慎判断，可以返回空 incidents。",
	)

	if bundle.IOStat != nil {
		contextInput.Evidence = append(contextInput.Evidence, buildMLIOStatEvidence(bundle.IOStat, start, end)...)
	}
	if bundle.MemInfo != nil {
		contextInput.Evidence = append(contextInput.Evidence, buildMLMemInfoEvidence(bundle.MemInfo, start, end)...)
	}
	if bundle.Top != nil {
		contextInput.Evidence = append(contextInput.Evidence, buildMLTopEvidence(bundle.Top, start, end)...)
	}

	if len(contextInput.Evidence) > 24 {
		contextInput.Evidence = contextInput.Evidence[:24]
	}
	return contextInput
}

func buildMLIOStatEvidence(log *iostat.IOStatLog, start, end time.Time) []diagnosis.Evidence {
	if log == nil {
		return nil
	}

	maxWait, avgWait, ok := mlSummarizeIOWait(log, start, end)
	if !ok {
		return nil
	}

	return []diagnosis.Evidence{{
		ID:      "iostat-summary",
		Source:  "iostat",
		Level:   diagnosis.SignalLevelSoft,
		Title:   "iostat 格式化摘要",
		Summary: fmt.Sprintf("CPU iowait 平均 %.1f%%，峰值 %.1f%%，设备数 %d。", avgWait, maxWait, len(log.GetAllDevices())),
		Metrics: map[string]float64{
			"cpu_iowait_avg": avgWait,
			"cpu_iowait_max": maxWait,
			"device_count":   float64(len(log.GetAllDevices())),
		},
		Tags: []string{"ml", "summary", "iostat"},
	}}
}

func buildMLMemInfoEvidence(log *meminfo.MemInfoLog, start, end time.Time) []diagnosis.Evidence {
	return buildMLMemInfoEvidenceWithConfig(log, start, end, config.Default().Meminfo)
}

func buildMLMemInfoEvidenceWithConfig(log *meminfo.MemInfoLog, start, end time.Time, cfg config.MeminfoConfig) []diagnosis.Evidence {
	cfg = cfg.WithDefaults()
	if log == nil {
		return nil
	}

	data := filterMemInfoRange(log.Data, start, end)
	if len(data) == 0 {
		return nil
	}

	latest := data[len(data)-1]
	if latest.MemStats.MemTotal == 0 {
		return nil
	}

	memTotalKB := float64(latest.MemStats.MemTotal)
	memTotalMB := kbToMB(memTotalKB)
	availPct := pct(float64(meminfo.EffectiveMemAvailableKB(latest.MemStats)), memTotalKB)
	availMin, availMax, availAvg, _ := summarizeSeries(data, func(ms meminfo.MemStats) float64 { return float64(meminfo.EffectiveMemAvailableKB(ms)) })
	anonMin, anonMax, anonAvg, _ := summarizeSeries(data, func(ms meminfo.MemStats) float64 { return float64(ms.AnonPages) })

	evidence := []diagnosis.Evidence{{
		ID:      "meminfo-summary",
		Source:  "meminfo",
		Level:   diagnosis.SignalLevelSoft,
		Title:   "meminfo 格式化摘要",
		Summary: fmt.Sprintf("可用内存当前 %.1f%%，范围 %.2f~%.2f GB，匿名页范围 %.2f~%.2f GB。", availPct, kbToGB(availMin), kbToGB(availMax), kbToGB(anonMin), kbToGB(anonMax)),
		Time:    latest.Timestamp.Format(TimeLayout),
		Metrics: map[string]float64{
			"mem_available_pct":    availPct,
			"mem_available_avg_gb": kbToGB(availAvg),
			"anon_pages_avg_gb":    kbToGB(anonAvg),
		},
		Tags: []string{"ml", "summary", "meminfo"},
	}}

	availAnomalies := findSignificantTrendChangeWithConfig(data, func(ms meminfo.MemStats) float64 { return float64(meminfo.EffectiveMemAvailableKB(ms)) }, cfg.SlopeBurstMBPerSample, memTotalMB, cfg)
	availAnomalies = append(availAnomalies, detectVPattern(data, func(ms meminfo.MemStats) float64 { return float64(meminfo.EffectiveMemAvailableKB(ms)) }, cfg)...)
	availAnomalies = filterAvailablePressureAnomalies(availAnomalies, data, cfg)
	evidence = append(evidence, trendAnomalyEvidence("meminfo-available-anomaly", "MemAvailable 可用内存突变", "meminfo", []string{"memory", "available"}, availAnomalies)...)

	anonAnomalies := findSignificantTrendChangeWithConfig(data, func(ms meminfo.MemStats) float64 { return float64(ms.AnonPages) }, cfg.SlopeBurstMBPerSample, memTotalMB, cfg)
	evidence = append(evidence, trendAnomalyEvidence("meminfo-anon-anomaly", "AnonPages 匿名页突变", "meminfo", []string{"memory", "anon"}, anonAnomalies)...)

	slabAnomalies := findSignificantTrendChangeWithConfig(data, func(ms meminfo.MemStats) float64 { return float64(ms.Slab) }, cfg.SlabSlopeBurstMBPerSample, memTotalMB, cfg)
	evidence = append(evidence, trendAnomalyEvidence("meminfo-slab-anomaly", "Slab 突变", "meminfo", []string{"memory", "slab"}, slabAnomalies)...)

	if latest.MemStats.SwapTotal > 0 {
		swapTotalMB := float64(latest.MemStats.SwapTotal) / 1024.0
		swapThreshold := (swapTotalMB * (cfg.SwapBurstPct / 100.0)) / float64(cfg.ShortWindowPoints)
		swapAnomalies := findSignificantTrendChangeWithConfig(data, func(ms meminfo.MemStats) float64 { return float64(ms.SwapFree) }, swapThreshold, memTotalMB, cfg)
		evidence = append(evidence, trendAnomalyEvidence("meminfo-swap-anomaly", "SwapFree 突变", "meminfo", []string{"memory", "swap"}, swapAnomalies)...)
	}

	return evidence
}

func buildMLTopEvidence(log *top.TopLog, start, end time.Time) []diagnosis.Evidence {
	if log == nil {
		return nil
	}

	data := filterTopRange(log.Snapshots, start, end)
	if len(data) == 0 {
		return nil
	}

	loadAvg, loadMax := mlSummarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.Load1 })
	waitAvg, waitMax := mlSummarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return s.CpuWait })
	idleAvg, idleMin := mlSummarizeTopMetricMin(data, func(s top.TopSnapshot) float64 { return s.CpuIdle })
	runningAvg, runningMax := mlSummarizeTopMetricMax(data, func(s top.TopSnapshot) float64 { return float64(s.TaskRunning) })

	return []diagnosis.Evidence{{
		ID:      "top-summary",
		Source:  "top",
		Level:   diagnosis.SignalLevelSoft,
		Title:   "top 格式化摘要",
		Summary: fmt.Sprintf("Load1 平均 %.2f 峰值 %.2f；Running 峰值 %.0f；CPU wait 平均 %.1f%% 峰值 %.1f%%；Idle 平均 %.1f%% 最低 %.1f%%。", loadAvg, loadMax, runningMax, waitAvg, waitMax, idleAvg, idleMin),
		Metrics: map[string]float64{
			"load1_avg":        loadAvg,
			"load1_max":        loadMax,
			"task_running_avg": runningAvg,
			"task_running_max": runningMax,
			"cpu_wait_avg":     waitAvg,
			"cpu_wait_max":     waitMax,
			"cpu_idle_avg":     idleAvg,
			"cpu_idle_min":     idleMin,
		},
		Tags: []string{"ml", "summary", "top"},
	}}
}

func trendAnomalyEvidence(prefix, title, source string, tags []string, anomalies []common.TrendAnomaly) []diagnosis.Evidence {
	if len(anomalies) == 0 {
		return nil
	}

	limit := 3
	if len(anomalies) < limit {
		limit = len(anomalies)
	}

	evidence := make([]diagnosis.Evidence, 0, limit)
	for i := 0; i < limit; i++ {
		anomaly := anomalies[i]
		evidence = append(evidence, diagnosis.Evidence{
			ID:      fmt.Sprintf("%s-%d", prefix, i+1),
			Source:  source,
			Level:   diagnosis.SignalLevelHard,
			Title:   title,
			Summary: fmt.Sprintf("%s @ %s，变化 %.2f MB，规则: %s。", anomaly.Type, anomaly.Time.Format(TimeLayout), anomaly.Value, anomaly.RuleName),
			Time:    anomaly.Time.Format(TimeLayout),
			Metrics: map[string]float64{
				"change_mb":       anomaly.Value,
				"start_value_mb":  anomaly.StartVal,
				"end_value_mb":    anomaly.EndVal,
				"threshold_mb":    anomaly.Threshold,
				"is_sudden_point": boolAsFloat(anomaly.IsSudden),
			},
			Tags: append([]string{"ml", "anomaly", anomaly.Type}, tags...),
		})
	}
	return evidence
}

func boolAsFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func mlSummarizeIOWait(log *iostat.IOStatLog, start, end time.Time) (maxVal, avgVal float64, ok bool) {
	sum := 0.0
	count := 0.0
	for _, item := range log.Data {
		if item.Timestamp.Before(start) || item.Timestamp.After(end) {
			continue
		}
		ok = true
		sum += item.CPU.IOWait
		count++
		if item.CPU.IOWait > maxVal {
			maxVal = item.CPU.IOWait
		}
	}
	if !ok || count == 0 {
		return 0, 0, false
	}
	return maxVal, sum / count, true
}

func mlSummarizeTopMetricMax(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64) (avg, maxVal float64) {
	if len(data) == 0 {
		return 0, 0
	}
	sum := 0.0
	maxVal = extractor(data[0])
	for _, item := range data {
		value := extractor(item)
		sum += value
		if value > maxVal {
			maxVal = value
		}
	}
	return sum / float64(len(data)), maxVal
}

func mlSummarizeTopMetricMin(data []top.TopSnapshot, extractor func(top.TopSnapshot) float64) (avg, minVal float64) {
	if len(data) == 0 {
		return 0, 0
	}
	sum := 0.0
	minVal = extractor(data[0])
	for _, item := range data {
		value := extractor(item)
		sum += value
		if value < minVal {
			minVal = value
		}
	}
	return sum / float64(len(data)), minVal
}

func resolveBundleTimeRange(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location) (time.Time, time.Time, error) {
	var (
		requestStart time.Time
		requestEnd   time.Time
		hasRequest   bool
	)

	if startTimeStr != "" && endTimeStr != "" {
		startTime, err := time.ParseInLocation(TimeLayout, startTimeStr, cst)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("开始时间格式错误: %v", err)
		}
		endTime, err := time.ParseInLocation(TimeLayout, endTimeStr, cst)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("结束时间格式错误: %v", err)
		}
		requestStart = startTime
		requestEnd = endTime
		hasRequest = true
	}

	var starts []time.Time
	var ends []time.Time
	if bundle.IOStat != nil {
		start, end := bundle.IOStat.GetTimeRange()
		appendBoundedRange(&starts, &ends, start, end, requestStart, requestEnd, hasRequest)
	}
	if bundle.MemInfo != nil {
		start, end := bundle.MemInfo.GetTimeRange()
		appendBoundedRange(&starts, &ends, start, end, requestStart, requestEnd, hasRequest)
	}
	if bundle.Top != nil {
		start, end := bundle.Top.GetTimeRange()
		appendBoundedRange(&starts, &ends, start, end, requestStart, requestEnd, hasRequest)
	}

	if len(starts) == 0 {
		if hasRequest {
			return time.Time{}, time.Time{}, fmt.Errorf("指定时间范围内无可用于 AI 诊断的数据")
		}
		return time.Time{}, time.Time{}, fmt.Errorf("没有可用时间范围")
	}

	startTime := starts[0]
	endTime := ends[0]
	for i := 1; i < len(starts); i++ {
		if starts[i].After(startTime) {
			startTime = starts[i]
		}
		if ends[i].Before(endTime) {
			endTime = ends[i]
		}
	}

	if endTime.Before(startTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("各模块日志时间范围无交集，无法进行联合 AI 诊断")
	}

	return startTime, endTime, nil
}

func appendBoundedRange(starts, ends *[]time.Time, start, end, requestStart, requestEnd time.Time, hasRequest bool) {
	if hasRequest {
		if start.Before(requestStart) {
			start = requestStart
		}
		if end.After(requestEnd) {
			end = requestEnd
		}
	}

	if end.Before(start) {
		return
	}

	*starts = append(*starts, start)
	*ends = append(*ends, end)
}

func buildIOStatOptions(bundle *analysisBundle, outputFormat, startTimeStr, endTimeStr string, cst *time.Location, aiResult diagnosis.AIResult, cfg config.Config) analysisOptions {
	opts := analysisOptions{
		outputFormat:  outputFormat,
		startTimeStr:  startTimeStr,
		endTimeStr:    endTimeStr,
		location:      cst,
		hostname:      bundle.Hostname,
		rangeScope:    "文件",
		aiDiagnosis:   aiResult,
		iostatConfig:  cfg.Iostat,
		meminfoConfig: cfg.Meminfo,
		topConfig:     cfg.Top,
	}

	if bundle.Merged {
		opts.introLines = []string{fmt.Sprintf("成功合并 %d 个文件，总共 %d 个数据点", bundle.IOStatFiles, len(bundle.IOStat.Data))}
		opts.leadingBlankIntro = true
		opts.rangeScope = "合并数据"
		return opts
	}

	opts.introLines = []string{
		fmt.Sprintf("成功解析iostat日志: %s", bundle.IOStat.Header),
		fmt.Sprintf("总共 %d 个数据点", len(bundle.IOStat.Data)),
	}
	return opts
}

func buildMemInfoOptions(bundle *analysisBundle, outputFormat, startTimeStr, endTimeStr string, cst *time.Location, aiResult diagnosis.AIResult, cfg config.Config) analysisOptions {
	opts := analysisOptions{
		outputFormat:  outputFormat,
		startTimeStr:  startTimeStr,
		endTimeStr:    endTimeStr,
		location:      cst,
		hostname:      bundle.Hostname,
		rangeScope:    "文件",
		aiDiagnosis:   aiResult,
		iostatConfig:  cfg.Iostat,
		meminfoConfig: cfg.Meminfo,
		topConfig:     cfg.Top,
	}

	if bundle.Merged {
		opts.introLines = []string{fmt.Sprintf("成功合并 %d 个文件，总共 %d 个数据点", bundle.MemInfoFiles, len(bundle.MemInfo.Data))}
		opts.leadingBlankIntro = true
		opts.rangeScope = "合并数据"
		return opts
	}

	opts.introLines = []string{
		"成功解析meminfo日志",
		fmt.Sprintf("总共 %d 个数据点", len(bundle.MemInfo.Data)),
	}
	return opts
}

func buildTopOptions(bundle *analysisBundle, outputFormat, startTimeStr, endTimeStr string, cst *time.Location, aiResult diagnosis.AIResult, cfg config.Config) analysisOptions {
	opts := analysisOptions{
		outputFormat:  outputFormat,
		startTimeStr:  startTimeStr,
		endTimeStr:    endTimeStr,
		location:      cst,
		hostname:      bundle.Hostname,
		rangeScope:    "文件",
		aiDiagnosis:   aiResult,
		iostatConfig:  cfg.Iostat,
		meminfoConfig: cfg.Meminfo,
		topConfig:     cfg.Top,
	}

	if bundle.Merged {
		opts.introLines = []string{fmt.Sprintf("成功合并 %d 个文件，总共 %d 个数据点", bundle.TopFiles, len(bundle.Top.Snapshots))}
		opts.leadingBlankIntro = true
		opts.rangeScope = "合并数据"
		return opts
	}

	opts.introLines = []string{
		"成功解析top日志",
		fmt.Sprintf("总共 %d 个数据点", len(bundle.Top.Snapshots)),
	}
	return opts
}

func chooseMemInfoLayout(bundle *analysisBundle) string {
	if bundle != nil && bundle.Merged {
		return TimeLayout
	}
	return TimeShortLayout
}

func (fp *FileProcessor) writeAIDiagnosisReport(result diagnosis.AIResult) error {
	return fp.effectiveOutputSink().Write(context.Background(), internaloutput.OutputRequest{
		Format:   internaloutput.FormatText,
		Data:     []byte(diagnosis.FormatResultText(result)),
		ToStdout: true,
	})
}

func (fp *FileProcessor) writeFindingsSummary(items []findings.Finding) error {
	return fp.effectiveOutputSink().Write(context.Background(), internaloutput.OutputRequest{
		Format:   internaloutput.FormatText,
		Data:     []byte(output.RenderFindingsSummary(items)),
		ToStdout: true,
	})
}

func (fp *FileProcessor) writeHostLevelSummary(bundle *analysisBundle, startTimeStr, endTimeStr string, cst *time.Location) error {
	text, err := renderHostLevelSummaryText(bundle, startTimeStr, endTimeStr, cst, fp.cfg)
	if err != nil {
		text = fmt.Sprintf("主机级结论生成失败: %v\n", err)
	}
	return fp.effectiveOutputSink().Write(context.Background(), internaloutput.OutputRequest{
		Format:   internaloutput.FormatText,
		Data:     []byte(text),
		ToStdout: true,
	})
}
