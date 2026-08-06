package localai

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"oswbb-analyse/internal/logging"
	"oswbb-analyse/pkg/aitypes"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/findings"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultModelFile   = aitypes.DefaultModelFile
	defaultPromptLimit = 2048
	defaultCtxSize     = 32768
	defaultTimeout     = 60 * time.Second
	defaultMLBatchRows = 80
)

func DefaultModelName() string {
	return aitypes.DefaultModelName()
}

type Options = aitypes.Options

type Request struct {
	RuntimePath string
	ModelPath   string
	Prompt      string
	MaxTokens   int
	ContextSize int
	Debug       bool
}

type Runner interface {
	Run(ctx context.Context, req Request) (string, error)
}

type Service struct {
	runner Runner
}

type MLSection = aitypes.MLSection

type MLPromptInput = aitypes.MLPromptInput

func NewService(runner Runner) *Service {
	if runner == nil {
		runner = CLIRunner{}
	}
	return &Service{runner: runner}
}

func (s *Service) Diagnose(ctx context.Context, opts Options, input diagnosis.Context) diagnosis.AIResult {
	if !opts.Enabled {
		result := diagnosis.DisabledResult()
		result.EvidenceCount = len(input.Evidence)
		return result
	}

	modelName := modelDisplayName(opts.ModelPath)
	if len(input.Evidence) == 0 {
		return diagnosis.FallbackResult(modelName, "没有可供模型使用的结构化证据", 0)
	}

	prompt := BuildPrompt(input)
	if opts.Debug {
		debugPrintPrompt("evidence", prompt)
	}
	return s.runDiagnosis(ctx, opts, modelName, prompt, input.EvidenceIDs(), len(input.Evidence))
}

func (s *Service) DiagnoseML(ctx context.Context, opts Options, input MLPromptInput) diagnosis.AIResult {
	if !opts.Enabled {
		result := diagnosis.DisabledResult()
		result.EvidenceCount = len(input.Sections)
		return result
	}

	modelName := modelDisplayName(opts.ModelPath)
	if len(input.Sections) == 0 {
		return diagnosis.FallbackResult(modelName, "没有可供模型使用的 ML 格式数据", 0)
	}

	evidenceIDs := input.EvidenceIDs()
	batches, err := splitMLPromptInputBatches(input, defaultMLBatchRows)
	if err != nil {
		return diagnosis.FallbackResult(modelName, fmt.Sprintf("ML CSV 分批失败: %v", err), len(evidenceIDs))
	}
	if len(batches) == 0 {
		return diagnosis.FallbackResult(modelName, "没有可供模型使用的 ML CSV 批次", len(evidenceIDs))
	}

	results := make([]diagnosis.AIResult, 0, len(batches))
	for _, batch := range batches {
		prompt := BuildMLPrompt(batch)
		if opts.Debug {
			debugPrintMLPrompt(batch, prompt)
		}
		batchEvidenceIDs := batch.EvidenceIDs()
		result := s.runDiagnosis(ctx, opts, modelName, prompt, batchEvidenceIDs, len(batchEvidenceIDs))
		if result.Status == diagnosis.AIStatusFallback {
			return result
		}
		results = append(results, result)
	}

	if len(results) == 1 {
		return results[0]
	}

	summaryPrompt := BuildMLSummaryPrompt(input, results)
	if opts.Debug {
		debugPrintPrompt("ml-summary", summaryPrompt)
	}
	summaryResult := s.runDiagnosis(ctx, opts, modelName, summaryPrompt, evidenceIDs, len(evidenceIDs))
	if summaryResult.Status == diagnosis.AIStatusActive {
		return summaryResult
	}
	return combineMLBatchResults(modelName, "", results, len(evidenceIDs))
}

func (s *Service) runDiagnosis(ctx context.Context, opts Options, modelName, prompt string, evidenceIDs map[string]struct{}, evidenceCount int) diagnosis.AIResult {
	runtimePath, runtimeErr := resolveRuntimePath(opts.RuntimePath)
	modelPath, modelErr := resolveModelPath(opts.ModelPath)
	missingReason := buildMissingDependencyReason(runtimePath, modelPath, runtimeErr, modelErr)
	if missingReason != "" {
		return diagnosis.FallbackResult(modelName, missingReason, evidenceCount)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if opts.Debug {
		debugPrintRuntimeRequest(runtimePath, modelPath, len(prompt), defaultPromptLimit, defaultCtxSize)
	}
	output, err := s.runner.Run(runCtx, Request{
		RuntimePath: runtimePath,
		ModelPath:   modelPath,
		Prompt:      prompt,
		MaxTokens:   defaultPromptLimit,
		ContextSize: defaultCtxSize,
		Debug:       opts.Debug,
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || runCtx.Err() == context.DeadlineExceeded {
			return diagnosis.FallbackResult(filepath.Base(modelPath), "AI 诊断超时，已回退到规则分析", evidenceCount)
		}
		return diagnosis.FallbackResult(filepath.Base(modelPath), fmt.Sprintf("AI runtime 执行失败: %v", err), evidenceCount)
	}

	response, err := ParseResponse(output, evidenceIDs)
	if err != nil {
		return diagnosis.FallbackResult(filepath.Base(modelPath), fmt.Sprintf("AI 输出校验失败: %v", err), evidenceCount)
	}

	return diagnosis.ActiveResult(filepath.Base(modelPath), runtimePath, response.Summary, response.Incidents, evidenceCount)
}

func buildMissingDependencyReason(runtimePath, modelPath string, runtimeErr, modelErr error) string {
	var parts []string
	if runtimePath == "" && runtimeErr != nil {
		parts = append(parts, fmt.Sprintf("%s；%s", runtimeErr.Error(), runtimeDownloadMessage()))
	}
	if modelPath == "" && modelErr != nil {
		parts = append(parts, fmt.Sprintf("%s；%s", modelErr.Error(), modelDownloadMessage()))
	}
	return strings.Join(parts, "；")
}

type CLIRunner struct{}

func (CLIRunner) Run(ctx context.Context, req Request) (string, error) {
	runtimePath := completionRuntimePath(req.RuntimePath)
	gpuAvailable, devicesOutput, devicesErr := detectGPUDevice(ctx, runtimePath)
	if req.Debug {
		debugPrintDeviceDetection(runtimePath, devicesOutput, devicesErr, gpuAvailable)
	}

	if gpuAvailable || devicesErr != nil {
		if req.Debug {
			debugPrintDeviceAttempt("GPU/auto", "-ngl auto")
		}
		output, err := runLlamaCommand(ctx, runtimePath, buildLlamaArgs(req, runtimePath, false))
		if err == nil || ctx.Err() != nil {
			if err == nil && req.Debug {
				debugPrintDeviceResult("GPU/auto", true, nil)
			}
			return output, err
		}

		if req.Debug {
			debugPrintDeviceResult("GPU/auto", false, err)
			debugPrintDeviceAttempt("CPU fallback", cpuOnlyDeviceArgsLabel())
		}
		cpuOutput, cpuErr := runLlamaCommand(ctx, runtimePath, buildLlamaArgs(req, runtimePath, true))
		if cpuErr != nil {
			if req.Debug {
				debugPrintDeviceResult("CPU fallback", false, cpuErr)
			}
			if output != "" {
				return cpuOutput, fmt.Errorf("%w; accelerated attempt failed first: %s", cpuErr, truncateRunnerOutput(output))
			}
			return cpuOutput, cpuErr
		}
		if req.Debug {
			debugPrintDeviceResult("CPU fallback", true, nil)
		}
		return cpuOutput, nil
	}

	if req.Debug {
		debugPrintDeviceAttempt("CPU", cpuOnlyDeviceArgsLabel())
	}
	cpuOutput, cpuErr := runLlamaCommand(ctx, runtimePath, buildLlamaArgs(req, runtimePath, true))
	if cpuErr != nil {
		if req.Debug {
			debugPrintDeviceResult("CPU", false, cpuErr)
		}
		return cpuOutput, cpuErr
	}
	if req.Debug {
		debugPrintDeviceResult("CPU", true, nil)
	}
	return cpuOutput, nil
}

func detectGPUDevice(ctx context.Context, runtimePath string) (bool, string, error) {
	cmd := exec.CommandContext(ctx, runtimePath, "--list-devices")
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		return false, trimmed, err
	}
	return containsGPUDevice(trimmed), trimmed, nil
}

func containsGPUDevice(devicesOutput string) bool {
	normalized := strings.ToLower(devicesOutput)
	gpuMarkers := []string{
		"metal",
		"cuda",
		"vulkan",
		"rocm",
		"hip",
		"sycl",
		"kompute",
	}
	for _, marker := range gpuMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func buildLlamaArgs(req Request, runtimePath string, cpuOnly bool) []string {
	args := []string{
		"-m", req.ModelPath,
		"-p", req.Prompt,
		"-n", fmt.Sprintf("%d", req.MaxTokens),
		"--ctx-size", fmt.Sprintf("%d", req.ContextSize),
		"--temp", "0",
		"--no-display-prompt",
		"--no-warmup",
		"--log-verbosity", "1",
	}
	if cpuOnly {
		args = append(args, "--device", "none", "-ngl", "0", "--no-op-offload", "--no-kv-offload", "--fit", "off")
	} else {
		args = append(args, "-ngl", "auto")
	}
	if isCompletionRuntime(runtimePath) {
		args = append(args, "-cnv", "--single-turn")
	}
	return args
}

func cpuOnlyDeviceArgsLabel() string {
	return "--device none -ngl 0 --no-op-offload --no-kv-offload --fit off"
}

func runLlamaCommand(ctx context.Context, runtimePath string, args []string) (string, error) {
	cmd := exec.CommandContext(
		ctx,
		runtimePath,
		args...,
	)

	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil && trimmed != "" {
		return trimmed, fmt.Errorf("%w: %s", err, truncateRunnerOutput(trimmed))
	}
	return trimmed, err
}

func truncateRunnerOutput(output string) string {
	const limit = 500
	output = strings.TrimSpace(output)
	if len(output) <= limit {
		return output
	}
	head := output[:250]
	tail := output[len(output)-250:]
	return head + "...[truncated]..." + tail
}

func debugPrintPrompt(mode, prompt string) {
	fmt.Fprintln(debugWriter(), "\n=== AI 调试: prompt 构造过程 ===")
	fmt.Fprintf(debugWriter(), "模式: %s\n", mode)
	fmt.Fprintln(debugWriter(), "1. oswbb-analyse 解析并过滤 OSWbb 数据")
	fmt.Fprintln(debugWriter(), "2. 构造模型输入数据")
	fmt.Fprintln(debugWriter(), "3. 添加格式说明和 JSON 输出约束")
	fmt.Fprintln(debugWriter(), "4. 调用本地模型 runtime")
	fmt.Fprintf(debugWriter(), "Prompt 字节数: %d\n", len(prompt))
	fmt.Fprintln(debugWriter(), "--- Prompt BEGIN ---")
	fmt.Fprintln(debugWriter(), prompt)
	fmt.Fprintln(debugWriter(), "--- Prompt END ---")
}

func debugPrintMLPrompt(input MLPromptInput, prompt string) {
	fmt.Fprintln(debugWriter(), "\n=== AI 调试: oswbb-analyse 输入给模型的数据 ===")
	fmt.Fprintf(debugWriter(), "hostname=%s start_time=%s end_time=%s sections=%d\n", input.Hostname, input.StartTime, input.EndTime, len(input.Sections))
	for _, section := range input.Sections {
		fmt.Fprintf(debugWriter(), "\n[%s] module=%s format=%s rows=%d/%d\n", section.ID, section.Module, section.Format, section.SelectedRows, section.TotalRows)
		if section.BatchTotal > 0 {
			fmt.Fprintf(debugWriter(), "batch=%d/%d row_range=%d-%d/%d\n", section.BatchIndex, section.BatchTotal, section.RowStart, section.RowEnd, section.TotalRows)
		}
		if section.FilePath != "" {
			fmt.Fprintf(debugWriter(), "csv_path=%s\n", section.FilePath)
		}
		if section.Description != "" {
			fmt.Fprintf(debugWriter(), "description=%s\n", section.Description)
		}
		fmt.Fprintln(debugWriter(), "--- Data BEGIN ---")
		fmt.Fprintln(debugWriter(), strings.TrimSpace(section.Data))
		fmt.Fprintln(debugWriter(), "--- Data END ---")
	}
	debugPrintPrompt("ml", prompt)
}

func debugPrintRuntimeRequest(runtimePath, modelPath string, promptBytes, maxTokens, ctxSize int) {
	fmt.Fprintln(debugWriter(), "\n=== AI 调试: runtime 请求 ===")
	fmt.Fprintf(debugWriter(), "runtime=%s\n", runtimePath)
	fmt.Fprintf(debugWriter(), "model=%s\n", modelPath)
	fmt.Fprintf(debugWriter(), "prompt_bytes=%d max_tokens=%d ctx_size=%d\n", promptBytes, maxTokens, ctxSize)
}

func debugPrintDeviceDetection(runtimePath, devicesOutput string, err error, gpuAvailable bool) {
	fmt.Fprintln(debugWriter(), "\n=== AI 调试: 设备检测 ===")
	fmt.Fprintf(debugWriter(), "runtime=%s\n", runtimePath)
	if err != nil {
		fmt.Fprintf(debugWriter(), "--list-devices 执行失败: %v\n", err)
		if devicesOutput != "" {
			fmt.Fprintf(debugWriter(), "devices_output:\n%s\n", devicesOutput)
		}
		fmt.Fprintln(debugWriter(), "设备决策: 检测失败，先尝试 GPU/auto，失败再 CPU fallback")
		return
	}
	if devicesOutput != "" {
		fmt.Fprintf(debugWriter(), "devices_output:\n%s\n", devicesOutput)
	}
	if gpuAvailable {
		fmt.Fprintln(debugWriter(), "设备决策: 检测到 GPU/加速设备，先使用 GPU/auto (-ngl auto)")
		return
	}
	fmt.Fprintf(debugWriter(), "设备决策: 未检测到 GPU 设备，使用 CPU (%s)\n", cpuOnlyDeviceArgsLabel())
}

func debugPrintDeviceAttempt(label, args string) {
	fmt.Fprintf(debugWriter(), "AI runtime 调用: 尝试 %s [%s]\n", label, args)
}

func debugPrintDeviceResult(label string, success bool, err error) {
	if success {
		fmt.Fprintf(debugWriter(), "AI runtime 结果: 使用 %s 成功\n", label)
		return
	}
	fmt.Fprintf(debugWriter(), "AI runtime 结果: %s 失败: %v\n", label, err)
}

func debugWriter() io.Writer {
	return logging.Default().Writer()
}

func completionRuntimePath(runtimePath string) string {
	if runtimePath == "" || isCompletionRuntime(runtimePath) {
		return runtimePath
	}

	name := filepath.Base(runtimePath)
	completionName := ""
	switch name {
	case "llama-cli":
		completionName = "llama-completion"
	case "llama-cli.exe":
		completionName = "llama-completion.exe"
	default:
		return runtimePath
	}

	candidate := filepath.Join(filepath.Dir(runtimePath), completionName)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	return runtimePath
}

func isCompletionRuntime(runtimePath string) bool {
	name := filepath.Base(runtimePath)
	return name == "llama-completion" || name == "llama-completion.exe"
}

func BuildPrompt(input diagnosis.Context) string {
	payload, _ := json.MarshalIndent(input, "", "  ")
	return fmt.Sprintf(`/no_think
你是一个离线 OSWatcher 辅助诊断模型。请严格遵循以下规则：
1. 只能基于输入中的 evidence 作答，不能补充不存在的指标、设备、时间点。
2. 只输出 JSON，不要输出 Markdown、解释性前缀或代码块。
3. incidents 中每条结论至少引用 2 个观测 evidence_ids；ml-format 只是格式说明，不算观测证据。
4. 如果证据不足，不要猜测；可以返回空 incidents。
5. severity 只能是 info、warning、critical。
6. confidence 使用 0 到 1 的小数；如果输出 incident，confidence 必须 >= 0.6，否则不要输出该 incident。
7. top-process-rows 只能作为候选进程行，不能单独生成 incident。
8. top-process-high-cpu 只能作为候选进程线索，不能单独作为 high_cpu incident 根因。
9. top-process-d-state 是进程阻塞线索，不能单独作为系统级 I/O wait 或 load incident 根因；D-state incident 必须同时引用 top-cpu-wait 或 top-load-high。
10. high_cpu incident 必须同时引用 top-cpu-idle 或 top-load-high。
11. high_mem incident 必须同时引用 meminfo-available、meminfo-swap-usage、meminfo-commit-pressure 或 meminfo-anon-growth。

输出 JSON schema:
{
  "summary": "一句话总结",
  "incidents": [
    {
      "classification": "结论类别",
      "severity": "info|warning|critical",
      "confidence": 0.85,
      "evidence_ids": ["signal-a", "signal-b"],
      "next_checks": ["下一步核查建议 1", "下一步核查建议 2"]
    }
  ]
}

诊断上下文:
%s
`, string(payload))
}

func splitMLPromptInputBatches(input MLPromptInput, maxRows int) ([]MLPromptInput, error) {
	if maxRows <= 0 {
		maxRows = defaultMLBatchRows
	}

	var batches []MLPromptInput
	for _, section := range input.Sections {
		records, err := readMLCSVRecords(section.Data)
		if err != nil {
			return nil, fmt.Errorf("%s CSV 解析失败: %w", section.ID, err)
		}
		if len(records) <= 1 {
			copySection := section
			copySection.SelectedRows = 0
			copySection.TotalRows = 0
			copySection.BatchIndex = 1
			copySection.BatchTotal = 1
			batches = append(batches, withSingleMLSection(input, copySection, nil))
			continue
		}

		header := records[0]
		rows := records[1:]
		totalRows := len(rows)
		batchTotal := (totalRows + maxRows - 1) / maxRows
		for start := 0; start < totalRows; start += maxRows {
			end := start + maxRows
			if end > totalRows {
				end = totalRows
			}

			data, err := formatMLCSVRecords(header, rows[start:end])
			if err != nil {
				return nil, fmt.Errorf("%s CSV batch 格式化失败: %w", section.ID, err)
			}

			copySection := section
			copySection.Data = data
			copySection.SelectedRows = end - start
			copySection.TotalRows = totalRows
			copySection.BatchIndex = start/maxRows + 1
			copySection.BatchTotal = batchTotal
			copySection.RowStart = start + 1
			copySection.RowEnd = end
			copySection.Description = "从本地 ml CSV 按原始顺序切分的表格批次。"
			batches = append(batches, withSingleMLSection(input, copySection, filterFindingsForMLSection(input.Findings, copySection, header, rows[start:end])))
		}
	}
	return batches, nil
}

func withSingleMLSection(input MLPromptInput, section MLSection, findings []findings.Finding) MLPromptInput {
	return MLPromptInput{
		Hostname:  input.Hostname,
		StartTime: input.StartTime,
		EndTime:   input.EndTime,
		Findings:  findings,
		Sections:  []MLSection{section},
	}
}

func filterFindingsForMLSection(all []findings.Finding, section MLSection, header []string, rows [][]string) []findings.Finding {
	if len(all) == 0 {
		return nil
	}

	start, end, hasRange := mlRowsTimeRange(header, rows)
	filtered := make([]findings.Finding, 0, len(all))
	for _, finding := range all {
		if finding.Source != "" && section.Module != "" && finding.Source != section.Module {
			continue
		}
		if hasRange && !findingOverlapsTimeRange(finding, start, end) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func mlRowsTimeRange(header []string, rows [][]string) (time.Time, time.Time, bool) {
	timestampIndex := -1
	for index, column := range header {
		if strings.EqualFold(strings.TrimSpace(column), "timestamp") {
			timestampIndex = index
			break
		}
	}
	if timestampIndex < 0 {
		return time.Time{}, time.Time{}, false
	}

	var start, end time.Time
	for _, row := range rows {
		if timestampIndex >= len(row) {
			continue
		}
		current, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(row[timestampIndex]), time.Local)
		if err != nil {
			continue
		}
		if start.IsZero() || current.Before(start) {
			start = current
		}
		if end.IsZero() || current.After(end) {
			end = current
		}
	}
	if start.IsZero() || end.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}

func findingOverlapsTimeRange(finding findings.Finding, start, end time.Time) bool {
	if finding.Time != "" {
		at, err := time.ParseInLocation("2006-01-02 15:04:05", finding.Time, time.Local)
		if err == nil {
			return !at.Before(start) && !at.After(end)
		}
	}

	if finding.WindowStart != "" || finding.WindowEnd != "" {
		windowStart := start
		windowEnd := end
		if finding.WindowStart != "" {
			if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", finding.WindowStart, time.Local); err == nil {
				windowStart = parsed
			}
		}
		if finding.WindowEnd != "" {
			if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", finding.WindowEnd, time.Local); err == nil {
				windowEnd = parsed
			}
		}
		return !windowEnd.Before(start) && !windowStart.After(end)
	}

	return true
}

func readMLCSVRecords(data string) ([][]string, error) {
	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(data)))
	return reader.ReadAll()
}

func formatMLCSVRecords(header []string, rows [][]string) (string, error) {
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

func BuildMLPrompt(input MLPromptInput) string {
	evidenceIDs := mlEvidenceIDList(input)

	var sections strings.Builder
	for _, section := range input.Sections {
		fmt.Fprintf(&sections, "\n### %s\n", section.ID)
		fmt.Fprintf(&sections, "module: %s\nformat: %s\nrows: %d/%d\n", section.Module, section.Format, section.SelectedRows, section.TotalRows)
		if section.BatchTotal > 0 {
			fmt.Fprintf(&sections, "batch: %d/%d\nrow_range: %d-%d/%d\n", section.BatchIndex, section.BatchTotal, section.RowStart, section.RowEnd, section.TotalRows)
		}
		if section.FilePath != "" {
			fmt.Fprintf(&sections, "csv_path: %s\n", section.FilePath)
		}
		if section.Description != "" {
			fmt.Fprintf(&sections, "description: %s\n", section.Description)
		}
		fmt.Fprintf(&sections, "```csv\n%s\n```\n", strings.TrimSpace(section.Data))
	}

	findingFacts := buildMLFindingFacts(input.Findings)

	return fmt.Sprintf(`/no_think
你是 OSWbb 运维诊断助手。直接分析下面这一批 oswbb-analyse ml CSV 表格数据。
只输出 JSON 对象，顶层只能包含 summary 和 incidents。
有效 evidence_ids: %s。
不要假设未给出的批次正常；只对当前 CSV 批次做判断。不要编造未出现的设备、字段或时间点。
top_process_csv 中 CPU/MEM 高占用不能单独生成 incident；top-process-high-cpu 是进程线索，top-process-high-cpu 不能单独作为 high CPU incident 根因；high CPU incident 必须同时引用 top-cpu-idle 或 top-load-high；high MEM incident 必须同时引用 meminfo-available、meminfo-swap-usage、meminfo-commit-pressure 或 meminfo-anon-growth。
top-process-d-state 是进程阻塞线索，不能单独作为系统级 I/O wait 或 load incident 根因；D-state incident 必须同时引用 top-cpu-wait 或 top-load-high。
iostat finding 中 latency_system_pressure=0 表示存在设备级慢请求/瞬时尖峰，但缺少队列或 iowait 系统级压力；可以报告设备级延迟异常，不要直接定性为系统级 I/O 拥塞。
%s
incidents 中每项必须包含 classification、severity、confidence、evidence_ids、next_checks；每项至少引用 2 个观测 evidence_ids，ml-format 不算观测证据；没有发现异常时 incidents 返回 []。

字段结构 / ML format:
%s

Input:
hostname: %s
start_time: %s
end_time: %s
%s
%s
`, strings.Join(evidenceIDs, ", "), findingNatureGuide(), buildMLFormatGuide(input.Sections), input.Hostname, input.StartTime, input.EndTime, findingFacts, sections.String())
}

func BuildMLSummaryPrompt(input MLPromptInput, results []diagnosis.AIResult) string {
	evidenceIDs := mlEvidenceIDList(input)
	payload, _ := json.MarshalIndent(results, "", "  ")
	findingFacts := buildMLFindingFacts(input.Findings)
	return fmt.Sprintf(`/no_think
你是 OSWbb 运维诊断助手。下面是同一份 ml CSV 按原始顺序分批后得到的多个 AI JSON 结果。
请合并重复结论，保留具体时间点、设备/字段、证据和排查建议。
只输出 JSON 对象，顶层只能包含 summary 和 incidents。
有效 evidence_ids: %s。
%s

主机: %s
时间范围: %s - %s
%s

批次结果:
%s
`, strings.Join(evidenceIDs, ", "), findingNatureGuide(), input.Hostname, input.StartTime, input.EndTime, findingFacts, string(payload))
}

func buildMLFindingFacts(items []findings.Finding) string {
	if len(items) == 0 {
		return ""
	}
	payload, _ := json.MarshalIndent(items, "", "  ")
	return fmt.Sprintf("\n### finding-facts\ndescription: 工具确认的 finding 事实；它们是结构化证据索引，不是最终根因。CSV 原始数据仍然是最终证据来源。\n```json\n%s\n```\n", string(payload))
}

func findingNatureGuide() string {
	return "finding-facts 中 nature=risk 表示风险信号；nature=candidate 表示候选线索。candidate 不能单独升级为最终根因，必须结合 CSV 原始数据或 risk finding 佐证后再下结论。"
}

func mlEvidenceIDList(input MLPromptInput) []string {
	evidenceIDs := []string{"ml-format"}
	seen := map[string]struct{}{"ml-format": {}}
	add := func(id string) {
		if id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		evidenceIDs = append(evidenceIDs, id)
		seen[id] = struct{}{}
	}
	for _, section := range input.Sections {
		add(section.ID)
	}
	for _, finding := range input.Findings {
		add(finding.RuleID)
	}
	return evidenceIDs
}

func combineMLBatchResults(modelName, runtimePath string, results []diagnosis.AIResult, evidenceCount int) diagnosis.AIResult {
	var summaries []string
	var incidents []diagnosis.Incident
	for _, result := range results {
		if result.Summary != "" {
			summaries = append(summaries, result.Summary)
		}
		incidents = append(incidents, result.Incidents...)
	}
	if len(summaries) == 0 && len(incidents) == 0 {
		summaries = append(summaries, "模型分批分析完成，未返回高置信异常。")
	}
	return diagnosis.ActiveResult(modelName, runtimePath, strings.Join(summaries, "；"), incidents, evidenceCount)
}

func buildMLFormatGuide(sections []MLSection) string {
	var guide strings.Builder
	for _, section := range sections {
		switch section.Format {
		case "iostat_csv":
			guide.WriteString("- iostat_csv: CSV columns include timestamp, device, read/write/discard IOPS and throughput, read_await, write_await, discard_await, avg_queue_size, request size, merge pct, cpu_iowait, cpu_idle, utilization; await 单位: ms；CPU 字段单位: %；utilization 单位: %，表示设备忙碌度，需结合 await/queue/iowait 判断是否异常。\n")
		case "meminfo_csv":
			guide.WriteString("- meminfo_csv: 原始内存字段单位: KB；*_pct 为百分比；mem_available_pct/mem_available_delta 使用有效可用内存，若 mem_available 缺失则按 mem_free+buffers+cached+s_reclaimable 估算；其它 *_delta 为相对上一条采样的 KB 变化量；关注 mem_available_delta、anon_pages_delta、slab_delta、s_unreclaim_delta、dirty_delta、writeback_delta、swap_free_delta、committed_pct。\n")
		case "top_csv":
			guide.WriteString("- top_csv: load_* 为负载；cpu_count 为目标主机 CPU 核数，0 表示未知；load_1_per_cpu/task_running_per_cpu 是按核归一化指标；task_running 表示 runnable/R 队列；cpu_* 单位: %；有 cpu_count 时优先用 per-core 判断 CPU 容量，cpu_count=0 时不能判断是否超过核数；关注 cpu_wait 上升、cpu_idle 下降、cpu_steal 上升，以及 load/running 按核数偏高的 CPU 排队压力。\n")
		case "top_process_csv":
			guide.WriteString("- top_process_csv: top 进程表；字段包含 timestamp,pid,user,state,cpu_percent,mem_percent,virt_kb,res_kb,shr_kb,command；state=D/Z 是进程状态线索；D 状态进程、CPU/MEM 高占用都是候选线索，不能单独生成 incident；top-process-high-cpu 也只是进程线索，high CPU 结论需结合 top-cpu-idle/top-load-high，high MEM 结论需结合 meminfo 相关 finding，D-state 结论需结合 top-cpu-wait/top-load-high。\n")
		case "iostat_kv":
			guide.WriteString("- iostat_kv: each row is key=value; await 单位: ms; use write_await_ms for write latency and read_await_ms for read latency.\n")
		case "meminfo_kv":
			guide.WriteString("- meminfo_kv: each row is key=value; memory keys ending with _kb are KB; focus on mem_available_kb下降、anon_pages_kb/slab相关字段上升、swap_free_kb下降。\n")
		case "top_kv":
			guide.WriteString("- top_kv: each row is key=value; cpu_*_pct are percentages; focus on cpu_wait_pct 上升、cpu_idle_pct 下降。\n")
		}
	}
	guide.WriteString("- rows=selected/total 表示当前批次行数/完整 CSV 行数；batch 和 row_range 表示当前批次在完整 CSV 中的原始顺序范围。")
	return guide.String()
}

type responsePayload struct {
	Summary   string               `json:"summary"`
	Incidents []diagnosis.Incident `json:"incidents"`
}

func ParseResponse(raw string, evidenceIDs map[string]struct{}) (responsePayload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return responsePayload{}, fmt.Errorf("模型输出为空")
	}

	jsonBody, err := extractJSONObject(raw)
	if err != nil {
		return responsePayload{}, err
	}

	var payload responsePayload
	if err := json.Unmarshal([]byte(jsonBody), &payload); err != nil {
		return responsePayload{}, fmt.Errorf("JSON 解析失败: %w", err)
	}
	payload.Summary = strings.TrimSpace(payload.Summary)

	valid := make([]diagnosis.Incident, 0, len(payload.Incidents))
	for _, incident := range payload.Incidents {
		incident = normalizeIncident(incident)
		if incident.Confidence < 0.6 {
			continue
		}
		if !hasEnoughObservationalEvidence(incident.EvidenceIDs) {
			continue
		}
		if incident.Classification == "" || incident.Severity == "" {
			continue
		}
		if !validIncidentSeverity(incident.Severity) {
			continue
		}
		if !validEvidenceIDs(incident.EvidenceIDs, evidenceIDs) {
			continue
		}
		if processCandidateOnlyEvidence(incident.EvidenceIDs) {
			continue
		}
		valid = append(valid, incident)
	}
	payload.Incidents = valid

	if payload.Summary == "" && len(payload.Incidents) == 0 {
		return responsePayload{}, fmt.Errorf("没有有效 summary 或高置信 incidents")
	}

	return payload, nil
}

func normalizeIncident(incident diagnosis.Incident) diagnosis.Incident {
	incident.Classification = strings.TrimSpace(incident.Classification)
	incident.Severity = normalizeIncidentSeverity(incident.Severity)
	incident.EvidenceIDs = uniqueTrimmedNonEmptyStrings(incident.EvidenceIDs)
	incident.NextChecks = trimNonEmptyStrings(incident.NextChecks)
	return incident
}

func normalizeIncidentSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "severe":
		return "critical"
	case "warning", "medium":
		return "warning"
	case "info", "low":
		return "info"
	default:
		return strings.TrimSpace(severity)
	}
}

func validIncidentSeverity(severity string) bool {
	switch severity {
	case "info", "warning", "critical":
		return true
	default:
		return false
	}
}

func trimNonEmptyStrings(values []string) []string {
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		trimmed = append(trimmed, value)
	}
	return trimmed
}

func uniqueTrimmedNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		trimmed = append(trimmed, value)
	}
	return trimmed
}

func processCandidateOnlyEvidence(ids []string) bool {
	hasProcessCandidate := false
	for _, id := range ids {
		switch id {
		case "top-process-rows", "ml-top-processes", "top-process-high-cpu", "top-process-d-state":
			hasProcessCandidate = true
		case "ml-format":
			continue
		default:
			return false
		}
	}
	return hasProcessCandidate
}

func hasEnoughObservationalEvidence(ids []string) bool {
	count := 0
	for _, id := range ids {
		if id == "ml-format" {
			continue
		}
		count++
	}
	return count >= 2
}

func extractJSONObject(raw string) (string, error) {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start == -1 || end == -1 || start > end {
		return "", fmt.Errorf("未找到合法 JSON 对象")
	}
	return raw[start : end+1], nil
}

func validEvidenceIDs(ids []string, evidenceIDs map[string]struct{}) bool {
	for _, id := range ids {
		if _, exists := evidenceIDs[id]; !exists {
			return false
		}
	}
	return true
}

func modelDisplayName(path string) string {
	if path == "" {
		return defaultModelFile
	}
	return filepath.Base(path)
}
