package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/pkg/aitypes"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/findings"
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/localai"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/output"
	"oswbb-analyse/pkg/top"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type runnerStub struct {
	output   string
	err      error
	calls    *int
	requests *[]localai.Request
}

func (s runnerStub) Run(_ context.Context, req localai.Request) (string, error) {
	if s.calls != nil {
		(*s.calls)++
	}
	if s.requests != nil {
		*s.requests = append(*s.requests, req)
	}
	return s.output, s.err
}

type aiDiagnoserSpy struct {
	diagnoseCalls   int
	diagnoseMLCalls int
	lastOptions     aitypes.Options
	lastMLInput     aitypes.MLPromptInput
}

type aiReportSink struct {
	req internaloutput.OutputRequest
}

func (s *aiReportSink) Write(_ context.Context, req internaloutput.OutputRequest) error {
	s.req = req
	return nil
}

type aiBundleRecordingSink struct {
	reqs []internaloutput.OutputRequest
}

func (s *aiBundleRecordingSink) Write(_ context.Context, req internaloutput.OutputRequest) error {
	s.reqs = append(s.reqs, req)
	return nil
}

type fallbackMLDiagnoser struct{}

func (s fallbackMLDiagnoser) Diagnose(_ context.Context, _ aitypes.Options, _ diagnosis.Context) diagnosis.AIResult {
	return diagnosis.ActiveResult("spy-model", "spy-runtime", "unexpected diagnose", nil, 0)
}

func (s fallbackMLDiagnoser) DiagnoseML(_ context.Context, _ aitypes.Options, input aitypes.MLPromptInput) diagnosis.AIResult {
	return diagnosis.FallbackResult("spy-model", "runtime killed", len(input.Sections))
}

func (s *aiDiagnoserSpy) Diagnose(_ context.Context, opts aitypes.Options, _ diagnosis.Context) diagnosis.AIResult {
	s.diagnoseCalls++
	s.lastOptions = opts
	return diagnosis.ActiveResult("spy-model", "spy-runtime", "unexpected diagnose", nil, 0)
}

func (s *aiDiagnoserSpy) DiagnoseML(_ context.Context, opts aitypes.Options, input aitypes.MLPromptInput) diagnosis.AIResult {
	s.diagnoseMLCalls++
	s.lastOptions = opts
	s.lastMLInput = input
	return diagnosis.ActiveResult("spy-model", "spy-runtime", "ml ok", nil, len(input.Sections))
}

func createTestBinary(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	return path
}

func TestBuildAIDiagnosisUsesCombinedEvidence(t *testing.T) {
	modelPath := createTestBinary(t, localai.DefaultModelName())
	runtimePath := createTestBinary(t, "llama-cli")
	fp := NewFileProcessorWithService(localai.NewService(runnerStub{
		output: `{"summary":"存在组合型内存压力","incidents":[{"classification":"内存压力","severity":"warning","confidence":0.86,"evidence_ids":["meminfo-available","meminfo-swap-usage"],"next_checks":["检查匿名内存增长来源"]}]}`,
	}))

	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2025, time.January, 1, 10, 0, 0, 0, loc)
	end := start.Add(10 * time.Minute)
	bundle := &analysisBundle{
		Hostname: "db01",
		MemInfo: &meminfo.MemInfoLog{
			Data: []meminfo.MemStatData{
				{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 30 * 1024 * 1024, SwapTotal: 16 * 1024 * 1024, SwapFree: 16 * 1024 * 1024}},
				{Timestamp: end, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 18 * 1024 * 1024, SwapTotal: 16 * 1024 * 1024, SwapFree: 14 * 1024 * 1024}},
			},
		},
		Top: &top.TopLog{
			Snapshots: []top.TopSnapshot{
				{Timestamp: start, Load1: 4.0, CpuIdle: 21, CpuWait: 9},
				{Timestamp: end, Load1: 5.2, CpuIdle: 14, CpuWait: 12},
			},
		},
	}

	result := fp.buildAIDiagnosis(bundle, "", "", loc, AIConfig{
		Enabled:     true,
		ModelPath:   modelPath,
		RuntimePath: runtimePath,
	})

	if result.Status != diagnosis.AIStatusActive {
		t.Fatalf("期望 active, got=%s", result.Status)
	}
	if len(result.Incidents) != 1 {
		t.Fatalf("期望 1 条 incident, got=%d", len(result.Incidents))
	}
}

func TestBuildMLTopEvidenceIncludesRunnableQueue(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{
			{Timestamp: start, Load1: 5.0, CpuIdle: 70, CpuWait: 0, TaskRunning: 8},
			{Timestamp: start.Add(5 * time.Second), Load1: 9.0, CpuIdle: 65, CpuWait: 0, TaskRunning: 14},
		},
	}

	got := buildMLTopEvidence(log, start, start.Add(5*time.Second))
	if len(got) != 1 {
		t.Fatalf("期望 top summary evidence, got=%+v", got)
	}
	if got[0].Metrics["task_running_max"] != 14 {
		t.Fatalf("top summary 应包含 running 队列峰值: %+v", got[0].Metrics)
	}
	if !strings.Contains(got[0].Summary, "Running 峰值 14") {
		t.Fatalf("top summary 应说明 running 队列峰值: %s", got[0].Summary)
	}
}

func TestBuildMLMemInfoEvidenceUsesFallbackWhenMemAvailableMissing(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: start,
				MemStats: meminfo.MemStats{
					MemTotal:     128 * 1024 * 1024,
					MemFree:      4 * 1024 * 1024,
					Buffers:      2 * 1024 * 1024,
					Cached:       88 * 1024 * 1024,
					SReclaimable: 2 * 1024 * 1024,
				},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     128 * 1024 * 1024,
					MemFree:      3 * 1024 * 1024,
					Buffers:      2 * 1024 * 1024,
					Cached:       89 * 1024 * 1024,
					SReclaimable: 2 * 1024 * 1024,
				},
			},
		},
	}

	got := buildMLMemInfoEvidence(log, start, start.Add(5*time.Second))
	if len(got) == 0 {
		t.Fatalf("期望 meminfo summary evidence")
	}
	if got[0].Metrics["mem_available_pct"] != 75 {
		t.Fatalf("AI evidence 应使用有效可用内存 fallback: %+v", got[0].Metrics)
	}
	if !strings.Contains(got[0].Summary, "可用内存当前 75.0%") {
		t.Fatalf("AI evidence 摘要应使用有效可用内存 fallback: %s", got[0].Summary)
	}
}

func TestBuildMLMemInfoEvidenceIgnoresAvailableRecoveryRise(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 40 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 100 * 1024 * 1024}},
		},
	}

	got := buildMLMemInfoEvidence(log, start, start.Add(5*time.Second))
	for _, evidence := range got {
		if strings.Contains(evidence.ID, "meminfo-available-anomaly") {
			t.Fatalf("MemAvailable 单纯骤升是恢复线索，不应作为 AI 硬异常 evidence: %+v", got)
		}
	}
}

func TestBuildAIDiagnosisFallbackWhenModuleRangesDoNotOverlap(t *testing.T) {
	fp := NewFileProcessorWithService(localai.NewService(runnerStub{
		output: `{"summary":"should not run","incidents":[]}`,
	}))

	loc := time.FixedZone("CST", 8*3600)
	memStart := time.Date(2025, time.January, 1, 10, 0, 0, 0, loc)
	memEnd := memStart.Add(10 * time.Minute)
	topStart := memStart.Add(2 * time.Hour)
	topEnd := topStart.Add(10 * time.Minute)

	bundle := &analysisBundle{
		Hostname: "db01",
		MemInfo: &meminfo.MemInfoLog{
			Data: []meminfo.MemStatData{
				{Timestamp: memStart, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 30 * 1024 * 1024}},
				{Timestamp: memEnd, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 24 * 1024 * 1024}},
			},
		},
		Top: &top.TopLog{
			Snapshots: []top.TopSnapshot{
				{Timestamp: topStart, Load1: 8.1, CpuIdle: 9, CpuWait: 22},
				{Timestamp: topEnd, Load1: 7.8, CpuIdle: 11, CpuWait: 18},
			},
		},
	}

	result := fp.buildAIDiagnosis(bundle, "", "", loc, AIConfig{Enabled: true})

	if result.Status != diagnosis.AIStatusFallback {
		t.Fatalf("期望 fallback, got=%s", result.Status)
	}
	if result.FallbackReason == "" || !strings.Contains(result.FallbackReason, "无交集") {
		t.Fatalf("期望提示时间范围无交集, got=%s", result.FallbackReason)
	}
}

func TestExecuteBundleAILocalMLWritesCSVThenRunsAI(t *testing.T) {
	calls := 0
	modelPath := createTestBinary(t, localai.DefaultModelName())
	runtimePath := createTestBinary(t, "llama-cli")
	fp := NewFileProcessorWithService(localai.NewService(runnerStub{
		calls:  &calls,
		output: `{"summary":"发现可用内存异常下降","incidents":[{"classification":"内存可用量异常","severity":"warning","confidence":0.82,"evidence_ids":["meminfo-available","meminfo-anon-growth"],"next_checks":["检查内存申请来源"]}]}`,
	}))

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 10, 0, 0, 0, loc)
	bundle := &analysisBundle{
		Hostname: "db01",
		MemInfo: &meminfo.MemInfoLog{
			Data: []meminfo.MemStatData{
				{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 20 * 1024 * 1024, AnonPages: 1024 * 1024}},
				{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 18 * 1024 * 1024, AnonPages: 2 * 1024 * 1024}},
				{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 12 * 1024 * 1024, AnonPages: 3 * 1024 * 1024}},
			},
		},
	}

	err = fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{
		Enabled:     true,
		ModelPath:   modelPath,
		RuntimePath: runtimePath,
	})
	if err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if calls != 1 {
		t.Fatalf("期望 AI runner 被调用一次, got=%d", calls)
	}
	matches, err := filepath.Glob("meminfo_*.csv")
	if err != nil {
		t.Fatalf("匹配 CSV 文件失败: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("ai-local ml 模式应先生成 CSV 文件, got=%v", matches)
	}
}

func TestExecuteBundleAILocalMLCallsDiagnoseMLWithAllCSVSections(t *testing.T) {
	spy := &aiDiagnoserSpy{}
	fp := NewFileProcessorWithService(spy)

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		IOStat: &iostat.IOStatLog{Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteKBPerSec:  277,
				WriteAwait:     300.11,
			}},
		}}},
		MemInfo: &meminfo.MemInfoLog{Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemAvailable: 64 * 1024 * 1024,
				AnonPages:    4 * 1024 * 1024,
			},
		}}},
		Top: &top.TopLog{Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       2.5,
			CpuIdle:     90,
			TaskRunning: 2,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "R",
				CPUPercent: 88.5,
				MemPercent: 3.2,
				VirtKB:     987654,
				ResKB:      131072,
				ShrKB:      8192,
				Command:    "oracle",
			}},
		}}},
	}

	if err := fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{Enabled: true}); err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}

	if spy.diagnoseCalls != 0 {
		t.Fatalf("ml+AI 路径不应调用旧 Diagnose/report evidence 路径, got=%d", spy.diagnoseCalls)
	}
	if spy.diagnoseMLCalls != 1 {
		t.Fatalf("ml+AI 路径应调用 DiagnoseML 一次, got=%d", spy.diagnoseMLCalls)
	}

	gotSections := map[string]aitypes.MLSection{}
	for _, section := range spy.lastMLInput.Sections {
		gotSections[section.ID] = section
	}
	wantFormats := map[string]string{
		"ml-iostat-data":   "iostat_csv",
		"ml-meminfo-data":  "meminfo_csv",
		"ml-top-data":      "top_csv",
		"ml-top-processes": "top_process_csv",
	}
	for id, format := range wantFormats {
		section, ok := gotSections[id]
		if !ok {
			t.Fatalf("DiagnoseML 输入缺少 section %s, got=%+v", id, spy.lastMLInput.Sections)
		}
		if section.Format != format || section.FilePath == "" || section.Data == "" {
			t.Fatalf("section %s 应包含 CSV format/path/data, got=%+v", id, section)
		}
	}
}

func TestExecuteBundleAILocalMLWritesAIReportThroughSink(t *testing.T) {
	spy := &aiDiagnoserSpy{}
	sink := &aiReportSink{}
	fp := NewFileProcessorWithService(spy)
	fp.SetOutputSink(sink)

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		MemInfo: &meminfo.MemInfoLog{Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemAvailable: 64 * 1024 * 1024,
			},
		}}},
	}

	if err := fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{Enabled: true}); err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if !sink.req.ToStdout || sink.req.Format != internaloutput.FormatText {
		t.Fatalf("AI report should be written to stdout text sink: %+v", sink.req)
	}
	if !strings.Contains(string(sink.req.Data), "=== AI 辅助诊断 ===") || !strings.Contains(string(sink.req.Data), "总结：ml ok") {
		t.Fatalf("AI report sink data missing expected text:\n%s", sink.req.Data)
	}
}

func TestExecuteBundleAILocalMLPassesAITimeout(t *testing.T) {
	spy := &aiDiagnoserSpy{}
	fp := NewFileProcessorWithService(spy)

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		MemInfo: &meminfo.MemInfoLog{Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemAvailable: 64 * 1024 * 1024,
			},
		}}},
	}

	if err := fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{
		Enabled: true,
		Timeout: 180 * time.Second,
	}); err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if spy.lastOptions.Timeout != 180*time.Second {
		t.Fatalf("AIConfig.Timeout 应传递到 DiagnoseML Options, got=%s", spy.lastOptions.Timeout)
	}
}

func TestExecuteBundleAILocalMLFallbackPrintsRuleFindings(t *testing.T) {
	modelPath := createTestBinary(t, localai.DefaultModelName())
	runtimePath := createTestBinary(t, "llama-cli")
	fp := NewFileProcessorWithService(localai.NewService(runnerStub{
		err: errors.New("runtime killed"),
	}))

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: at,
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 41,
					WriteAwait:     300.11,
				}},
			}},
		},
	}

	output := captureStdout(t, func() {
		err = fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{
			Enabled:     true,
			ModelPath:   modelPath,
			RuntimePath: runtimePath,
		})
	})
	if err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}

	for _, want := range []string{
		"=== AI 辅助诊断 ===",
		"AI 诊断未生效",
		"=== 异常摘要 ===",
		"nvme11n1 写延迟存在突增",
		"候选线索",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("AI fallback 时应同时打印规则诊断摘要 %q:\n%s", want, output)
		}
	}
}

func TestExecuteBundleAILocalMLFallbackWritesRuleFindingsThroughSink(t *testing.T) {
	sink := &aiBundleRecordingSink{}
	fp := NewFileProcessorWithService(fallbackMLDiagnoser{})
	fp.SetOutputSink(sink)

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: at,
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 41,
					WriteAwait:     300.11,
				}},
			}},
		},
	}

	if err := fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{Enabled: true}); err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if len(sink.reqs) != 2 {
		t.Fatalf("AI fallback 应通过 sink 写出 AI 报告和规则摘要, got=%d", len(sink.reqs))
	}
	summaryReq := sink.reqs[1]
	if !summaryReq.ToStdout || summaryReq.Format != internaloutput.FormatText {
		t.Fatalf("规则摘要应写到 stdout text sink: %+v", summaryReq)
	}
	for _, want := range []string{"=== 异常摘要 ===", "nvme11n1 写延迟存在突增", "候选线索"} {
		if !strings.Contains(string(summaryReq.Data), want) {
			t.Fatalf("sink 中规则摘要缺少 %q:\n%s", want, summaryReq.Data)
		}
	}
}

func TestExecuteBundleMergedReportWritesHostSummaryThroughSink(t *testing.T) {
	sink := &aiBundleRecordingSink{}
	fp := NewFileProcessor()
	fp.SetOutputSink(sink)

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		Merged:   true,
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: at,
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 41,
					WriteAwait:     300.11,
				}},
			}},
		},
	}

	if err := fp.executeBundle(bundle, "", "", "report", loc, AIConfig{}); err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if len(sink.reqs) != 1 {
		t.Fatalf("合并报告应通过 sink 写出主机级结论, got=%d", len(sink.reqs))
	}
	req := sink.reqs[0]
	if !req.ToStdout || req.Format != internaloutput.FormatText {
		t.Fatalf("主机级结论应写到 stdout text sink: %+v", req)
	}
	for _, want := range []string{"=== 主机级结论 ===", "风险信号=", "nvme11n1 写延迟存在突增"} {
		if !strings.Contains(string(req.Data), want) {
			t.Fatalf("sink 中主机级结论缺少 %q:\n%s", want, req.Data)
		}
	}
}

func TestExecuteBundleAILocalMLSendsSavedCSVDataToAI(t *testing.T) {
	var requests []localai.Request
	modelPath := createTestBinary(t, localai.DefaultModelName())
	runtimePath := createTestBinary(t, "llama-cli")
	fp := NewFileProcessorWithService(localai.NewService(runnerStub{
		requests: &requests,
		output:   `{"summary":"发现 nvme11n1 写延迟突增","incidents":[]}`,
	}))

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	avgReqSize := 4.0
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: start,
				CPU:       iostat.CPUStats{IOWait: 25, Idle: 60},
				Devices: []iostat.DeviceStats{{
					Device:           "nvme11n1",
					WriteReqPerSec:   1,
					WriteKBPerSec:    4,
					WriteAwait:       300.11,
					AvgQueueSize:     0.5,
					AvgReqSize:       &avgReqSize,
					ReadReqPerSec:    0,
					ReadKBPerSec:     0,
					ReadAwait:        0,
					ReadMergePerSec:  0,
					DiscardReqPerSec: 2,
					DiscardKBPerSec:  8,
					DiscardAwait:     5,
				}},
			}},
		},
	}

	err = fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{
		Enabled:     true,
		ModelPath:   modelPath,
		RuntimePath: runtimePath,
	})
	if err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("期望 AI runner 被调用一次, got=%d", len(requests))
	}

	prompt := requests[0].Prompt
	for _, want := range []string{
		"字段结构 / ML format",
		"工具确认的 finding 事实",
		"iostat-write-latency-nvme11n1",
		"iostat_csv",
		"csv_path",
		"batch: 1/1",
		"row_range: 1-1/1",
		"timestamp,device,read_req_per_sec",
		"write_await",
		"discard_req_per_sec",
		"discard_await",
		"cpu_iowait",
		"cpu_idle",
		"CPU 字段单位: %",
		"单位: ms",
		"nvme11n1",
		"300.11",
		"25.00",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("AI prompt 未包含 %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, `"evidence"`) {
		t.Fatalf("ai-local ml 不应把 evidence-only JSON 作为主要输入:\n%s", prompt)
	}

	matches, err := filepath.Glob("iostat_*.csv")
	if err != nil {
		t.Fatalf("匹配 CSV 文件失败: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("期望生成 iostat CSV 文件, got=%v", matches)
	}
}

func TestExecuteBundleAILocalMLSendsTopProcessRowsToAI(t *testing.T) {
	var requests []localai.Request
	modelPath := createTestBinary(t, localai.DefaultModelName())
	runtimePath := createTestBinary(t, "llama-cli")
	fp := NewFileProcessorWithService(localai.NewService(runnerStub{
		requests: &requests,
		output:   `{"summary":"ok","incidents":[]}`,
	}))

	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 6, 58, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		Top: &top.TopLog{
			Snapshots: []top.TopSnapshot{{
				Timestamp:  at,
				Load1:      6.2,
				CpuIdle:    84.2,
				CpuWait:    0.1,
				TaskTotal:  900,
				TaskZombie: 1,
				Processes: []top.ProcessStats{{
					PID:        3666962,
					User:       "root",
					State:      "D",
					CPUPercent: 0,
					MemPercent: 0,
					VirtKB:     123456,
					ResKB:      4096,
					ShrKB:      2048,
					Command:    "sshd",
				}, {
					PID:        19518,
					User:       "oracle",
					State:      "R",
					CPUPercent: 88.5,
					MemPercent: 3.2,
					VirtKB:     987654,
					ResKB:      131072,
					ShrKB:      8192,
					Command:    "oracle",
				}, {
					PID:        123,
					User:       "app",
					State:      "S",
					CPUPercent: 0.1,
					MemPercent: 0.1,
					VirtKB:     20480,
					ResKB:      1024,
					ShrKB:      512,
					Command:    "sleep",
				}},
			}},
		},
	}

	err = fp.executeBundle(bundle, "", "", "ml", loc, AIConfig{
		Enabled:     true,
		ModelPath:   modelPath,
		RuntimePath: runtimePath,
	})
	if err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}
	if len(requests) == 0 {
		t.Fatalf("期望 AI runner 被调用")
	}

	var prompts []string
	for _, req := range requests {
		prompts = append(prompts, req.Prompt)
	}
	prompt := strings.Join(prompts, "\n")
	for _, want := range []string{
		"ml-top-processes",
		"top_process_csv",
		"timestamp,pid,user,state,cpu_percent,mem_percent,virt_kb,res_kb,shr_kb,command",
		"2026-04-21 03:06:58,3666962,root,D",
		"sshd",
		"19518,oracle,R,88.5,3.2",
		"123,app,S,0.1,0.1",
		"top-process-d-state",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("AI prompt 未包含 top 进程字段 %q:\n%s", want, prompt)
		}
	}

	matches, err := filepath.Glob("top_processes_*.csv")
	if err != nil {
		t.Fatalf("匹配 top process CSV 文件失败: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("期望生成 top process CSV 文件, got=%v", matches)
	}
	csvData, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("读取 top process CSV 文件失败: %v", err)
	}
	if !strings.Contains(string(csvData), "123,app,S,0.1,0.1") {
		t.Fatalf("top process CSV 应包含普通低占用进程，证明 AI 输入是完整表格而非候选行: %s", csvData)
	}
}

func TestExecuteBundleJSONIncludesGeneratedFindings(t *testing.T) {
	fp := NewFileProcessor()
	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换测试目录失败: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:          "nvme11n1",
					WriteReqPerSec:  41,
					WriteKBPerSec:   277,
					WriteAwait:      300.11,
					AvgQueueSize:    0.01,
					ReadReqPerSec:   0,
					ReadKBPerSec:    0,
					ReadAwait:       0,
					ReadMergePerSec: 0,
				}},
			}},
		},
	}

	if err := fp.executeBundle(bundle, "", "", "json", loc, AIConfig{Enabled: false}); err != nil {
		t.Fatalf("executeBundle 返回错误: %v", err)
	}

	matches, err := filepath.Glob("iostat_*.json")
	if err != nil {
		t.Fatalf("匹配 JSON 文件失败: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("期望生成一个 iostat JSON 文件, got=%v", matches)
	}

	content, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("读取 JSON 文件失败: %v", err)
	}
	var got struct {
		Data     []output.IOStatRawMetrics `json:"data"`
		Findings []findings.Finding        `json:"findings"`
	}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("JSON 内容无法解析: %v", err)
	}
	if len(got.Data) != 1 || got.Data[0].Device != "nvme11n1" || got.Data[0].WriteAwait != 300.11 {
		t.Fatalf("JSON data 未包含原始 iostat 行: %+v", got.Data)
	}
	finding, ok := findProcessorFindingByRuleID(got.Findings, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("JSON findings 未包含写延迟 finding: %+v", got.Findings)
	}
	if finding.Time != "2026-04-21 03:29:12" || finding.ObservedValue != 300.11 {
		t.Fatalf("finding 关键字段不一致: %+v", finding)
	}
}

func TestExecuteBundleMergedReportPrintsHostLevelSummaryBeforeModuleDetails(t *testing.T) {
	fp := NewFileProcessor()
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 0, 0, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		Merged:   true,
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 41,
					WriteKBPerSec:  277,
					WriteAwait:     300.11,
				}},
			}},
		},
		Top: &top.TopLog{
			Snapshots: []top.TopSnapshot{
				{Timestamp: start, Load1: 5.0, CpuIdle: 70, CpuWait: 0, TaskRunning: 8},
				{Timestamp: start.Add(5 * time.Second), Load1: 9.0, CpuIdle: 65, CpuWait: 0, TaskRunning: 14},
				{Timestamp: start.Add(10 * time.Second), Load1: 7.0, CpuIdle: 68, CpuWait: 0, TaskRunning: 10},
			},
		},
	}

	output := captureStdout(t, func() {
		if err := fp.executeBundle(bundle, "", "", "report", loc, AIConfig{Enabled: false}); err != nil {
			t.Fatalf("executeBundle 返回错误: %v", err)
		}
	})

	for _, want := range []string{
		"=== 主机级结论 ===",
		"风险信号=1 候选线索=1",
		"关键风险/线索:",
		"1. [高][风险信号] 系统负载持续偏高",
		"[高][候选线索] nvme11n1 写延迟存在突增",
		"建议优先查看: top/system, iostat/nvme11n1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("主机级摘要缺少 %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "Top 风险/线索") {
		t.Fatalf("主机级摘要不应把跨模块 finding 错标为 Top:\n%s", output)
	}
	if strings.Index(output, "=== 主机级结论 ===") > strings.Index(output, "=== 异常摘要 ===") {
		t.Fatalf("主机级结论应出现在模块异常摘要之前:\n%s", output)
	}
}

func TestExecuteBundleMergedReportRanksRiskSignalsBeforeCandidates(t *testing.T) {
	fp := NewFileProcessor()
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 0, 0, 0, loc)
	bundle := &analysisBundle{
		Hostname: "rdsmaster1",
		Merged:   true,
		IOStat: &iostat.IOStatLog{
			Data: []iostat.IOStatData{{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 41,
					WriteKBPerSec:  277,
					WriteAwait:     300.11,
				}},
			}},
		},
		Top: &top.TopLog{
			Snapshots: []top.TopSnapshot{
				{Timestamp: start, CpuIdle: 95, TaskZombie: 1},
				{Timestamp: start.Add(5 * time.Second), CpuIdle: 95, TaskZombie: 1},
			},
		},
	}

	output := captureStdout(t, func() {
		if err := fp.executeBundle(bundle, "", "", "report", loc, AIConfig{Enabled: false}); err != nil {
			t.Fatalf("executeBundle 返回错误: %v", err)
		}
	})

	riskIndex := strings.Index(output, "[中][风险信号] 存在僵尸进程")
	candidateIndex := strings.Index(output, "[高][候选线索] nvme11n1 写延迟存在突增")
	if riskIndex < 0 || candidateIndex < 0 {
		t.Fatalf("测试前提不成立，输出未同时包含风险信号和候选线索:\n%s", output)
	}
	if riskIndex > candidateIndex {
		t.Fatalf("主机级摘要应先展示风险信号，再展示候选线索:\n%s", output)
	}
}

func TestBuildCSVMLSectionKeepsCompleteCSVInOriginalOrder(t *testing.T) {
	header := []string{"timestamp", "device", "read_req_per_sec", "write_req_per_sec", "read_kb_per_sec", "write_kb_per_sec", "read_merge_per_sec", "write_merge_per_sec", "read_await", "write_await", "avg_queue_size", "avg_req_size"}
	rows := make([][]string, 13)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("2026-04-21 03:%02d:00", i), "sda", "0.00", "10.00", "0.00", "64.00", "0.00", "0.00", "0.00", "0.20", "0.00", "NA"}
	}
	rows[8] = []string{"2026-04-21 03:08:00", "nvme11n1", "0.00", "41.00", "0.00", "277.00", "0.00", "0.00", "0.00", "300.11", "0.00", "NA"}
	data, err := formatCSVRecords(header, rows)
	if err != nil {
		t.Fatalf("formatCSVRecords 返回错误: %v", err)
	}
	filename := filepath.Join(t.TempDir(), "iostat.csv")
	if err := os.WriteFile(filename, []byte(data+"\n"), 0o644); err != nil {
		t.Fatalf("写入测试 CSV 失败: %v", err)
	}

	section, err := buildCSVMLSection("ml-iostat-data", "iostat", filename)
	if err != nil {
		t.Fatalf("buildCSVMLSection 返回错误: %v", err)
	}
	if section.SelectedRows != 13 || section.TotalRows != 13 {
		t.Fatalf("应保留完整 CSV 行数, selected=%d total=%d", section.SelectedRows, section.TotalRows)
	}
	if strings.Contains(section.Description, "高风险") || strings.Contains(section.Description, "风险排序") {
		t.Fatalf("section 描述不应包含风险筛选语义: %s", section.Description)
	}
	firstDataLine := strings.Split(section.Data, "\n")[1]
	if !strings.Contains(firstDataLine, "03:00:00,sda") {
		t.Fatalf("第一条数据行应保持原始顺序, got=%s", firstDataLine)
	}
	if !strings.Contains(section.Data, "03:08:00,nvme11n1") {
		t.Fatalf("完整 CSV 应包含中间异常行, got:\n%s", section.Data)
	}
}

func findProcessorFindingByRuleID(items []findings.Finding, ruleID string) (findings.Finding, bool) {
	for _, item := range items {
		if item.RuleID == ruleID {
			return item, true
		}
	}
	return findings.Finding{}, false
}

func TestBuildMLDiagnosisContextIncludesMemInfoAnomalyTime(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 100 * 1024 * 1024}},
			{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 8 * 1024 * 1024}},
			{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 99 * 1024 * 1024}},
		},
	}
	bundle := &analysisBundle{
		Hostname: "db01",
		MemInfo:  log,
	}

	got := buildMLDiagnosisContext(bundle, start, start.Add(10*time.Second))

	found := false
	for _, evidence := range got.Evidence {
		if strings.Contains(evidence.ID, "meminfo-available-anomaly") && evidence.Time == "2026-04-23 05:04:08" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("期望 AI payload 包含 MemAvailable 异常时间点, got=%+v", got.Evidence)
	}
}
