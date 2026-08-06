package localai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/findings"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type stubRunner struct {
	output string
	err    error
}

func (s stubRunner) Run(_ context.Context, _ Request) (string, error) {
	return s.output, s.err
}

type captureRunner struct {
	output   string
	requests []Request
}

func (s *captureRunner) Run(_ context.Context, req Request) (string, error) {
	s.requests = append(s.requests, req)
	return s.output, nil
}

type sequenceRunner struct {
	outputs  []string
	requests []Request
}

func (s *sequenceRunner) Run(_ context.Context, req Request) (string, error) {
	s.requests = append(s.requests, req)
	if len(s.outputs) == 0 {
		return `{"summary":"ok","incidents":[]}`, nil
	}
	output := s.outputs[0]
	s.outputs = s.outputs[1:]
	return output, nil
}

func createFakeBinary(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	return path
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建 stderr pipe 失败: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = old
		_ = reader.Close()
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 stderr writer 失败: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("读取 stderr 失败: %v", err)
	}
	return string(output)
}

func TestBuildPromptContainsEvidenceIDs(t *testing.T) {
	input := diagnosis.Context{
		Hostname: "db01",
		Evidence: []diagnosis.Evidence{
			{ID: "meminfo-available", Source: "meminfo", Summary: "可用内存偏低"},
			{ID: "top-cpu-wait", Source: "top", Summary: "CPU wait 偏高"},
		},
	}

	prompt := BuildPrompt(input)
	if !strings.Contains(prompt, "meminfo-available") || !strings.Contains(prompt, "top-cpu-wait") {
		t.Fatalf("prompt 未包含 evidence id: %s", prompt)
	}
	if !strings.Contains(prompt, "/no_think") {
		t.Fatalf("prompt 应要求 Qwen3 关闭思考输出: %s", prompt)
	}
}

func TestBuildPromptConstrainTopProcessRowsAsCandidates(t *testing.T) {
	prompt := BuildPrompt(diagnosis.Context{
		Hostname: "db01",
		Evidence: []diagnosis.Evidence{{
			ID:      "top-process-rows",
			Source:  "top",
			Level:   diagnosis.SignalLevelSoft,
			Summary: "top-process-rows 为代表进程行，仅用于定位候选进程。",
		}},
	})

	for _, want := range []string{
		"top-process-rows 只能作为候选进程行",
		"top-process-high-cpu 只能作为候选进程线索",
		"high_cpu incident 必须同时引用 top-cpu-idle 或 top-load-high",
		"high_mem incident 必须同时引用 meminfo-available、meminfo-swap-usage、meminfo-commit-pressure 或 meminfo-anon-growth",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt 缺少 top process 约束 %q:\n%s", want, prompt)
		}
	}
}

func TestParseResponseFiltersInvalidIncidents(t *testing.T) {
	raw := `{
  "summary": "存在组合型压力",
  "incidents": [
    {
      "classification": "内存压力",
      "severity": "warning",
      "confidence": 0.88,
      "evidence_ids": ["meminfo-available", "meminfo-swap-usage"],
      "next_checks": ["检查大对象分配"]
    },
    {
      "classification": "无效结论",
      "severity": "warning",
      "confidence": 0.2,
      "evidence_ids": ["meminfo-available", "missing"],
      "next_checks": []
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"meminfo-available":  {},
		"meminfo-swap-usage": {},
	})
	if err != nil {
		t.Fatalf("ParseResponse 返回错误: %v", err)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("期望只保留 1 条有效 incident, got=%d", len(payload.Incidents))
	}
}

func TestParseResponseRejectsWhitespaceOnlySummaryWithoutValidIncidents(t *testing.T) {
	raw := `{
  "summary": "   ",
  "incidents": [
    {
      "classification": "无效结论",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["meminfo-available"],
      "next_checks": []
    }
  ]
}`

	if _, err := ParseResponse(raw, map[string]struct{}{
		"meminfo-available": {},
	}); err == nil {
		t.Fatalf("summary 只有空白且没有有效 incident 时应校验失败")
	}
}

func TestParseResponseNormalizesIncidentTextFields(t *testing.T) {
	raw := `{
  "summary": "  存在 I/O 风险  ",
  "incidents": [
    {
      "classification": "  I/O 延迟  ",
      "severity": " warning ",
      "confidence": 0.88,
      "evidence_ids": [" ml-iostat-data ", " iostat-write-latency-nvme11n1 "],
      "next_checks": [" 检查慢盘 ", "  "]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-iostat-data":                {},
		"iostat-write-latency-nvme11n1": {},
	})
	if err != nil {
		t.Fatalf("ParseResponse 应接受可安全 trim 的模型输出: %v", err)
	}
	if payload.Summary != "存在 I/O 风险" {
		t.Fatalf("summary 应 trim, got=%q", payload.Summary)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("期望保留 1 条归一化后的 incident, got=%+v", payload.Incidents)
	}
	incident := payload.Incidents[0]
	if incident.Classification != "I/O 延迟" || incident.Severity != "warning" {
		t.Fatalf("classification/severity 应 trim, got=%+v", incident)
	}
	if len(incident.EvidenceIDs) != 2 ||
		incident.EvidenceIDs[0] != "ml-iostat-data" ||
		incident.EvidenceIDs[1] != "iostat-write-latency-nvme11n1" {
		t.Fatalf("evidence_ids 应 trim 后校验并保留, got=%+v", incident.EvidenceIDs)
	}
	if len(incident.NextChecks) != 1 || incident.NextChecks[0] != "检查慢盘" {
		t.Fatalf("next_checks 应 trim 并丢弃空白项, got=%+v", incident.NextChecks)
	}
}

func TestParseResponseDropsIncidentWithWhitespaceOnlyClassification(t *testing.T) {
	raw := `{
  "summary": "存在候选线索",
  "incidents": [
    {
      "classification": "   ",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["ml-format", "ml-iostat-data"],
      "next_checks": ["检查慢盘"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-format":      {},
		"ml-iostat-data": {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤空白 incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("classification 为空白的 incident 应被过滤, got=%+v", payload.Incidents)
	}
}

func TestParseResponseNormalizesCommonSeveritySynonyms(t *testing.T) {
	raw := `{
  "summary": "存在多类风险",
  "incidents": [
    {
      "classification": "严重 I/O 延迟",
      "severity": "HIGH",
      "confidence": 0.9,
      "evidence_ids": ["ml-iostat-data", "iostat-write-latency-nvme11n1"],
      "next_checks": ["检查慢盘"]
    },
    {
      "classification": "观察项",
      "severity": "low",
      "confidence": 0.9,
      "evidence_ids": ["ml-meminfo-data", "meminfo-anon-growth"],
      "next_checks": ["观察趋势"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-iostat-data":                {},
		"iostat-write-latency-nvme11n1": {},
		"ml-format":                     {},
		"ml-meminfo-data":               {},
		"meminfo-anon-growth":           {},
	})
	if err != nil {
		t.Fatalf("常见 severity 同义值应可归一化: %v", err)
	}
	if len(payload.Incidents) != 2 {
		t.Fatalf("期望保留 2 条 incident, got=%+v", payload.Incidents)
	}
	if payload.Incidents[0].Severity != "critical" || payload.Incidents[1].Severity != "info" {
		t.Fatalf("severity 应归一化到 info/warning/critical, got=%+v", payload.Incidents)
	}
}

func TestParseResponseDropsIncidentWithUnknownSeverity(t *testing.T) {
	raw := `{
  "summary": "存在候选线索",
  "incidents": [
    {
      "classification": "未知级别",
      "severity": "urgent",
      "confidence": 0.9,
      "evidence_ids": ["ml-iostat-data", "iostat-write-latency-nvme11n1"],
      "next_checks": ["检查慢盘"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-iostat-data":                {},
		"iostat-write-latency-nvme11n1": {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤未知 severity incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("未知 severity incident 应被过滤, got=%+v", payload.Incidents)
	}
}

func TestParseResponseDropsIncidentWithDuplicateEvidenceIDsOnly(t *testing.T) {
	raw := `{
  "summary": "存在候选线索",
  "incidents": [
    {
      "classification": "I/O 延迟",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["ml-iostat-data", " ml-iostat-data "],
      "next_checks": ["检查慢盘"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-iostat-data": {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤重复证据 incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("重复 evidence_id 不能凑够两个独立证据, got=%+v", payload.Incidents)
	}
}

func TestParseResponseDropsIncidentBackedOnlyByMLFormatAndOneDataSection(t *testing.T) {
	raw := `{
  "summary": "存在候选线索",
  "incidents": [
    {
      "classification": "I/O 延迟",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["ml-format", "ml-iostat-data"],
      "next_checks": ["检查慢盘"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-format":      {},
		"ml-iostat-data": {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤 ml-format 凑数 incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("ml-format 不是观测证据，不能和单个数据 section 凑够双证据, got=%+v", payload.Incidents)
	}
}

func TestParseResponseDeduplicatesEvidenceIDsButKeepsValidIncident(t *testing.T) {
	raw := `{
  "summary": "存在 I/O 风险",
  "incidents": [
    {
      "classification": "I/O 延迟",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["ml-iostat-data", "ml-iostat-data", "iostat-write-latency-nvme11n1"],
      "next_checks": ["检查慢盘"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-iostat-data":                {},
		"iostat-write-latency-nvme11n1": {},
	})
	if err != nil {
		t.Fatalf("去重后仍有两个有效证据时应保留 incident: %v", err)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("期望保留 1 条 incident, got=%+v", payload.Incidents)
	}
	got := payload.Incidents[0].EvidenceIDs
	if len(got) != 2 || got[0] != "ml-iostat-data" || got[1] != "iostat-write-latency-nvme11n1" {
		t.Fatalf("evidence_ids 应按首次出现顺序去重, got=%+v", got)
	}
}

func TestParseResponseDropsTopProcessCandidateOnlyIncident(t *testing.T) {
	raw := `{
  "summary": "存在候选进程线索",
  "incidents": [
    {
      "classification": "高 CPU 进程",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["top-process-rows", "ml-top-processes"],
      "next_checks": ["检查进程"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"top-process-rows": {},
		"ml-top-processes": {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤候选-only incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("仅由 top 进程候选 evidence 支撑的 incident 应被过滤, got=%+v", payload.Incidents)
	}
}

func TestParseResponseDropsTopHighCPUProcessFindingWithoutSystemPressure(t *testing.T) {
	raw := `{
  "summary": "存在候选进程线索",
  "incidents": [
    {
      "classification": "高 CPU 进程",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["top-process-high-cpu", "top-process-rows"],
      "next_checks": ["检查进程"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"top-process-high-cpu": {},
		"top-process-rows":     {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤候选-only high CPU incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("top-process-high-cpu 缺少 CPU 压力 evidence 时应被过滤, got=%+v", payload.Incidents)
	}
}

func TestParseResponseDropsTopDStateProcessFindingWithoutPressure(t *testing.T) {
	raw := `{
  "summary": "存在 D 状态候选进程",
  "incidents": [
    {
      "classification": "D 状态进程",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["ml-top-processes", "top-process-d-state"],
      "next_checks": ["检查进程阻塞"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"ml-top-processes":    {},
		"top-process-d-state": {},
	})
	if err != nil {
		t.Fatalf("summary 有效时应保留 AI 结果并过滤 D-state 候选-only incident: %v", err)
	}
	if len(payload.Incidents) != 0 {
		t.Fatalf("top-process-d-state 缺少 iowait/load 等压力 evidence 时应被过滤, got=%+v", payload.Incidents)
	}
}

func TestParseResponseKeepsTopProcessIncidentWithPressureEvidence(t *testing.T) {
	raw := `{
  "summary": "CPU 压力与进程候选吻合",
  "incidents": [
    {
      "classification": "高 CPU 进程伴随 CPU 压力",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["top-process-rows", "top-cpu-idle"],
      "next_checks": ["检查进程 CPU 使用"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"top-process-rows": {},
		"top-cpu-idle":     {},
	})
	if err != nil {
		t.Fatalf("候选进程结合真实 CPU 压力 evidence 时应保留 incident: %v", err)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("期望保留 1 条 incident, got=%+v", payload.Incidents)
	}
}

func TestParseResponseKeepsTopHighCPUProcessFindingWithSystemPressure(t *testing.T) {
	raw := `{
  "summary": "CPU 压力与高 CPU 进程候选吻合",
  "incidents": [
    {
      "classification": "高 CPU 进程伴随 CPU 压力",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["top-process-high-cpu", "top-cpu-idle"],
      "next_checks": ["检查进程 CPU 使用"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"top-process-high-cpu": {},
		"top-cpu-idle":         {},
	})
	if err != nil {
		t.Fatalf("高 CPU 进程结合真实 CPU 压力 evidence 时应保留 incident: %v", err)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("期望保留 1 条 incident, got=%+v", payload.Incidents)
	}
}

func TestParseResponseKeepsTopDStateProcessFindingWithIOWaitPressure(t *testing.T) {
	raw := `{
  "summary": "D 状态与 iowait 压力吻合",
  "incidents": [
    {
      "classification": "D 状态阻塞伴随 I/O wait",
      "severity": "warning",
      "confidence": 0.9,
      "evidence_ids": ["top-process-d-state", "top-cpu-wait"],
      "next_checks": ["检查阻塞进程内核栈"]
    }
  ]
}`

	payload, err := ParseResponse(raw, map[string]struct{}{
		"top-process-d-state": {},
		"top-cpu-wait":        {},
	})
	if err != nil {
		t.Fatalf("D-state 候选结合真实 iowait evidence 时应保留 incident: %v", err)
	}
	if len(payload.Incidents) != 1 {
		t.Fatalf("期望保留 1 条 incident, got=%+v", payload.Incidents)
	}
}

func TestBuildMLPromptDescribesTableSchemaWithoutAnalyzerRules(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-24 15:41:51",
		EndTime:   "2026-04-24 15:42:01",
		Sections: []MLSection{{
			ID:           "ml-meminfo-data",
			Module:       "meminfo",
			Format:       "meminfo_csv",
			FilePath:     "meminfo_20260424154151.csv",
			SelectedRows: 2,
			TotalRows:    10,
			Data: strings.Join([]string{
				"timestamp,mem_total,mem_free,mem_available,buffers,cached,slab,s_reclaimable,s_unreclaim,anon_pages,swap_total,swap_free",
				"2026-04-24 15:41:51,134217728,1048576,2097152,0,0,3145728,1048576,2097152,4194304,8388608,4194304",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"module: meminfo",
		"format: meminfo_csv",
		"字段结构",
		"mem_available",
		"有效可用内存",
		"mem_free+buffers+cached+s_reclaimable",
		"单位",
		"csv_path: meminfo_20260424154151.csv",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 未包含表结构说明 %q:\n%s", want, prompt)
		}
	}
	for _, forbidden := range []string{
		"必须执行的 meminfo 判断规则",
		"classification=\"memory_pressure\"",
		"classification=\"io_write_latency\"",
		"高风险",
		"最高风险",
	} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("ML prompt 不应包含工具侧异常判断 %q:\n%s", forbidden, prompt)
		}
	}
}

func TestBuildMLPromptIOStatCSVDescribesCPUAndDiscardFields(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:00",
		EndTime:   "2026-04-21 03:10:00",
		Sections: []MLSection{{
			ID:           "ml-iostat-data",
			Module:       "iostat",
			Format:       "iostat_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,device,read_req_per_sec,write_req_per_sec,read_kb_per_sec,write_kb_per_sec,read_await,write_await,avg_queue_size,discard_req_per_sec,discard_await,cpu_iowait,cpu_idle,utilization",
				"2026-04-21 03:00:00,nvme0n1,0.00,0.00,0.00,0.00,0.00,0.00,1.20,50.00,5.00,25.00,60.00,96.50",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"iostat_csv",
		"discard_req_per_sec",
		"discard_await",
		"cpu_iowait",
		"cpu_idle",
		"utilization",
		"await 单位: ms",
		"CPU 字段单位: %",
		"utilization 单位: %",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 缺少 iostat_csv 字段说明 %q:\n%s", want, prompt)
		}
	}
}

func TestBuildMLPromptDoesNotHardCodeIOStatLatencyIncident(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:29:12",
		EndTime:   "2026-04-21 03:29:12",
		Sections: []MLSection{{
			ID:           "ml-iostat-data",
			Module:       "iostat",
			Format:       "iostat_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,device,write_await",
				"2026-04-21 03:29:12,nvme11n1,300.11",
			}, "\n"),
		}},
	})

	for _, forbidden := range []string{
		"If write_await_ms >= 100",
		"incidents must contain",
		"severity \"critical\"",
		"第一条数据行就是最高风险行",
	} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("ML prompt 不应包含早期调试用硬编码 iostat 结论 %q:\n%s", forbidden, prompt)
		}
	}
}

func TestBuildMLPromptConstrainTopProcessCSVIncidents(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:00",
		EndTime:   "2026-04-21 03:10:00",
		Sections: []MLSection{{
			ID:           "ml-top-processes",
			Module:       "top",
			Format:       "top_process_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,pid,user,state,cpu_percent,mem_percent,virt_kb,res_kb,shr_kb,command",
				"2026-04-21 03:00:00,19518,oracle,R,88.5,3.2,987654,131072,8192,oracle",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"top_process_csv 中 CPU/MEM 高占用不能单独生成 incident",
		"high CPU incident 必须同时引用 top-cpu-idle 或 top-load-high",
		"high MEM incident 必须同时引用 meminfo-available、meminfo-swap-usage、meminfo-commit-pressure 或 meminfo-anon-growth",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 缺少 top process CSV 约束 %q:\n%s", want, prompt)
		}
	}
}

func TestBuildMLPromptConstrainTopHighCPUProcessFinding(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:00",
		EndTime:   "2026-04-21 03:10:00",
		Findings: []findings.Finding{{
			RuleID:        "top-process-high-cpu",
			Source:        "top",
			Category:      "process_cpu",
			Severity:      findings.SeverityMedium,
			Title:         "CPU 饱和时存在高 CPU 进程",
			Target:        "process",
			Metric:        "process_cpu_pct",
			ObservedValue: 95,
			Time:          "2026-04-21 03:00:00",
		}},
		Sections: []MLSection{{
			ID:           "ml-top-processes",
			Module:       "top",
			Format:       "top_process_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,pid,user,state,cpu_percent,mem_percent,virt_kb,res_kb,shr_kb,command",
				"2026-04-21 03:00:00,19518,oracle,R,95.0,3.2,987654,131072,8192,oracle",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"top-process-high-cpu 是进程线索",
		"top-process-high-cpu 不能单独作为 high CPU incident 根因",
		"high CPU incident 必须同时引用 top-cpu-idle 或 top-load-high",
		"有效 evidence_ids: ml-format, ml-top-processes, top-process-high-cpu",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 缺少 top-process-high-cpu 约束 %q:\n%s", want, prompt)
		}
	}
}

func TestBuildMLPromptConstrainTopDStateProcessFinding(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:00",
		EndTime:   "2026-04-21 03:10:00",
		Findings: []findings.Finding{{
			RuleID:        "top-process-d-state",
			Source:        "top",
			Category:      "process_d_state",
			Severity:      findings.SeverityMedium,
			Nature:        findings.FindingNatureCandidate,
			Title:         "存在 D 状态进程",
			Target:        "process",
			Metric:        "d_state_process_count",
			ObservedValue: 2,
			Time:          "2026-04-21 03:00:00",
		}},
		Sections: []MLSection{{
			ID:           "ml-top-processes",
			Module:       "top",
			Format:       "top_process_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,pid,user,state,cpu_percent,mem_percent,virt_kb,res_kb,shr_kb,command",
				"2026-04-21 03:00:00,19518,oracle,D,0.0,0.0,987654,131072,8192,oracle",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"top-process-d-state 是进程阻塞线索",
		"不能单独作为系统级 I/O wait 或 load incident 根因",
		"D-state incident 必须同时引用 top-cpu-wait 或 top-load-high",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 缺少 top-process-d-state 约束 %q:\n%s", want, prompt)
		}
	}
}

func TestBuildMLPromptTopCSVDescribesRunnableQueue(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:00",
		EndTime:   "2026-04-21 03:10:00",
		Sections: []MLSection{{
			ID:           "ml-top-data",
			Module:       "top",
			Format:       "top_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,load_1,load_5,load_15,cpu_count,load_1_per_cpu,task_total,task_running,task_running_per_cpu,task_sleeping,task_stopped,task_zombie,cpu_user,cpu_sys,cpu_idle,cpu_wait,cpu_steal",
				"2026-04-21 03:00:00,9.00,8.00,7.00,16,0.562,100,14,0.875,86,0,0,20.0,10.0,65.0,0.0,0.0",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"top_csv",
		"cpu_count 为目标主机 CPU 核数",
		"load_1_per_cpu/task_running_per_cpu",
		"task_running 表示 runnable/R 队列",
		"per-core 判断 CPU 容量",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 缺少 top_csv runnable 队列说明 %q:\n%s", want, prompt)
		}
	}
}

func TestBuildMLPromptIncludesFindingFactsBesideCSV(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:29:12",
		EndTime:   "2026-04-21 03:29:12",
		Findings: []findings.Finding{{
			RuleID:        "iostat-write-latency-nvme11n1",
			Source:        "iostat",
			Category:      "disk_latency",
			Severity:      findings.SeverityHigh,
			Nature:        findings.FindingNatureCandidate,
			Title:         "nvme11n1 写延迟存在突增",
			Target:        "nvme11n1",
			Metric:        "write_await_ms",
			Operator:      ">=",
			Threshold:     8,
			ObservedValue: 300.11,
			EvidenceRef:   "iostat:nvme11n1:write_await_ms:2026-04-21 03:29:12",
			Time:          "2026-04-21 03:29:12",
		}},
		Sections: []MLSection{{
			ID:           "ml-iostat-data",
			Module:       "iostat",
			Format:       "iostat_csv",
			FilePath:     "iostat_20260421032912.csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,device,write_await",
				"2026-04-21 03:29:12,nvme11n1,300.11",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"工具确认的 finding 事实",
		"CSV 原始数据仍然是最终证据来源",
		"nature=risk 表示风险信号",
		"nature=candidate 表示候选线索",
		"candidate 不能单独升级为最终根因",
		"有效 evidence_ids: ml-format, ml-iostat-data, iostat-write-latency-nvme11n1",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 未包含 finding 事实 %q:\n%s", want, prompt)
		}
	}

	got := extractMLFindingFacts(t, prompt)
	if len(got) != 1 {
		t.Fatalf("期望 1 条 finding fact, got=%+v", got)
	}
	finding := got[0]
	if finding.RuleID != "iostat-write-latency-nvme11n1" ||
		finding.Source != "iostat" ||
		finding.Severity != findings.SeverityHigh ||
		finding.Nature != findings.FindingNatureCandidate ||
		finding.Target != "nvme11n1" ||
		finding.Metric != "write_await_ms" ||
		finding.Threshold != 8 ||
		finding.ObservedValue != 300.11 ||
		finding.EvidenceRef != "iostat:nvme11n1:write_await_ms:2026-04-21 03:29:12" {
		t.Fatalf("finding fact 字段不一致: %+v", finding)
	}
}

func TestBuildMLSummaryPromptPreservesFindingNatureSemantics(t *testing.T) {
	prompt := BuildMLSummaryPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:04",
		EndTime:   "2026-04-21 03:59:57",
		Findings: []findings.Finding{{
			RuleID:   "iostat-write-latency-nvme11n1",
			Source:   "iostat",
			Severity: findings.SeverityHigh,
			Nature:   findings.FindingNatureCandidate,
		}},
		Sections: []MLSection{{ID: "ml-iostat-data"}},
	}, []diagnosis.AIResult{{
		Summary: "发现 nvme11n1 写延迟尖峰",
		Incidents: []diagnosis.Incident{{
			Classification: "设备级慢请求",
			Severity:       "warning",
			Confidence:     0.8,
			EvidenceIDs:    []string{"ml-iostat-data", "iostat-write-latency-nvme11n1"},
		}},
	}})

	for _, want := range []string{
		"nature=risk 表示风险信号",
		"nature=candidate 表示候选线索",
		"candidate 不能单独升级为最终根因",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML 汇总 prompt 未保留 finding nature 语义 %q:\n%s", want, prompt)
		}
	}
}

func TestBuildMLSummaryPromptIncludesFindingFacts(t *testing.T) {
	prompt := BuildMLSummaryPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:00:04",
		EndTime:   "2026-04-21 03:59:57",
		Findings: []findings.Finding{{
			RuleID:   "iostat-write-latency-nvme11n1",
			Source:   "iostat",
			Category: "disk_latency",
			Severity: findings.SeverityHigh,
			Nature:   findings.FindingNatureCandidate,
			Target:   "nvme11n1",
			Metric:   "write_await_ms",
			Time:     "2026-04-21 03:29:12",
		}},
		Sections: []MLSection{{ID: "ml-iostat-data"}},
	}, []diagnosis.AIResult{{
		Summary: "发现 nvme11n1 写延迟尖峰",
		Incidents: []diagnosis.Incident{{
			Classification: "设备级慢请求",
			Severity:       "warning",
			Confidence:     0.8,
			EvidenceIDs:    []string{"ml-iostat-data", "iostat-write-latency-nvme11n1"},
		}},
	}})

	if !strings.Contains(prompt, "### finding-facts") {
		t.Fatalf("ML 汇总 prompt 应包含原始 finding facts，避免丢失 nature 语义:\n%s", prompt)
	}
	got := extractMLFindingFacts(t, prompt)
	if len(got) != 1 || got[0].RuleID != "iostat-write-latency-nvme11n1" || got[0].Nature != findings.FindingNatureCandidate {
		t.Fatalf("ML 汇总 prompt finding facts 不完整: %+v", got)
	}
}

func TestBuildMLPromptExplainsIOStatLatencyWithoutSystemPressure(t *testing.T) {
	prompt := BuildMLPrompt(MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-21 03:29:12",
		EndTime:   "2026-04-21 03:29:12",
		Findings: []findings.Finding{{
			RuleID:        "iostat-write-latency-nvme11n1",
			Source:        "iostat",
			Category:      "disk_latency",
			Severity:      findings.SeverityHigh,
			Title:         "nvme11n1 写延迟存在突增",
			Target:        "nvme11n1",
			Metric:        "write_await_ms",
			ObservedValue: 300.11,
			Time:          "2026-04-21 03:29:12",
			Metrics: map[string]float64{
				"latency_system_pressure": 0,
			},
		}},
		Sections: []MLSection{{
			ID:           "ml-iostat-data",
			Module:       "iostat",
			Format:       "iostat_csv",
			SelectedRows: 1,
			TotalRows:    1,
			Data: strings.Join([]string{
				"timestamp,device,write_req_per_sec,write_await,avg_queue_size,cpu_iowait,utilization",
				"2026-04-21 03:29:12,nvme11n1,41.00,300.11,0.00,0.00,0.00",
			}, "\n"),
		}},
	})

	for _, want := range []string{
		"latency_system_pressure=0",
		"设备级慢请求/瞬时尖峰",
		"不要直接定性为系统级 I/O 拥塞",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("ML prompt 缺少 iostat latency_system_pressure 约束 %q:\n%s", want, prompt)
		}
	}
}

func TestMLPromptInputEvidenceIDsIncludesFindingRuleIDs(t *testing.T) {
	input := MLPromptInput{
		Sections: []MLSection{{ID: "ml-iostat-data"}},
		Findings: []findings.Finding{{
			RuleID: "iostat-write-latency-nvme11n1",
		}},
	}

	ids := input.EvidenceIDs()
	for _, want := range []string{"ml-format", "ml-iostat-data", "iostat-write-latency-nvme11n1"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("EvidenceIDs 缺少 %s: %+v", want, ids)
		}
	}
}

func extractMLFindingFacts(t *testing.T, prompt string) []findings.Finding {
	t.Helper()

	const begin = "```json\n"
	start := strings.Index(prompt, "### finding-facts")
	if start < 0 {
		t.Fatalf("prompt 缺少 finding facts block:\n%s", prompt)
	}
	jsonStart := strings.Index(prompt[start:], begin)
	if jsonStart < 0 {
		t.Fatalf("finding facts block 缺少 JSON fence:\n%s", prompt[start:])
	}
	jsonStart += start + len(begin)
	jsonEnd := strings.Index(prompt[jsonStart:], "\n```")
	if jsonEnd < 0 {
		t.Fatalf("finding facts block 未闭合:\n%s", prompt[jsonStart:])
	}

	var facts []findings.Finding
	if err := json.Unmarshal([]byte(prompt[jsonStart:jsonStart+jsonEnd]), &facts); err != nil {
		t.Fatalf("finding facts JSON 无法解析: %v\n%s", err, prompt[jsonStart:jsonStart+jsonEnd])
	}
	return facts
}

func TestSplitMLPromptInputBatchesPreservesOriginalRowOrder(t *testing.T) {
	input := MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-24 15:41:51",
		EndTime:   "2026-04-24 15:42:01",
		Sections: []MLSection{{
			ID:        "ml-iostat-data",
			Module:    "iostat",
			Format:    "iostat_csv",
			FilePath:  "iostat.csv",
			TotalRows: 5,
			Data: strings.Join([]string{
				"timestamp,device,write_await",
				"2026-04-24 15:41:51,sda,1.00",
				"2026-04-24 15:41:56,sda,2.00",
				"2026-04-24 15:42:01,nvme11n1,300.00",
				"2026-04-24 15:42:06,sda,4.00",
				"2026-04-24 15:42:11,sda,5.00",
			}, "\n"),
		}},
	}

	batches, err := splitMLPromptInputBatches(input, 2)
	if err != nil {
		t.Fatalf("splitMLPromptInputBatches 返回错误: %v", err)
	}
	if len(batches) != 3 {
		t.Fatalf("期望 3 个顺序 batch, got=%d", len(batches))
	}

	wantRows := []string{
		"2026-04-24 15:41:51,sda,1.00\n2026-04-24 15:41:56,sda,2.00",
		"2026-04-24 15:42:01,nvme11n1,300.00\n2026-04-24 15:42:06,sda,4.00",
		"2026-04-24 15:42:11,sda,5.00",
	}
	for index, want := range wantRows {
		got := batches[index].Sections[0]
		if got.BatchIndex != index+1 || got.BatchTotal != 3 {
			t.Fatalf("batch 元数据错误: %+v", got)
		}
		if !strings.Contains(got.Data, want) {
			t.Fatalf("batch %d 未保持原始顺序, want rows:\n%s\ngot:\n%s", index+1, want, got.Data)
		}
	}
}

func TestSplitMLPromptInputBatchesFiltersFindingsByBatchTime(t *testing.T) {
	input := MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-24 15:41:51",
		EndTime:   "2026-04-24 15:42:11",
		Findings: []findings.Finding{{
			RuleID:        "iostat-write-latency-nvme11n1",
			Source:        "iostat",
			Severity:      findings.SeverityHigh,
			Target:        "nvme11n1",
			Metric:        "write_await_ms",
			ObservedValue: 300,
			Time:          "2026-04-24 15:42:01",
		}},
		Sections: []MLSection{{
			ID:       "ml-iostat-data",
			Module:   "iostat",
			Format:   "iostat_csv",
			FilePath: "iostat.csv",
			Data: strings.Join([]string{
				"timestamp,device,write_await",
				"2026-04-24 15:41:51,sda,1.00",
				"2026-04-24 15:41:56,sda,2.00",
				"2026-04-24 15:42:01,nvme11n1,300.00",
				"2026-04-24 15:42:06,sda,4.00",
			}, "\n"),
		}},
	}

	batches, err := splitMLPromptInputBatches(input, 2)
	if err != nil {
		t.Fatalf("splitMLPromptInputBatches 返回错误: %v", err)
	}
	if len(batches) != 2 {
		t.Fatalf("期望 2 个 batch, got=%d", len(batches))
	}
	if len(batches[0].Findings) != 0 {
		t.Fatalf("第一批没有异常时间点，不应携带 finding: %+v", batches[0].Findings)
	}
	if len(batches[1].Findings) != 1 || batches[1].Findings[0].RuleID != "iostat-write-latency-nvme11n1" {
		t.Fatalf("第二批应携带对应 finding: %+v", batches[1].Findings)
	}
	if strings.Contains(BuildMLPrompt(batches[0]), "iostat-write-latency-nvme11n1") {
		t.Fatalf("第一批 prompt 不应包含范围外 finding:\n%s", BuildMLPrompt(batches[0]))
	}
	if !strings.Contains(BuildMLPrompt(batches[1]), "iostat-write-latency-nvme11n1") {
		t.Fatalf("第二批 prompt 应包含范围内 finding:\n%s", BuildMLPrompt(batches[1]))
	}
}

func TestDiagnoseMLRunsSequentialBatchesThenSummary(t *testing.T) {
	var rows []string
	rows = append(rows, "timestamp,device,write_await")
	for i := 1; i <= defaultMLBatchRows+1; i++ {
		rows = append(rows, "2026-04-24 15:41:51,sda,1.00")
	}

	runner := &captureRunner{output: `{"summary":"batch ok","incidents":[]}`}
	service := NewService(runner)
	result := service.DiagnoseML(context.Background(), Options{
		Enabled:     true,
		ModelPath:   createFakeBinary(t, DefaultModelName()),
		RuntimePath: createFakeBinary(t, "llama-cli"),
	}, MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-24 15:41:51",
		EndTime:   "2026-04-24 15:42:01",
		Sections: []MLSection{{
			ID:        "ml-iostat-data",
			Module:    "iostat",
			Format:    "iostat_csv",
			FilePath:  "iostat.csv",
			TotalRows: defaultMLBatchRows + 1,
			Data:      strings.Join(rows, "\n"),
		}},
	})
	if result.Status != diagnosis.AIStatusActive {
		t.Fatalf("期望 active, got=%s reason=%s", result.Status, result.FallbackReason)
	}
	if len(runner.requests) != 3 {
		t.Fatalf("期望 2 个数据批次 + 1 个汇总请求, got=%d", len(runner.requests))
	}
	if !strings.Contains(runner.requests[0].Prompt, "row_range: 1-80/81") {
		t.Fatalf("第一个 batch 范围错误:\n%s", runner.requests[0].Prompt)
	}
	if !strings.Contains(runner.requests[1].Prompt, "row_range: 81-81/81") {
		t.Fatalf("第二个 batch 范围错误:\n%s", runner.requests[1].Prompt)
	}
	if !strings.Contains(runner.requests[2].Prompt, "批次结果") {
		t.Fatalf("最后一次请求应为汇总 prompt:\n%s", runner.requests[2].Prompt)
	}
}

func TestDiagnoseMLCombinesBatchResultsWhenSummaryFails(t *testing.T) {
	var rows []string
	rows = append(rows, "timestamp,device,write_await")
	for i := 1; i <= defaultMLBatchRows+1; i++ {
		rows = append(rows, "2026-04-24 15:41:51,sda,1.00")
	}

	runner := &sequenceRunner{outputs: []string{
		`{"summary":"first batch","incidents":[{"classification":"写延迟异常","severity":"warning","confidence":0.9,"evidence_ids":["ml-iostat-data","iostat-write-latency-sda"],"next_checks":["检查慢盘"]}]}`,
		`{"summary":"second batch","incidents":[]}`,
		`not json`,
	}}
	service := NewService(runner)
	result := service.DiagnoseML(context.Background(), Options{
		Enabled:     true,
		ModelPath:   createFakeBinary(t, DefaultModelName()),
		RuntimePath: createFakeBinary(t, "llama-cli"),
	}, MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-24 15:41:51",
		EndTime:   "2026-04-24 15:42:01",
		Findings: []findings.Finding{{
			RuleID: "iostat-write-latency-sda",
			Source: "iostat",
			Time:   "2026-04-24 15:41:51",
		}},
		Sections: []MLSection{{
			ID:        "ml-iostat-data",
			Module:    "iostat",
			Format:    "iostat_csv",
			FilePath:  "iostat.csv",
			TotalRows: defaultMLBatchRows + 1,
			Data:      strings.Join(rows, "\n"),
		}},
	})

	if result.Status != diagnosis.AIStatusActive {
		t.Fatalf("summary 失败后应合并已完成批次并保持 active, got=%s reason=%s", result.Status, result.FallbackReason)
	}
	if len(runner.requests) != 3 {
		t.Fatalf("期望 2 个数据批次 + 1 个失败汇总请求, got=%d", len(runner.requests))
	}
	if !strings.Contains(result.Summary, "first batch") || !strings.Contains(result.Summary, "second batch") {
		t.Fatalf("合并结果应保留批次 summary, got=%s", result.Summary)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Classification != "写延迟异常" {
		t.Fatalf("合并结果应保留批次 incident, got=%+v", result.Incidents)
	}
}

func TestDiagnoseMLValidatesEvidenceIDsPerBatch(t *testing.T) {
	var rows []string
	rows = append(rows, "timestamp,device,write_await")
	for i := 1; i <= defaultMLBatchRows; i++ {
		rows = append(rows, "2026-04-24 15:41:51,sda,1.00")
	}
	rows = append(rows, "2026-04-24 15:42:01,nvme11n1,300.00")

	runner := &sequenceRunner{outputs: []string{
		`{"summary":"first batch","incidents":[{"classification":"写延迟异常","severity":"critical","confidence":0.9,"evidence_ids":["ml-iostat-data","iostat-write-latency-nvme11n1"],"next_checks":["检查慢盘"]}]}`,
		`{"summary":"second batch","incidents":[]}`,
		`{"summary":"summary ok","incidents":[]}`,
	}}
	service := NewService(runner)
	result := service.DiagnoseML(context.Background(), Options{
		Enabled:     true,
		ModelPath:   createFakeBinary(t, DefaultModelName()),
		RuntimePath: createFakeBinary(t, "llama-cli"),
	}, MLPromptInput{
		Hostname:  "rdsmaster1",
		StartTime: "2026-04-24 15:41:51",
		EndTime:   "2026-04-24 15:42:01",
		Findings: []findings.Finding{{
			RuleID: "iostat-write-latency-nvme11n1",
			Source: "iostat",
			Time:   "2026-04-24 15:42:01",
		}},
		Sections: []MLSection{{
			ID:        "ml-iostat-data",
			Module:    "iostat",
			Format:    "iostat_csv",
			FilePath:  "iostat.csv",
			TotalRows: defaultMLBatchRows + 1,
			Data:      strings.Join(rows, "\n"),
		}},
	})

	if result.Status != diagnosis.AIStatusActive {
		t.Fatalf("期望汇总仍成功, got=%s reason=%s", result.Status, result.FallbackReason)
	}
	if len(runner.requests) != 3 {
		t.Fatalf("期望 2 个 batch + 1 个 summary 请求, got=%d", len(runner.requests))
	}
	summaryPrompt := runner.requests[2].Prompt
	if strings.Contains(summaryPrompt, `"evidence_ids":[`) || strings.Contains(summaryPrompt, `"evidence_ids": [`) {
		t.Fatalf("第一批范围外 finding 引用不应进入汇总 prompt:\n%s", summaryPrompt)
	}
}

func TestServiceUsesDefault32768ContextSize(t *testing.T) {
	runner := &captureRunner{output: `{"summary":"ok","incidents":[]}`}
	service := NewService(runner)
	result := service.Diagnose(context.Background(), Options{
		Enabled:     true,
		ModelPath:   createFakeBinary(t, DefaultModelName()),
		RuntimePath: createFakeBinary(t, "llama-cli"),
	}, diagnosis.Context{
		Hostname: "rdsmaster1",
		Evidence: []diagnosis.Evidence{{
			ID:      "iostat-write-latency",
			Source:  "iostat",
			Summary: "写延迟偏高",
		}},
	})

	if result.Status != diagnosis.AIStatusActive {
		t.Fatalf("期望 active, got=%s reason=%s", result.Status, result.FallbackReason)
	}
	if len(runner.requests) != 1 {
		t.Fatalf("期望 1 次 runtime 请求, got=%d", len(runner.requests))
	}
	if runner.requests[0].ContextSize != 32768 {
		t.Fatalf("默认 ctx-size 应为 32768, got=%d", runner.requests[0].ContextSize)
	}
}

func TestServiceDoesNotPrintDebugByDefault(t *testing.T) {
	runner := &captureRunner{output: `{"summary":"ok","incidents":[]}`}
	service := NewService(runner)

	stderr := captureStderr(t, func() {
		result := service.DiagnoseML(context.Background(), Options{
			Enabled:     true,
			ModelPath:   createFakeBinary(t, DefaultModelName()),
			RuntimePath: createFakeBinary(t, "llama-cli"),
		}, MLPromptInput{
			Hostname:  "rdsmaster1",
			StartTime: "2026-04-24 15:41:51",
			EndTime:   "2026-04-24 15:42:01",
			Sections: []MLSection{{
				ID:        "ml-iostat-data",
				Module:    "iostat",
				Format:    "iostat_csv",
				TotalRows: 1,
				Data:      "timestamp,device,write_await\n2026-04-24 15:41:51,sda,1.00",
			}},
		})
		if result.Status != diagnosis.AIStatusActive {
			t.Fatalf("期望 active, got=%s reason=%s", result.Status, result.FallbackReason)
		}
	})

	for _, forbidden := range []string{"AI 调试", "Prompt BEGIN", "Data BEGIN", "runtime 请求"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("默认不应打印 AI 调试内容 %q:\n%s", forbidden, stderr)
		}
	}
	if len(runner.requests) != 1 || runner.requests[0].Debug {
		t.Fatalf("默认 runtime 请求不应开启 Debug, got=%+v", runner.requests)
	}
}

func TestServicePrintsDebugWhenEnabled(t *testing.T) {
	runner := &captureRunner{output: `{"summary":"ok","incidents":[]}`}
	service := NewService(runner)

	stderr := captureStderr(t, func() {
		result := service.DiagnoseML(context.Background(), Options{
			Enabled:     true,
			Debug:       true,
			ModelPath:   createFakeBinary(t, DefaultModelName()),
			RuntimePath: createFakeBinary(t, "llama-cli"),
		}, MLPromptInput{
			Hostname:  "rdsmaster1",
			StartTime: "2026-04-24 15:41:51",
			EndTime:   "2026-04-24 15:42:01",
			Sections: []MLSection{{
				ID:        "ml-iostat-data",
				Module:    "iostat",
				Format:    "iostat_csv",
				TotalRows: 1,
				Data:      "timestamp,device,write_await\n2026-04-24 15:41:51,sda,1.00",
			}},
		})
		if result.Status != diagnosis.AIStatusActive {
			t.Fatalf("期望 active, got=%s reason=%s", result.Status, result.FallbackReason)
		}
	})

	for _, want := range []string{"AI 调试", "Prompt BEGIN", "Data BEGIN", "runtime 请求"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("开启 Debug 后应打印 AI 调试内容 %q:\n%s", want, stderr)
		}
	}
	if len(runner.requests) != 1 || !runner.requests[0].Debug {
		t.Fatalf("开启 Debug 后 runtime 请求应携带 Debug, got=%+v", runner.requests)
	}
}

func TestDebugOutputUsesLoggingWriter(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("读取 service.go 失败: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "os.Stderr") {
		t.Fatalf("localai debug 输出不应直接依赖 os.Stderr")
	}
	if !strings.Contains(text, "logging.Default().Writer()") {
		t.Fatalf("localai debug 输出应通过 internal/logging writer")
	}
}

func TestServiceDiagnoseFallbackOnRunnerError(t *testing.T) {
	modelPath := createFakeBinary(t, "Qwen3-0.6B-Q8_0.gguf")
	runtimePath := createFakeBinary(t, "llama-cli")
	service := NewService(stubRunner{err: errors.New("boom")})
	result := service.Diagnose(context.Background(), Options{
		Enabled:     true,
		ModelPath:   modelPath,
		RuntimePath: runtimePath,
	}, diagnosis.Context{
		Evidence: []diagnosis.Evidence{{ID: "cross-io-contention"}},
	})

	if result.Status != diagnosis.AIStatusFallback {
		t.Fatalf("期望 fallback, got=%s", result.Status)
	}
}

func TestServiceDiagnoseFallbackContainsDownloadLinksWhenDepsMissing(t *testing.T) {
	service := NewService(stubRunner{})
	result := service.Diagnose(context.Background(), Options{
		Enabled:     true,
		ModelPath:   filepath.Join(t.TempDir(), "missing-model.gguf"),
		RuntimePath: filepath.Join(t.TempDir(), "missing-llama-cli"),
	}, diagnosis.Context{
		Evidence: []diagnosis.Evidence{{ID: "cross-io-contention"}},
	})

	if result.Status != diagnosis.AIStatusFallback {
		t.Fatalf("期望 fallback, got=%s", result.Status)
	}
	if !strings.Contains(result.FallbackReason, runtimeDownloadURL) {
		t.Fatalf("缺少 runtime 下载链接: %s", result.FallbackReason)
	}
	if !strings.Contains(result.FallbackReason, modelDownloadURL) {
		t.Fatalf("缺少 model 下载链接: %s", result.FallbackReason)
	}
}

func TestResolveModelPathAcceptsBareRelativeFilename(t *testing.T) {
	workdir := t.TempDir()
	modelName := "Qwen3-0.6B-Q8_0.gguf"
	modelPath := filepath.Join(workdir, modelName)
	if err := os.WriteFile(modelPath, []byte("stub"), 0o644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换目录失败: %v", err)
	}

	resolved, err := resolveModelPath(modelName)
	if err != nil {
		t.Fatalf("resolveModelPath 返回错误: %v", err)
	}
	if resolved != modelName {
		t.Fatalf("期望返回本地相对文件名, got=%s", resolved)
	}
}

func TestResolveRuntimePathAcceptsBareRelativeFilename(t *testing.T) {
	workdir := t.TempDir()
	runtimeName := "llama-cli"
	runtimePath := filepath.Join(workdir, runtimeName)
	if err := os.WriteFile(runtimePath, []byte("stub"), 0o755); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前目录失败: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldwd)
	}()
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("切换目录失败: %v", err)
	}

	resolved, err := resolveRuntimePath(runtimeName)
	if err != nil {
		t.Fatalf("resolveRuntimePath 返回错误: %v", err)
	}
	if resolved != runtimeName {
		t.Fatalf("期望返回本地相对文件名, got=%s", resolved)
	}
}

func TestCompletionRuntimePathUsesSiblingCompletionForLlamaCLI(t *testing.T) {
	workdir := t.TempDir()
	cliPath := filepath.Join(workdir, "llama-cli")
	completionPath := filepath.Join(workdir, "llama-completion")
	if err := os.WriteFile(cliPath, []byte("stub"), 0o755); err != nil {
		t.Fatalf("创建 llama-cli 失败: %v", err)
	}
	if err := os.WriteFile(completionPath, []byte("stub"), 0o755); err != nil {
		t.Fatalf("创建 llama-completion 失败: %v", err)
	}

	if got := completionRuntimePath(cliPath); got != completionPath {
		t.Fatalf("期望使用 sibling llama-completion, got=%s", got)
	}
}

func TestCLIRunnerFallsBackToCPUWhenAcceleratedRunFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test is Unix-only")
	}

	workdir := t.TempDir()
	runtimePath := filepath.Join(workdir, "fake-llama")
	callsPath := filepath.Join(workdir, "calls.txt")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--list-devices\" ]; then printf 'Available devices:\\n  Metal: Fake GPU (8192 MiB)\\n'; exit 0; fi\n" +
		"printf '%s\\n' \"$*\" >> " + shellQuote(callsPath) + "\n" +
		"case \"$*\" in\n" +
		"  *'--device none'*'-ngl 0'*) printf '{\"summary\":\"cpu ok\",\"incidents\":[]}' ; exit 0 ;;\n" +
		"  *) echo 'gpu failed' >&2 ; exit 3 ;;\n" +
		"esac\n"
	if err := os.WriteFile(runtimePath, []byte(script), 0o755); err != nil {
		t.Fatalf("创建 fake runtime 失败: %v", err)
	}

	output, err := (CLIRunner{}).Run(context.Background(), Request{
		RuntimePath: runtimePath,
		ModelPath:   "model.gguf",
		Prompt:      "prompt",
		MaxTokens:   16,
		ContextSize: 256,
	})
	if err != nil {
		t.Fatalf("期望 CPU fallback 成功, got err=%v", err)
	}
	if !strings.Contains(output, "cpu ok") {
		t.Fatalf("期望返回 CPU fallback 输出, got=%s", output)
	}

	callsRaw, err := os.ReadFile(callsPath)
	if err != nil {
		t.Fatalf("读取调用记录失败: %v", err)
	}
	calls := strings.Split(strings.TrimSpace(string(callsRaw)), "\n")
	if len(calls) != 2 {
		t.Fatalf("期望先尝试 GPU 再 fallback CPU，共 2 次调用, got=%d: %q", len(calls), callsRaw)
	}
	if strings.Contains(calls[0], "--device none") || strings.Contains(calls[0], "-ngl 0") {
		t.Fatalf("首次调用不应强制 CPU: %s", calls[0])
	}
	if !strings.Contains(calls[1], "--device none") || !strings.Contains(calls[1], "-ngl 0") ||
		!strings.Contains(calls[1], "--no-op-offload") || !strings.Contains(calls[1], "--no-kv-offload") ||
		!strings.Contains(calls[1], "--fit off") {
		t.Fatalf("第二次调用应强制 CPU: %s", calls[1])
	}
}

func TestCLIRunnerDoesNotUseCPUFallbackWhenAcceleratedRunSucceeds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test is Unix-only")
	}

	workdir := t.TempDir()
	runtimePath := filepath.Join(workdir, "fake-llama")
	callsPath := filepath.Join(workdir, "calls.txt")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--list-devices\" ]; then printf 'Available devices:\\n  Metal: Fake GPU (8192 MiB)\\n'; exit 0; fi\n" +
		"printf '%s\\n' \"$*\" >> " + shellQuote(callsPath) + "\n" +
		"printf '{\"summary\":\"accelerated ok\",\"incidents\":[]}'\n"
	if err := os.WriteFile(runtimePath, []byte(script), 0o755); err != nil {
		t.Fatalf("创建 fake runtime 失败: %v", err)
	}

	output, err := (CLIRunner{}).Run(context.Background(), Request{
		RuntimePath: runtimePath,
		ModelPath:   "model.gguf",
		Prompt:      "prompt",
		MaxTokens:   16,
		ContextSize: 256,
	})
	if err != nil {
		t.Fatalf("期望 accelerated 调用成功, got err=%v", err)
	}
	if !strings.Contains(output, "accelerated ok") {
		t.Fatalf("期望返回 accelerated 输出, got=%s", output)
	}

	callsRaw, err := os.ReadFile(callsPath)
	if err != nil {
		t.Fatalf("读取调用记录失败: %v", err)
	}
	calls := strings.Split(strings.TrimSpace(string(callsRaw)), "\n")
	if len(calls) != 1 {
		t.Fatalf("accelerated 成功时不应 fallback, got calls=%d: %q", len(calls), callsRaw)
	}
	if strings.Contains(calls[0], "--device none") || strings.Contains(calls[0], "-ngl 0") {
		t.Fatalf("accelerated 调用不应强制 CPU: %s", calls[0])
	}
}

func TestCLIRunnerUsesCPUWhenNoGPUDeviceDetected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test is Unix-only")
	}

	workdir := t.TempDir()
	runtimePath := filepath.Join(workdir, "fake-llama")
	callsPath := filepath.Join(workdir, "calls.txt")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--list-devices\" ]; then printf 'Available devices:\\n  BLAS: Accelerate\\n'; exit 0; fi\n" +
		"printf '%s\\n' \"$*\" >> " + shellQuote(callsPath) + "\n" +
		"printf '{\"summary\":\"cpu ok\",\"incidents\":[]}'\n"
	if err := os.WriteFile(runtimePath, []byte(script), 0o755); err != nil {
		t.Fatalf("创建 fake runtime 失败: %v", err)
	}

	output, err := (CLIRunner{}).Run(context.Background(), Request{
		RuntimePath: runtimePath,
		ModelPath:   "model.gguf",
		Prompt:      "prompt",
		MaxTokens:   16,
		ContextSize: 256,
	})
	if err != nil {
		t.Fatalf("期望 CPU 调用成功, got err=%v", err)
	}
	if !strings.Contains(output, "cpu ok") {
		t.Fatalf("期望返回 CPU 输出, got=%s", output)
	}

	callsRaw, err := os.ReadFile(callsPath)
	if err != nil {
		t.Fatalf("读取调用记录失败: %v", err)
	}
	calls := strings.Split(strings.TrimSpace(string(callsRaw)), "\n")
	if len(calls) != 1 {
		t.Fatalf("未检测到 GPU 时应只调用 CPU 一次, got=%d: %q", len(calls), callsRaw)
	}
	if !strings.Contains(calls[0], "--device none") || !strings.Contains(calls[0], "-ngl 0") ||
		!strings.Contains(calls[0], "--no-op-offload") || !strings.Contains(calls[0], "--no-kv-offload") ||
		!strings.Contains(calls[0], "--fit off") {
		t.Fatalf("未检测到 GPU 时应强制 CPU: %s", calls[0])
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func TestServiceDiagnoseActiveWithExplicitPaths(t *testing.T) {
	modelPath := createFakeBinary(t, "Qwen3-0.6B-Q8_0.gguf")
	runtimePath := createFakeBinary(t, "llama-cli")
	service := NewService(stubRunner{output: `{"summary":"高负载更像 I/O 争用","incidents":[{"classification":"I/O 争用","severity":"warning","confidence":0.82,"evidence_ids":["top-cpu-wait","iostat-read-latency-sda"],"next_checks":["检查慢盘"]}]}`})
	result := service.Diagnose(context.Background(), Options{
		Enabled:     true,
		ModelPath:   modelPath,
		RuntimePath: runtimePath,
	}, diagnosis.Context{
		Evidence: []diagnosis.Evidence{
			{ID: "top-cpu-wait"},
			{ID: "iostat-read-latency-sda"},
		},
	})

	if result.Status != diagnosis.AIStatusActive {
		t.Fatalf("期望 active, got=%s", result.Status)
	}
	if len(result.Incidents) != 1 {
		t.Fatalf("期望 1 条 incident, got=%d", len(result.Incidents))
	}
}
