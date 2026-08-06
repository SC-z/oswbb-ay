package output

import (
	"encoding/json"
	"os"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/findings"
	"path/filepath"
	"testing"
)

func TestJSONFormatterWritesMemInfoFile(t *testing.T) {
	formatter := NewJSONFormatter()
	filename := filepath.Join(t.TempDir(), "meminfo_test.json")

	input := []MemInfoRawMetrics{
		{
			Timestamp:    "2024-09-10 08:00:00",
			MemTotal:     1024,
			MemAvailable: 512,
		},
	}

	if err := formatter.OutputMemInfoData(MemInfoExport{
		Data: input,
		AIDiagnosis: diagnosis.AIResult{
			Enabled: true,
			Status:  diagnosis.AIStatusFallback,
		},
	}, filename); err != nil {
		t.Fatalf("OutputMemInfoData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取JSON文件失败: %v", err)
	}

	var got struct {
		Data        []MemInfoRawMetrics `json:"data"`
		AIDiagnosis diagnosis.AIResult  `json:"ai_diagnosis"`
	}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("JSON内容无法解析: %v", err)
	}

	if len(got.Data) != 1 || got.Data[0].Timestamp != input[0].Timestamp {
		t.Fatalf("写入JSON内容不符合预期: got=%v", got)
	}
	if got.AIDiagnosis.Status != diagnosis.AIStatusFallback {
		t.Fatalf("AI 诊断字段未写入: got=%+v", got.AIDiagnosis)
	}
}

func TestJSONFormatterWritesIOStatFindings(t *testing.T) {
	formatter := NewJSONFormatter()
	filename := filepath.Join(t.TempDir(), "iostat_test.json")

	input := IOStatExport{
		Data: []IOStatRawMetrics{{
			Timestamp:  "2026-04-21 03:29:12",
			Device:     "nvme11n1",
			WriteAwait: 300.11,
		}},
		Findings: []findings.Finding{{
			RuleID:        "iostat-write-latency-nvme11n1",
			Source:        "iostat",
			Severity:      findings.SeverityHigh,
			Nature:        findings.FindingNatureCandidate,
			Target:        "nvme11n1",
			Metric:        "write_await_ms",
			Operator:      ">=",
			Threshold:     8,
			ObservedValue: 300.11,
			EvidenceRef:   "iostat:nvme11n1:write_await_ms:2026-04-21 03:29:12",
		}},
	}

	if err := formatter.OutputIOStatData(input, filename); err != nil {
		t.Fatalf("OutputIOStatData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取JSON文件失败: %v", err)
	}

	var got struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("JSON内容无法解析: %v", err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("expected one finding, got=%+v", got.Findings)
	}
	if got.Findings[0].RuleID != "iostat-write-latency-nvme11n1" {
		t.Fatalf("finding rule_id mismatch: got=%+v", got.Findings[0])
	}
	if got.Findings[0].Nature != findings.FindingNatureCandidate {
		t.Fatalf("finding nature mismatch: got=%+v", got.Findings[0])
	}
}
