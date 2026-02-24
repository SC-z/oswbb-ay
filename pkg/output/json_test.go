package output

import (
	"encoding/json"
	"os"
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

	if err := formatter.OutputMemInfoData(input, filename); err != nil {
		t.Fatalf("OutputMemInfoData 返回错误: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("读取JSON文件失败: %v", err)
	}

	var got []MemInfoRawMetrics
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("JSON内容无法解析: %v", err)
	}

	if len(got) != 1 || got[0].Timestamp != input[0].Timestamp {
		t.Fatalf("写入JSON内容不符合预期: got=%v", got)
	}
}
