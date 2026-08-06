package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// JSONFormatter JSON格式输出器
type JSONFormatter struct{}

// NewJSONFormatter 创建JSON输出器
//
// Deprecated: new code should use internal/output.JSONFormatter. This legacy
// formatter keeps the old JSON envelope for compatibility callers.
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func writeJSONFile(filename string, data interface{}, dataType string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建JSON文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("写入JSON格式失败: %v", err)
	}

	fmt.Printf("已将%s数据写入文件: %s\n", dataType, filename)
	return nil
}

type jsonEnvelope struct {
	DataType    string      `json:"data_type"`
	Data        interface{} `json:"data"`
	AIDiagnosis interface{} `json:"ai_diagnosis"`
	Findings    interface{} `json:"findings,omitempty"`
}

// OutputIOStatData 输出iostat数据为JSON格式
//
// Deprecated: new code should format internal/report.Report via internal/output.
func (f *JSONFormatter) OutputIOStatData(data IOStatExport, filename string) error {
	return writeJSONFile(filename, jsonEnvelope{
		DataType:    "iostat",
		Data:        data.Data,
		AIDiagnosis: data.AIDiagnosis,
		Findings:    data.Findings,
	}, "iostat")
}

// OutputMemInfoData 输出meminfo数据为JSON格式
//
// Deprecated: new code should format internal/report.Report via internal/output.
func (f *JSONFormatter) OutputMemInfoData(data MemInfoExport, filename string) error {
	return writeJSONFile(filename, jsonEnvelope{
		DataType:    "meminfo",
		Data:        data.Data,
		AIDiagnosis: data.AIDiagnosis,
		Findings:    data.Findings,
	}, "meminfo")
}

// OutputTopData 输出top数据为JSON格式
//
// Deprecated: new code should format internal/report.Report via internal/output.
func (f *JSONFormatter) OutputTopData(data TopExport, filename string) error {
	return writeJSONFile(filename, jsonEnvelope{
		DataType:    "top",
		Data:        data.Data,
		AIDiagnosis: data.AIDiagnosis,
		Findings:    data.Findings,
	}, "top")
}
