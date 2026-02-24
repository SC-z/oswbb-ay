package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// JSONFormatter JSON格式输出器
type JSONFormatter struct{}

// NewJSONFormatter 创建JSON输出器
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

// OutputIOStatData 输出iostat数据为JSON格式
func (f *JSONFormatter) OutputIOStatData(data []IOStatRawMetrics, filename string) error {
	return writeJSONFile(filename, data, "iostat")
}

// OutputMemInfoData 输出meminfo数据为JSON格式
func (f *JSONFormatter) OutputMemInfoData(data []MemInfoRawMetrics, filename string) error {
	return writeJSONFile(filename, data, "meminfo")
}

// OutputTopData 输出top数据为JSON格式
func (f *JSONFormatter) OutputTopData(data []TopRawMetrics, filename string) error {
	return writeJSONFile(filename, data, "top")
}
