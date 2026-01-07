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

// OutputIOStatData 输出iostat数据为JSON格式
func (f *JSONFormatter) OutputIOStatData(data []IOStatRawMetrics, filename string) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("输出JSON格式失败: %v", err)
	}
	
	return nil
}

// OutputMemInfoData 输出meminfo数据为JSON格式

func (f *JSONFormatter) OutputMemInfoData(data []MemInfoRawMetrics, filename string) error {

	encoder := json.NewEncoder(os.Stdout)

	encoder.SetIndent("", "  ")

	

	if err := encoder.Encode(data); err != nil {

		return fmt.Errorf("输出JSON格式失败: %v", err)

	}

	

	return nil

}



// OutputTopData 输出top数据为JSON格式

func (f *JSONFormatter) OutputTopData(data []TopRawMetrics, filename string) error {

	encoder := json.NewEncoder(os.Stdout)

	encoder.SetIndent("", "  ")

	

	if err := encoder.Encode(data); err != nil {

		return fmt.Errorf("输出JSON格式失败: %v", err)

	}

	

	return nil

}
