package output

import "fmt"

// CreateFormatter 根据输出格式创建对应的格式化器
func CreateFormatter(format string) (OutputFormatter, error) {
	switch format {
	case "csv", "ml": // ml格式使用CSV输出
		return NewCSVFormatter(), nil
	case "json":
		return NewJSONFormatter(), nil
	default:
		return nil, fmt.Errorf("不支持的输出格式: %s", format)
	}
}
