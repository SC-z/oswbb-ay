package output

import "fmt"

// CreateFormatter 根据输出格式创建对应的格式化器。
//
// Deprecated: new code should use internal/output.NewFormatter. This factory
// remains for legacy processor callers and the old JSON/HTML/AI CSV adapters.
func CreateFormatter(format string) (OutputFormatter, error) {
	switch format {
	case "csv", "ml": // ml格式使用CSV输出
		return NewCSVFormatter(), nil
	case "json":
		return NewJSONFormatter(), nil
	case "html":
		return NewHTMLFormatter(), nil
	default:
		return nil, fmt.Errorf("不支持的输出格式: %s", format)
	}
}
