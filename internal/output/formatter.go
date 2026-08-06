package output

import (
	"fmt"
	"oswbb-analyse/internal/report"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatHTML Format = "html"
	FormatCSV  Format = "csv"
)

type Formatter interface {
	Format(r *report.Report) ([]byte, error)
}

type TextFormatter struct{}

type JSONFormatter struct{}

type HTMLFormatter struct{}

type CSVFormatter struct {
	TableName string
}

func NewFormatter(format Format) (Formatter, error) {
	switch format {
	case FormatText:
		return TextFormatter{}, nil
	case FormatJSON:
		return JSONFormatter{}, nil
	case FormatHTML:
		return HTMLFormatter{}, nil
	case FormatCSV:
		return CSVFormatter{}, nil
	default:
		return nil, fmt.Errorf("不支持的输出格式: %s", format)
	}
}
