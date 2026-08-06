package processor

import (
	"context"
	"encoding/json"
	"fmt"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
)

func useReportFormatterForExport(format string) bool {
	switch format {
	case "html", "csv", "ml":
		return true
	default:
		return false
	}
}

func writeReportExport(filename, format string, r *report.Report, sink internaloutput.OutputSink) error {
	outFormat := internaloutput.Format(format)
	if outFormat == "ml" {
		outFormat = internaloutput.FormatCSV
	}
	formatter, err := internaloutput.NewFormatter(outFormat)
	if err != nil {
		return err
	}
	data, err := formatter.Format(r)
	if err != nil {
		return err
	}
	if sink == nil {
		sink = internaloutput.FileSink{}
	}
	return sink.Write(context.Background(), internaloutput.OutputRequest{
		Format: outFormat,
		Data:   data,
		Path:   filename,
	})
}

func writeReportExportWithMessage(filename, module, format string, r *report.Report, sink internaloutput.OutputSink) error {
	if err := writeReportExport(filename, format, r, sink); err != nil {
		return err
	}
	if sink == nil {
		sink = internaloutput.FileSink{}
	}
	return sink.Write(context.Background(), internaloutput.OutputRequest{
		Format:   internaloutput.FormatText,
		Data:     []byte(reportExportMessage(module, format, filename)),
		ToStdout: true,
	})
}

func prepareHTMLExportReport(r *report.Report, dataType string, rawData interface{}, aiDiagnosis diagnosis.AIResult) error {
	if r.Metadata == nil {
		r.Metadata = map[string]string{}
	}
	data, err := json.Marshal(rawData)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}
	r.Metadata["html.data_type"] = dataType
	r.Metadata["html.raw_data"] = string(data)
	if aiDiagnosis.Enabled {
		r.Metadata["ai.enabled"] = "true"
		r.Metadata["ai.status"] = aiDiagnosis.Status
		r.Metadata["ai.summary"] = aiDiagnosis.Summary
		r.Metadata["ai.fallback_reason"] = aiDiagnosis.FallbackReason
	}
	return nil
}

func reportExportMessage(module, format, filename string) string {
	if format == "html" {
		return fmt.Sprintf("已生成交互式HTML报告: %s\n", filename)
	}
	return fmt.Sprintf("已将%s数据写入文件: %s\n", module, filename)
}
