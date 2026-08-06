package output

import (
	"fmt"
	"os"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/meminfo"
	"strconv"
)

// CSVFormatter CSV格式输出器。
//
// Deprecated: new code should use internal/output.CSVFormatter. This type is
// kept only for legacy OutputFormatter callers.
type CSVFormatter struct{}

// NewCSVFormatter 创建CSV输出器。
//
// Deprecated: new code should use internal/output.CSVFormatter.
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

// Deprecated: new code should use internal/output.CSVFormatter with a Report
// table. Kept for legacy AI CSV compatibility.
func FormatIOStatCSV(export IOStatExport) (string, error) {
	return formatCSVTable(IOStatRawMetricsTable(export.Data))
}

// Deprecated: new code should use internal/output.CSVFormatter with a Report
// table. Kept for legacy AI CSV compatibility.
func FormatMemInfoCSV(export MemInfoExport) (string, error) {
	return formatCSVTable(MemInfoRawMetricsTable(export.Data))
}

// Deprecated: new code should use internal/output.CSVFormatter with a Report
// table. Kept for legacy AI CSV compatibility.
func FormatTopCSV(export TopExport) (string, error) {
	return formatCSVTable(TopRawMetricsTable(export.Data))
}

// OutputIOStatData 输出iostat数据为CSV格式。
//
// Deprecated: new code should format internal/report.Report via internal/output.
func (f *CSVFormatter) OutputIOStatData(export IOStatExport, filename string) error {
	return writeCSVFile(filename, "iostat", IOStatRawMetricsTable(export.Data))
}

// OutputMemInfoData 输出meminfo数据为CSV格式。
//
// Deprecated: new code should format internal/report.Report via internal/output.
func (f *CSVFormatter) OutputMemInfoData(export MemInfoExport, filename string) error {
	return writeCSVFile(filename, "meminfo", MemInfoRawMetricsTable(export.Data))
}

// OutputTopData 输出top数据为CSV格式。
//
// Deprecated: new code should format internal/report.Report via internal/output.
func (f *CSVFormatter) OutputTopData(export TopExport, filename string) error {
	return writeCSVFile(filename, "top", TopRawMetricsTable(export.Data))
}

func formatCSVTable(table report.Table) (string, error) {
	data, err := internaloutput.CSVFormatter{}.Format(&report.Report{Tables: []report.Table{table}})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func writeCSVFile(filename, module string, table report.Table) error {
	data, err := internaloutput.CSVFormatter{}.Format(&report.Report{Tables: []report.Table{table}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	fmt.Printf("已将%s数据写入文件: %s\n", module, filename)
	return nil
}

// IOStatRawMetricsTable converts legacy iostat CSV rows into a report table.
//
// Deprecated: new code should populate report.Table in internal/modules/iostat.
func IOStatRawMetricsTable(data []IOStatRawMetrics) report.Table {
	rows := make([][]string, 0, len(data))
	for _, metrics := range data {
		avgReqSize := "NA"
		if metrics.AvgReqSize != nil {
			avgReqSize = formatFloat2(*metrics.AvgReqSize)
		}
		rows = append(rows, []string{
			metrics.Timestamp,
			metrics.Device,
			formatFloat2(metrics.ReadReqPerSec),
			formatFloat2(metrics.WriteReqPerSec),
			formatFloat2(metrics.ReadKBPerSec),
			formatFloat2(metrics.WriteKBPerSec),
			formatFloat2(metrics.ReadMergePerSec),
			formatFloat2(metrics.WriteMergePerSec),
			formatFloat2(metrics.ReadMergePct),
			formatFloat2(metrics.WriteMergePct),
			formatFloat2(metrics.ReadAwait),
			formatFloat2(metrics.WriteAwait),
			formatFloat2(metrics.AvgQueueSize),
			avgReqSize,
			formatFloat2(metrics.ReadReqSize),
			formatFloat2(metrics.WriteReqSize),
			formatFloat2(metrics.DiscardReqPerSec),
			formatFloat2(metrics.DiscardKBPerSec),
			formatFloat2(metrics.DiscardMergePerSec),
			formatFloat2(metrics.DiscardMergePct),
			formatFloat2(metrics.DiscardAwait),
			formatFloat2(metrics.DiscardReqSize),
			formatFloat2(metrics.CPUUser),
			formatFloat2(metrics.CPUNice),
			formatFloat2(metrics.CPUSystem),
			formatFloat2(metrics.CPUIOWait),
			formatFloat2(metrics.CPUSteal),
			formatFloat2(metrics.CPUIdle),
			formatFloat2(metrics.Utilization),
		})
	}
	return report.Table{Title: "iostat", Headers: ioStatCSVHeaders(), Rows: rows}
}

func ioStatCSVHeaders() []string {
	return []string{
		"timestamp",
		"device",
		"read_req_per_sec",
		"write_req_per_sec",
		"read_kb_per_sec",
		"write_kb_per_sec",
		"read_merge_per_sec",
		"write_merge_per_sec",
		"read_merge_pct",
		"write_merge_pct",
		"read_await",
		"write_await",
		"avg_queue_size",
		"avg_req_size",
		"read_req_size",
		"write_req_size",
		"discard_req_per_sec",
		"discard_kb_per_sec",
		"discard_merge_per_sec",
		"discard_merge_pct",
		"discard_await",
		"discard_req_size",
		"cpu_user",
		"cpu_nice",
		"cpu_system",
		"cpu_iowait",
		"cpu_steal",
		"cpu_idle",
		"utilization",
	}
}

// MemInfoRawMetricsTable converts legacy meminfo CSV rows into a report table.
//
// Deprecated: new code should populate report.Table in internal/modules/meminfo.
func MemInfoRawMetricsTable(data []MemInfoRawMetrics) report.Table {
	headers := []string{
		"timestamp",
		"mem_total",
		"mem_free",
		"mem_available",
		"buffers",
		"cached",
		"slab",
		"s_reclaimable",
		"s_unreclaim",
		"anon_pages",
		"dirty",
		"writeback",
		"swap_total",
		"swap_free",
		"commit_limit",
		"committed_as",
		"mem_available_pct",
		"swap_used_pct",
		"committed_pct",
		"slab_pct",
		"s_unreclaim_pct",
		"dirty_pct",
		"writeback_pct",
		"mem_available_delta",
		"anon_pages_delta",
		"slab_delta",
		"s_unreclaim_delta",
		"dirty_delta",
		"writeback_delta",
		"swap_free_delta",
	}

	rows := make([][]string, 0, len(data))
	for index, metrics := range data {
		var prev *MemInfoRawMetrics
		if index > 0 {
			prev = &data[index-1]
		}
		effectiveAvailable := effectiveMemAvailableMetric(metrics)
		rows = append(rows, []string{
			metrics.Timestamp,
			strconv.FormatInt(metrics.MemTotal, 10),
			strconv.FormatInt(metrics.MemFree, 10),
			strconv.FormatInt(metrics.MemAvailable, 10),
			strconv.FormatInt(metrics.Buffers, 10),
			strconv.FormatInt(metrics.Cached, 10),
			strconv.FormatInt(metrics.Slab, 10),
			strconv.FormatInt(metrics.SReclaimable, 10),
			strconv.FormatInt(metrics.SUnreclaim, 10),
			strconv.FormatInt(metrics.AnonPages, 10),
			strconv.FormatInt(metrics.Dirty, 10),
			strconv.FormatInt(metrics.Writeback, 10),
			strconv.FormatInt(metrics.SwapTotal, 10),
			strconv.FormatInt(metrics.SwapFree, 10),
			strconv.FormatInt(metrics.CommitLimit, 10),
			strconv.FormatInt(metrics.Committed, 10),
			formatPct(effectiveAvailable, metrics.MemTotal),
			formatSwapUsedPct(metrics.SwapFree, metrics.SwapTotal),
			formatPct(metrics.Committed, metrics.CommitLimit),
			formatPct(metrics.Slab, metrics.MemTotal),
			formatPct(metrics.SUnreclaim, metrics.MemTotal),
			formatPct(metrics.Dirty, metrics.MemTotal),
			formatPct(metrics.Writeback, metrics.MemTotal),
			formatDelta(effectiveAvailable, prevMemValue(prev, effectiveMemAvailableMetric), prev != nil),
			formatDelta(metrics.AnonPages, prevMemValue(prev, func(m MemInfoRawMetrics) int64 { return m.AnonPages }), prev != nil),
			formatDelta(metrics.Slab, prevMemValue(prev, func(m MemInfoRawMetrics) int64 { return m.Slab }), prev != nil),
			formatDelta(metrics.SUnreclaim, prevMemValue(prev, func(m MemInfoRawMetrics) int64 { return m.SUnreclaim }), prev != nil),
			formatDelta(metrics.Dirty, prevMemValue(prev, func(m MemInfoRawMetrics) int64 { return m.Dirty }), prev != nil),
			formatDelta(metrics.Writeback, prevMemValue(prev, func(m MemInfoRawMetrics) int64 { return m.Writeback }), prev != nil),
			formatDelta(metrics.SwapFree, prevMemValue(prev, func(m MemInfoRawMetrics) int64 { return m.SwapFree }), prev != nil),
		})
	}
	return report.Table{Title: "meminfo", Headers: headers, Rows: rows}
}

// TopRawMetricsTable converts legacy top CSV rows into a report table.
//
// Deprecated: new code should populate report.Table in internal/modules/top.
func TopRawMetricsTable(data []TopRawMetrics) report.Table {
	headers := []string{
		"timestamp",
		"load_1",
		"load_5",
		"load_15",
		"cpu_count",
		"load_1_per_cpu",
		"task_total",
		"task_running",
		"task_running_per_cpu",
		"task_sleeping",
		"task_stopped",
		"task_zombie",
		"cpu_user",
		"cpu_sys",
		"cpu_idle",
		"cpu_wait",
		"cpu_steal",
	}
	rows := make([][]string, 0, len(data))
	for _, metrics := range data {
		rows = append(rows, []string{
			metrics.Timestamp,
			formatFloat2(metrics.Load1),
			formatFloat2(metrics.Load5),
			formatFloat2(metrics.Load15),
			strconv.Itoa(metrics.CPUCount),
			strconv.FormatFloat(metrics.Load1PerCPU, 'f', 3, 64),
			strconv.Itoa(metrics.TaskTotal),
			strconv.Itoa(metrics.TaskRunning),
			strconv.FormatFloat(metrics.TaskRunningPerCPU, 'f', 3, 64),
			strconv.Itoa(metrics.TaskSleeping),
			strconv.Itoa(metrics.TaskStopped),
			strconv.Itoa(metrics.TaskZombie),
			strconv.FormatFloat(metrics.CpuUser, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuSys, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuIdle, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuWait, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuSteal, 'f', 1, 64),
		})
	}
	return report.Table{Title: "top", Headers: headers, Rows: rows}
}

func effectiveMemAvailableMetric(metrics MemInfoRawMetrics) int64 {
	return meminfo.EffectiveMemAvailableKB(meminfo.MemStats{
		MemTotal:     metrics.MemTotal,
		MemFree:      metrics.MemFree,
		MemAvailable: metrics.MemAvailable,
		Buffers:      metrics.Buffers,
		Cached:       metrics.Cached,
		SReclaimable: metrics.SReclaimable,
	})
}

func formatFloat2(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}

func formatPct(value, total int64) string {
	if total <= 0 {
		return "0.00"
	}
	return formatFloat2(float64(value) / float64(total) * 100)
}

func formatSwapUsedPct(free, total int64) string {
	if total <= 0 {
		return "0.00"
	}
	used := total - free
	if used < 0 {
		used = 0
	}
	return formatPct(used, total)
}

func formatDelta(current, previous int64, hasPrevious bool) string {
	if !hasPrevious {
		return "0"
	}
	return strconv.FormatInt(current-previous, 10)
}

func prevMemValue(prev *MemInfoRawMetrics, pick func(MemInfoRawMetrics) int64) int64 {
	if prev == nil {
		return 0
	}
	return pick(*prev)
}
