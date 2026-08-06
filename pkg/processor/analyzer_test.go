package processor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"oswbb-analyse/pkg/findings"
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
	"strings"
	"testing"
	"time"
)

type timeRangeStub struct {
	start time.Time
	end   time.Time
}

func (s timeRangeStub) GetTimeRange() (time.Time, time.Time) {
	return s.start, s.end
}

func TestResolveTimeRangeDefault(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := timeRangeStub{start: start, end: end}

	gotStart, gotEnd, usedDefault, err := resolveTimeRange(log, "", "", loc)
	if err != nil {
		t.Fatalf("resolveTimeRange 返回错误: %v", err)
	}
	if !usedDefault {
		t.Fatalf("期望使用默认时间范围")
	}
	if !gotStart.Equal(start) || !gotEnd.Equal(end) {
		t.Fatalf("返回的时间范围不正确: got (%s, %s)", gotStart, gotEnd)
	}
}

func TestResolveTimeRangeRejectsSingleSidedRange(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	log := timeRangeStub{start: start, end: start.Add(2 * time.Hour)}

	if _, _, _, err := resolveTimeRange(log, "2024-09-10 08:00:00", "", loc); err == nil {
		t.Fatalf("只指定 start 时不应静默退回完整时间范围")
	}
	if _, _, _, err := resolveTimeRange(log, "", "2024-09-10 09:00:00", loc); err == nil {
		t.Fatalf("只指定 end 时不应静默退回完整时间范围")
	}
}

func TestAnalysisOutputFilenameIncludesSafeHostname(t *testing.T) {
	got := analysisOutputFilename("iostat", "rds/master 1", "csv")
	if !strings.HasPrefix(got, "iostat_rds_master_1_") || !strings.HasSuffix(got, ".csv") {
		t.Fatalf("输出文件名应包含安全化主机名和扩展名, got=%s", got)
	}
	if strings.Contains(got, "/") || strings.Contains(got, " ") {
		t.Fatalf("输出文件名不应包含路径分隔符或空格, got=%s", got)
	}
}

func TestAnalysisOutputFilenameKeepsLegacyPrefixWithoutHostname(t *testing.T) {
	got := analysisOutputFilename("meminfo", "", "json")
	if !strings.HasPrefix(got, "meminfo_") || !strings.HasSuffix(got, ".json") {
		t.Fatalf("缺少主机名时仍应保持 module_timestamp.ext 形式, got=%s", got)
	}
}

func TestResolveTimeRangeCustom(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := timeRangeStub{start: start, end: end}

	startStr := "2024-09-10 09:00:00"
	endStr := "2024-09-10 11:00:00"

	gotStart, gotEnd, usedDefault, err := resolveTimeRange(log, startStr, endStr, loc)
	if err != nil {
		t.Fatalf("resolveTimeRange 返回错误: %v", err)
	}
	if usedDefault {
		t.Fatalf("期望使用自定义时间范围")
	}

	wantStart, _ := time.ParseInLocation(TimeLayout, startStr, loc)
	wantEnd, _ := time.ParseInLocation(TimeLayout, endStr, loc)

	if !gotStart.Equal(wantStart) || !gotEnd.Equal(wantEnd) {
		t.Fatalf("返回的时间范围不正确: got (%s, %s)", gotStart, gotEnd)
	}
}

func TestResolveTimeRangeInvalid(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := timeRangeStub{start: start, end: end}

	if _, _, _, err := resolveTimeRange(log, "invalid", "2024-09-10 11:00:00", loc); err == nil {
		t.Fatalf("时间格式错误时应返回错误")
	}
}

func TestPrintTimeRangeNoticeWritesLogToStderr(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			printTimeRangeNotice("文件", true, start, end)
		})
	})

	if stdout != "" {
		t.Fatalf("时间范围提示不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "INFO 使用文件完整时间范围: 2024-09-10 08:00:00 到 2024-09-10 10:00:00") {
		t.Fatalf("时间范围提示应写入 stderr info: %q", stderr)
	}
}

func TestPrintMemInfoReportNoDataWritesLogToStderr(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := &meminfo.MemInfoLog{}

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			printMemInfoReport(log, start, end, TimeLayout)
		})
	})

	if stdout != "" {
		t.Fatalf("meminfo 无数据提示不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "INFO 指定时间范围内无 meminfo 数据") {
		t.Fatalf("meminfo 无数据提示应写入 stderr info: %q", stderr)
	}
}

func TestPrintMemInfoReportMissingMemTotalWritesLogToStderr(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	log := &meminfo.MemInfoLog{Data: []meminfo.MemStatData{{
		Timestamp: at,
		MemStats:  meminfo.MemStats{MemAvailable: 1024},
	}}}

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			printMemInfoReport(log, at, at, TimeLayout)
		})
	})

	if stdout != "" {
		t.Fatalf("meminfo 缺 MemTotal 提示不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "WARN meminfo 数据缺少 MemTotal 字段，无法生成报告") {
		t.Fatalf("meminfo 缺 MemTotal 提示应写入 stderr warn: %q", stderr)
	}
}

func TestPrintTopReportNoDataWritesLogToStderr(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := &top.TopLog{}

	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			printTopReport(log, start, end)
		})
	})

	if stdout != "" {
		t.Fatalf("top 无数据提示不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "INFO 指定时间范围内无 top 数据") {
		t.Fatalf("top 无数据提示应写入 stderr info: %q", stderr)
	}
}

func TestPrintReportTextFailureWritesLogToStderr(t *testing.T) {
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			if printReportText(nil) {
				t.Fatalf("nil report should not print successfully")
			}
		})
	})

	if stdout != "" {
		t.Fatalf("文本报告格式化失败不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "ERROR 生成文本报告失败: report 不能为空") {
		t.Fatalf("文本报告格式化失败应写入 stderr error: %q", stderr)
	}
}

func TestOutputFileExt(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   string
	}{
		{name: "html", format: "html", want: "html"},
		{name: "json", format: "json", want: "json"},
		{name: "csv", format: "csv", want: "csv"},
		{name: "ml maps to csv", format: "ml", want: "csv"},
		{name: "unknown maps to csv", format: "unknown", want: "csv"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := outputFileExt(tc.format); got != tc.want {
				t.Fatalf("outputFileExt(%q) = %q, want %q", tc.format, got, tc.want)
			}
		})
	}
}

func TestPrintFindingsSummaryLabelsCandidateClues(t *testing.T) {
	output := captureStdout(t, func() {
		printFindingsSummary([]findings.Finding{{
			RuleID:   "top-process-high-cpu",
			Source:   "top",
			Category: "process",
			Severity: findings.SeverityMedium,
			Title:    "高 CPU 进程线索",
			Summary:  "进程 CPU 使用率高，需要结合系统 CPU 压力判断。",
		}})
	})

	if !strings.Contains(output, "- [中][候选线索] 高 CPU 进程线索") {
		t.Fatalf("终端摘要应区分严重级别和结论性质:\n%s", output)
	}
}

func TestSortIOStatDataByTimestamp(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	t1 := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	t2 := t1.Add(10 * time.Minute)
	t3 := t1.Add(20 * time.Minute)

	data := []iostat.IOStatData{
		{Timestamp: t3},
		{Timestamp: t1},
		{Timestamp: t2},
	}

	sortIOStatDataByTimestamp(data)

	if !data[0].Timestamp.Equal(t1) || !data[1].Timestamp.Equal(t2) || !data[2].Timestamp.Equal(t3) {
		t.Fatalf("iostat 合并数据未按时间升序排序: got %v, %v, %v", data[0].Timestamp, data[1].Timestamp, data[2].Timestamp)
	}
}

func TestSortMemInfoDataByTimestamp(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	t1 := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	t2 := t1.Add(10 * time.Minute)
	t3 := t1.Add(20 * time.Minute)

	data := []meminfo.MemStatData{
		{Timestamp: t2},
		{Timestamp: t3},
		{Timestamp: t1},
	}

	sortMemInfoDataByTimestamp(data)

	if !data[0].Timestamp.Equal(t1) || !data[1].Timestamp.Equal(t2) || !data[2].Timestamp.Equal(t3) {
		t.Fatalf("meminfo 合并数据未按时间升序排序: got %v, %v, %v", data[0].Timestamp, data[1].Timestamp, data[2].Timestamp)
	}
}

func TestPrintIOStatReportShowsUnifiedFindingsSummary(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteAwait:     300.11,
			}},
		}},
	}

	output := captureStdout(t, func() {
		printIOStatReport(log, at, at)
	})

	for _, want := range []string{
		"=== 异常摘要 ===",
		"[高]",
		"nvme11n1 写延迟存在突增",
		"对象=nvme11n1",
		"write_await_ms",
		"300.11",
		"阈值=8.00",
		"2026-04-21 03:29:12",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("report 未包含统一 finding 摘要 %q:\n%s", want, output)
		}
	}
}

func TestPrintIOStatReportUsesStructuredTextShell(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteAwait:     300.11,
			}},
		}},
	}

	output := captureStdout(t, func() {
		printIOStatReport(log, at, at)
	})

	for _, want := range []string{
		"OSWbb Analyse Report - iostat",
		"📊 分析概览",
		"时间范围: 2026-04-21 03:29:12 ~ 2026-04-21 03:29:12",
		"设备总数: 1",
		"📋 设备列表",
		"📌 规则诊断摘要",
		"📋 活跃设备分析",
		"📈 延迟突增明细",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("iostat report missing structured shell %q:\n%s", want, output)
		}
	}
}

func TestPrintIOStatReportUsesInternalReportFormatter(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteAwait:     300.11,
			}},
		}},
	}

	output := captureStdout(t, func() {
		printIOStatReport(log, at, at)
	})

	for _, want := range []string{
		"发现的设备:",
		"- nvme11n1",
		"[高][候选线索] nvme11n1 写延迟存在突增",
		"对象=nvme11n1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("iostat report should be rendered from unified report object, missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "\n设备\nnvme11n1\n") {
		t.Fatalf("iostat console report should not duplicate the device list as a table:\n%s", output)
	}
	for _, forbidden := range []string{
		"采样点:",
		"诊断摘要:",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("iostat console report should not expose new structured-only summary %q:\n%s", forbidden, output)
		}
	}
}

func TestPrintIOStatReportUsesNeutralLatencySpikeDetails(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteAwait:     300.11,
			}},
		}},
	}

	output := captureStdout(t, func() {
		printIOStatReport(log, at, at)
	})

	for _, want := range []string{
		"=== 异常摘要 ===",
		"=== 延迟突增明细 ===",
		"突增: 1个候选点",
		"300.1ms @ 2026-04-21 03:29:12",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("iostat 报告未包含中性延迟突增明细 %q:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{
		"=== 延迟异常检测 ===",
		"  异常:",
		"未检测到明显的延迟异常",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("iostat 统计明细不应再输出旧异常定性 %q:\n%s", forbidden, output)
		}
	}
}

func TestPrintIOStatReportShowsDiscardThroughput(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:           "nvme0n1",
				DiscardReqPerSec: 50,
				DiscardKBPerSec:  200,
				AvgQueueSize:     1.2,
			}},
		}},
	}

	output := captureStdout(t, func() {
		printIOStatReport(log, at, at)
	})

	for _, want := range []string{
		"nvme0n1:",
		"IOPS: 最大=50.0",
		"吞吐量(KB/s):",
		"丢弃最大=200.0",
		"丢弃平均=200.0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("discard-only iostat 报告未包含 %q:\n%s", want, output)
		}
	}
}

func TestPrintTopReportShowsRepresentativeProcessCandidates(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       8.5,
			CpuIdle:     8,
			TaskRunning: 12,
			Processes: []top.ProcessStats{{
				PID:        19518,
				User:       "oracle",
				State:      "R",
				CPUPercent: 88.5,
				MemPercent: 3.2,
				ResKB:      131072,
				Command:    "oracle foreground worker",
			}},
		}},
	}

	output := captureStdout(t, func() {
		printTopReport(log, at, at)
	})

	for _, want := range []string{
		"[代表进程候选]",
		"19518/oracle/R/oracle foreground worker",
		"cpu=88.5%",
		"reason=high_cpu",
		"候选线索",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("top 报告未包含代表进程候选 %q:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{"异常进程", "根因进程"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("top 代表进程候选不应直接定性为 %q:\n%s", forbidden, output)
		}
	}
}

func TestPrintTopReportDoesNotEmitLegacyWarningLabels(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       16.0,
			CpuIdle:     5.0,
			CpuWait:     25.0,
			CpuSteal:    12.0,
			TaskRunning: 12,
		}},
	}

	output := captureStdout(t, func() {
		printTopReport(log, at, at)
	})

	if !strings.Contains(output, "=== 异常摘要 ===") {
		t.Fatalf("top 报告应通过 findings 输出异常摘要:\n%s", output)
	}
	if strings.Contains(output, "[警告]") {
		t.Fatalf("top 报告统计段不应再输出旧告警标签:\n%s", output)
	}
}

func TestPrintTopReportUsesInternalReportFormatter(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	log := &top.TopLog{
		Snapshots: []top.TopSnapshot{{
			Timestamp:   at,
			Load1:       8.5,
			Load5:       7.5,
			Load15:      6.5,
			CpuUser:     80,
			CpuSys:      10,
			CpuIdle:     8,
			TaskRunning: 12,
		}},
	}

	output := captureStdout(t, func() {
		printTopReport(log, at, at)
	})

	for _, want := range []string{
		"OSWbb Analyse Report - top",
		"📊 分析概览",
		"时间范围: 2026-06-13 10:00:00 ~ 2026-06-13 10:00:00",
		"采样数量: 1",
		"📌 规则诊断摘要",
		"📈 系统指标摘要",
		"[Load Average 负载]",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("top report missing unified formatter output %q:\n%s", want, output)
		}
	}
	if strings.Index(output, "📌 规则诊断摘要") > strings.Index(output, "📈 系统指标摘要") {
		t.Fatalf("top report should keep findings before system metrics:\n%s", output)
	}
}

func TestPrintMemInfoReportUsesInternalReportFormatter(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{{
			Timestamp: at,
			MemStats: meminfo.MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemAvailable: 96 * 1024 * 1024,
				SwapTotal:    8 * 1024 * 1024,
				SwapFree:     8 * 1024 * 1024,
				CommitLimit:  128 * 1024 * 1024,
				Committed:    64 * 1024 * 1024,
			},
		}},
	}

	output := captureStdout(t, func() {
		printMemInfoReport(log, at, at, TimeLayout)
	})

	for _, want := range []string{
		"OSWbb Analyse Report - meminfo",
		"📊 分析概览",
		"时间范围: 2026-04-23 05:04:03 ~ 2026-04-23 05:04:03",
		"采样数量: 1",
		"📌 规则诊断摘要",
		"📈 系统指标摘要",
		"[概览]",
		"⚠️  告警与趋势",
		"📋 详细指标",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("meminfo report missing unified formatter output %q:\n%s", want, output)
		}
	}
	if strings.Index(output, "📌 规则诊断摘要") > strings.Index(output, "📈 系统指标摘要") {
		t.Fatalf("meminfo report should keep findings before system metrics:\n%s", output)
	}
}

func TestPrintMemInfoReportUsesFallbackWhenMemAvailableMissing(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{
				Timestamp: at,
				MemStats: meminfo.MemStats{
					MemTotal:     128 * 1024 * 1024,
					MemFree:      4 * 1024 * 1024,
					Buffers:      2 * 1024 * 1024,
					Cached:       88 * 1024 * 1024,
					SReclaimable: 2 * 1024 * 1024,
				},
			},
			{
				Timestamp: at.Add(5 * time.Second),
				MemStats: meminfo.MemStats{
					MemTotal:     128 * 1024 * 1024,
					MemFree:      3 * 1024 * 1024,
					Buffers:      2 * 1024 * 1024,
					Cached:       89 * 1024 * 1024,
					SReclaimable: 2 * 1024 * 1024,
				},
			},
		},
	}

	output := captureStdout(t, func() {
		printMemInfoReport(log, at, at.Add(5*time.Second), TimeLayout)
	})

	for _, want := range []string{
		"- 可用内存: 75.0% (当前 96.00 GB / 总 128.00 GB)",
		"当前: 96.00 GB (75.0%)",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("meminfo 报告未使用有效可用内存 fallback %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "当前 0.00 GB") {
		t.Fatalf("meminfo 报告不应把缺失的 MemAvailable 当作 0:\n%s", output)
	}
}

func TestPrintMemInfoReportDoesNotTreatAvailableRiseAsAnomaly(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: at, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 40 * 1024 * 1024}},
			{Timestamp: at.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 100 * 1024 * 1024}},
		},
	}

	output := captureStdout(t, func() {
		printMemInfoReport(log, at, at.Add(5*time.Second), TimeLayout)
	})

	for _, forbidden := range []string{"骤升(单点)", "骤升(趋势)"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("MemAvailable 单纯骤升不应作为异常输出 %q:\n%s", forbidden, output)
		}
	}
	if !strings.Contains(output, "- 可用内存: 正常") || !strings.Contains(output, "突变: 无") {
		t.Fatalf("MemAvailable 单纯骤升应作为恢复后的正常状态输出:\n%s", output)
	}
}

func TestPrintMemInfoReportSuppressesHealthyAvailableDropAnomaly(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: at, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 100 * 1024 * 1024}},
			{Timestamp: at.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 95 * 1024 * 1024}},
		},
	}

	output := captureStdout(t, func() {
		printMemInfoReport(log, at, at.Add(5*time.Second), TimeLayout)
	})

	for _, forbidden := range []string{"骤降(单点)", "可用内存 (Available)\n   - 时间:"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("高可用状态下的 MemAvailable 下降不应列为异常 %q:\n%s", forbidden, output)
		}
	}
	if !strings.Contains(output, "- 可用内存: 正常") || !strings.Contains(output, "1. 可用内存 (Available)\n   - 无异常") {
		t.Fatalf("高可用下降应保持正常并且异常列表为空:\n%s", output)
	}
}

func TestPrintMemInfoReportKeepsPressuredAvailableDropAnomaly(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 23, 5, 4, 3, 0, loc)
	log := &meminfo.MemInfoLog{
		Data: []meminfo.MemStatData{
			{Timestamp: at, MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 100 * 1024 * 1024}},
			{Timestamp: at.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: 128 * 1024 * 1024, MemAvailable: 8 * 1024 * 1024}},
		},
	}

	output := captureStdout(t, func() {
		printMemInfoReport(log, at, at.Add(5*time.Second), TimeLayout)
	})

	for _, want := range []string{"- 可用内存: 严重", "突变: 骤降(单点)", "可用内存 (Available)\n   - 时间: 2026-04-23 05:04:08"} {
		if !strings.Contains(output, want) {
			t.Fatalf("低可用状态下的 MemAvailable 下降应保留异常 %q:\n%s", want, output)
		}
	}
}

func TestPrintMemInfoReportIncludesFindingBackedAnonGrowthInAnomalyList(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.June, 13, 10, 0, 0, 0, loc)
	memTotal := int64(128 * 1024 * 1024)
	baselineAnon := int64(8 * 1024 * 1024)
	data := []meminfo.MemStatData{
		{Timestamp: start, MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 96 * 1024 * 1024, AnonPages: baselineAnon}},
		{Timestamp: start.Add(5 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 94 * 1024 * 1024, AnonPages: baselineAnon + 128*1024}},
		{Timestamp: start.Add(10 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 92 * 1024 * 1024, AnonPages: baselineAnon + 256*1024}},
		{Timestamp: start.Add(15 * time.Second), MemStats: meminfo.MemStats{MemTotal: memTotal, MemAvailable: 90 * 1024 * 1024, AnonPages: baselineAnon + 512*1024}},
	}
	for i := 4; i < 44; i++ {
		data = append(data, meminfo.MemStatData{
			Timestamp: start.Add(time.Duration(i*5) * time.Second),
			MemStats: meminfo.MemStats{
				MemTotal:     memTotal,
				MemAvailable: 90 * 1024 * 1024,
				AnonPages:    baselineAnon + 512*1024,
			},
		})
	}
	log := &meminfo.MemInfoLog{
		Data: data,
	}

	end := data[len(data)-1].Timestamp
	output := captureStdout(t, func() {
		printMemInfoReport(log, start, end, TimeLayout)
	})

	if !strings.Contains(output, "匿名页持续增长") {
		t.Fatalf("测试样例应先触发 findings 摘要里的匿名页增长:\n%s", output)
	}
	if !strings.Contains(output, "- 匿名页: 当前正常，历史有匿名页增长；") {
		t.Fatalf("匿名页当前窗口正常但历史有 findings 时，趋势状态不应只写正常:\n%s", output)
	}
	for _, want := range []string{"2. 匿名页 (AnonPages)\n   - 时间: 2026-06-13 10:00:15", "类型: findings: 匿名页持续增长"} {
		if !strings.Contains(output, want) {
			t.Fatalf("匿名页 findings 应同步到异常点列表 %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "2. 匿名页 (AnonPages)\n   - 无异常") {
		t.Fatalf("摘要已有匿名页增长时，异常点列表不应写无异常:\n%s", output)
	}
}

func TestLogParseErrorsWritesToStderr(t *testing.T) {
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			logParseErrors([]error{errors.New("解析文件失败 bad.log: bad line")})
		})
	})

	if stdout != "" {
		t.Fatalf("解析错误日志不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "WARN 解析文件失败 bad.log: bad line") {
		t.Fatalf("解析错误日志应写入 stderr warning: %q", stderr)
	}
}

func TestAnalyzeMergedTopFilesLogsParseErrorsToStderr(t *testing.T) {
	path := t.TempDir() + "/bad-top.log"

	var stderr string
	var runErr error
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			runErr = AnalyzeMergedTopFiles([]string{path}, "", "", "report", time.FixedZone("CST", 8*3600))
		})
	})

	if runErr == nil {
		t.Fatalf("无有效 top 数据时应返回错误")
	}
	if strings.Contains(stdout, "解析文件失败") {
		t.Fatalf("top 解析错误日志不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "WARN 解析文件失败 "+path) {
		t.Fatalf("top 解析错误日志应写入 stderr warning: %q", stderr)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建 stdout pipe 失败: %v", err)
	}
	os.Stdout = writer

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 stdout writer 失败: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatalf("读取 stdout 失败: %v", err)
	}
	return buf.String()
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建 stderr pipe 失败: %v", err)
	}
	os.Stderr = writer

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 stderr writer 失败: %v", err)
	}
	os.Stderr = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatalf("读取 stderr 失败: %v", err)
	}
	return buf.String()
}
