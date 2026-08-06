package output

import (
	"encoding/csv"
	"strings"
	"testing"
)

func TestFormatIOStatCSVIncludesCPUAndDiscardFields(t *testing.T) {
	got, err := FormatIOStatCSV(IOStatExport{Data: []IOStatRawMetrics{{
		Timestamp:          "2026-04-21 03:29:12",
		Device:             "nvme0n1",
		ReadReqPerSec:      0,
		WriteReqPerSec:     0,
		ReadKBPerSec:       0,
		WriteKBPerSec:      0,
		ReadMergePerSec:    0,
		WriteMergePerSec:   0,
		ReadMergePct:       0,
		WriteMergePct:      0,
		ReadAwait:          0,
		WriteAwait:         0,
		ReadReqSize:        0,
		WriteReqSize:       0,
		AvgQueueSize:       1.2,
		DiscardReqPerSec:   50,
		DiscardKBPerSec:    200,
		DiscardMergePerSec: 3,
		DiscardMergePct:    6,
		DiscardAwait:       5,
		DiscardReqSize:     4,
		Utilization:        96.5,
		CPUIOWait:          25,
		CPUIdle:            60,
	}}})
	if err != nil {
		t.Fatalf("FormatIOStatCSV 返回错误: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(got)).ReadAll()
	if err != nil {
		t.Fatalf("CSV 无法解析: %v\n%s", err, got)
	}
	if len(records) != 2 {
		t.Fatalf("期望 header+1 row, got=%d: %v", len(records), records)
	}
	headerIndex := make(map[string]int)
	for index, name := range records[0] {
		headerIndex[name] = index
	}
	for _, name := range []string{
		"discard_req_per_sec",
		"discard_kb_per_sec",
		"discard_merge_per_sec",
		"discard_merge_pct",
		"discard_await",
		"discard_req_size",
		"cpu_iowait",
		"cpu_idle",
		"read_req_size",
		"write_req_size",
		"read_merge_pct",
		"write_merge_pct",
		"utilization",
	} {
		if _, ok := headerIndex[name]; !ok {
			t.Fatalf("iostat CSV 缺少字段 %q, header=%v", name, records[0])
		}
	}
	if records[1][headerIndex["discard_req_per_sec"]] != "50.00" ||
		records[1][headerIndex["discard_await"]] != "5.00" ||
		records[1][headerIndex["utilization"]] != "96.50" ||
		records[1][headerIndex["cpu_iowait"]] != "25.00" ||
		records[1][headerIndex["cpu_idle"]] != "60.00" {
		t.Fatalf("iostat CSV 未写出 discard/cpu 值, rows=%v", records)
	}
}

func TestFormatIOStatCSVKeepsInputRowOrder(t *testing.T) {
	got, err := FormatIOStatCSV(IOStatExport{Data: []IOStatRawMetrics{
		{Timestamp: "2026-04-21 03:00:00", Device: "sda", WriteAwait: 1},
		{Timestamp: "2026-04-21 03:00:00", Device: "nvme11n1", WriteAwait: 2},
		{Timestamp: "2026-04-21 03:00:05", Device: "sda", WriteAwait: 3},
		{Timestamp: "2026-04-21 03:00:05", Device: "nvme11n1", WriteAwait: 300},
	}})
	if err != nil {
		t.Fatalf("FormatIOStatCSV 返回错误: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(got)).ReadAll()
	if err != nil {
		t.Fatalf("CSV 无法解析: %v\n%s", err, got)
	}
	if len(records) != 5 {
		t.Fatalf("期望 header+4 row, got=%d: %v", len(records), records)
	}

	gotOrder := []string{
		records[1][0] + "/" + records[1][1],
		records[2][0] + "/" + records[2][1],
		records[3][0] + "/" + records[3][1],
		records[4][0] + "/" + records[4][1],
	}
	wantOrder := []string{
		"2026-04-21 03:00:00/sda",
		"2026-04-21 03:00:00/nvme11n1",
		"2026-04-21 03:00:05/sda",
		"2026-04-21 03:00:05/nvme11n1",
	}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("iostat CSV 应保持输入行顺序, got=%v want=%v", gotOrder, wantOrder)
		}
	}
}

func TestFormatMemInfoCSVIncludesSlabFields(t *testing.T) {
	got, err := FormatMemInfoCSV(MemInfoExport{Data: []MemInfoRawMetrics{
		{
			Timestamp:    "2026-04-23 05:04:03",
			MemTotal:     134217728,
			MemFree:      1048576,
			MemAvailable: 2097152,
			Slab:         3145728,
			SReclaimable: 1048576,
			SUnreclaim:   2097152,
			AnonPages:    4194304,
			Dirty:        262144,
			Writeback:    0,
			SwapTotal:    8388608,
			SwapFree:     4194304,
			CommitLimit:  10485760,
			Committed:    9437184,
		},
		{
			Timestamp:    "2026-04-23 05:04:08",
			MemTotal:     134217728,
			MemFree:      1048576,
			MemAvailable: 2097152,
			Slab:         3145728,
			SReclaimable: 1048576,
			SUnreclaim:   2097152,
			AnonPages:    4194304,
			Dirty:        524288,
			Writeback:    131072,
			SwapTotal:    8388608,
			SwapFree:     4194304,
			CommitLimit:  10485760,
			Committed:    9437184,
		},
	}})
	if err != nil {
		t.Fatalf("FormatMemInfoCSV 返回错误: %v", err)
	}

	for _, want := range []string{
		"slab",
		"3145728",
		"mem_available_pct",
		"mem_available_delta",
		"anon_pages_delta",
		"slab_delta",
		"s_unreclaim_delta",
		"dirty",
		"writeback",
		"dirty_pct",
		"writeback_pct",
		"dirty_delta",
		"writeback_delta",
		"262144",
		"131072",
		"swap_used_pct",
		"swap_free_delta",
		"commit_limit",
		"committed_as",
		"committed_pct",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("meminfo CSV 应包含 %q, got:\n%s", want, got)
		}
	}
}

func TestFormatMemInfoCSVUsesEffectiveAvailableForDerivedColumns(t *testing.T) {
	got, err := FormatMemInfoCSV(MemInfoExport{Data: []MemInfoRawMetrics{
		{
			Timestamp:    "2026-04-23 05:04:03",
			MemTotal:     128 * 1024 * 1024,
			MemFree:      4 * 1024 * 1024,
			MemAvailable: 0,
			Buffers:      2 * 1024 * 1024,
			Cached:       88 * 1024 * 1024,
			SReclaimable: 2 * 1024 * 1024,
		},
		{
			Timestamp:    "2026-04-23 05:04:08",
			MemTotal:     128 * 1024 * 1024,
			MemFree:      3 * 1024 * 1024,
			MemAvailable: 0,
			Buffers:      2 * 1024 * 1024,
			Cached:       89 * 1024 * 1024,
			SReclaimable: 2 * 1024 * 1024,
		},
	}})
	if err != nil {
		t.Fatalf("FormatMemInfoCSV 返回错误: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(got)).ReadAll()
	if err != nil {
		t.Fatalf("读取 CSV 失败: %v", err)
	}
	headerIndex := map[string]int{}
	for i, header := range records[0] {
		headerIndex[header] = i
	}
	if records[1][headerIndex["mem_available_pct"]] != "75.00" {
		t.Fatalf("mem_available_pct 应使用有效可用内存 fallback, rows=%v", records)
	}
	if records[2][headerIndex["mem_available_delta"]] != "0" {
		t.Fatalf("mem_available_delta 应使用有效可用内存 fallback, rows=%v", records)
	}
}
