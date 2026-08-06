package iostat

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDeviceStats_DMDevice(t *testing.T) {
	parser := &IOStatParser{}
	// Sample line mimicking iostat output for a dm device
	// Format: Device r/s w/s rkB/s wkB/s ... (15 fields + 1 device name = 16 fields)
	// Wait, the code says: numFields := len(fields) - 1. If numFields == 15, then len(fields) == 16.
	// dm-0 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00
	line := "dm-0 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00"

	device, err := parser.parseDeviceStats(line)
	if err != nil {
		t.Errorf("Expected to parse dm-0 device, but got error: %v", err)
	}

	if device.Device != "dm-0" {
		t.Errorf("Expected device name dm-0, got %s", device.Device)
	}
}

func TestParseDeviceStats_MDDevice(t *testing.T) {
	parser := &IOStatParser{}
	// Sample line mimicking iostat output for a md device
	line := "md0 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00"

	device, err := parser.parseDeviceStats(line)
	if err != nil {
		t.Fatalf("md0 RAID device should be parsed, got error: %v", err)
	}

	if device.Device != "md0" {
		t.Fatalf("Expected device name md0, got %s", device.Device)
	}
}

func TestParseDeviceStats_HeaderDrivenExtraFields(t *testing.T) {
	parser := &IOStatParser{}

	// 表头包含 f/s 和 f_await 等扩展列（22列数值）
	header := "Device r/s rkB/s rrqm/s %rrqm r_await rareq-sz w/s wkB/s wrqm/s %wrqm w_await wareq-sz d/s dkB/s drqm/s %drqm d_await dareq-sz f/s f_await aqu-sz %util"
	parser.parseDeviceHeader(header)

	// 设备行: 1个设备名 + 22个数值
	line := "nvme0n1 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22"
	device, err := parser.parseDeviceStats(line)
	if err != nil {
		t.Fatalf("header-driven 解析失败: %v", err)
	}

	if device.ReadReqPerSec != 1 || device.ReadKBPerSec != 2 || device.ReadMergePerSec != 3 {
		t.Fatalf("读侧字段映射不正确: %+v", device)
	}
	if device.WriteReqPerSec != 7 || device.WriteKBPerSec != 8 || device.WriteMergePerSec != 9 {
		t.Fatalf("写侧字段映射不正确: %+v", device)
	}
	if device.ReadMergePct != 4 || device.WriteMergePct != 10 {
		t.Fatalf("读写 merge 百分比字段映射不正确: %+v", device)
	}
	if device.ReadAwait != 5 || device.WriteAwait != 11 {
		t.Fatalf("读写 await 字段映射不正确: %+v", device)
	}
	if device.ReadReqSize != 6 || device.WriteReqSize != 12 {
		t.Fatalf("读写请求大小字段映射不正确: %+v", device)
	}
	if device.DiscardReqPerSec != 13 || device.DiscardKBPerSec != 14 ||
		device.DiscardMergePerSec != 15 || device.DiscardMergePct != 16 ||
		device.DiscardAwait != 17 || device.DiscardReqSize != 18 {
		t.Fatalf("discard 字段映射不正确: %+v", device)
	}
	if device.AvgQueueSize != 21 {
		t.Fatalf("aqu-sz 映射不正确, got %.2f", device.AvgQueueSize)
	}
	if device.Utilization != 22 {
		t.Fatalf("%%util 映射不正确, got %.2f", device.Utilization)
	}
	if device.AvgReqSize != nil {
		t.Fatalf("表头无 avgrq-sz 时应为 nil, got %+v", device.AvgReqSize)
	}
}

func TestParseFileBadTimestampDoesNotPollutePreviousSnapshot(t *testing.T) {
	content := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:04 CST 2026
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           1.00    0.00    1.00    0.00    0.00   98.00

Device r/s w/s rkB/s wkB/s r_await w_await aqu-sz
nvme0n1 0.00 1.00 0.00 4.00 0.00 0.20 0.00

zzz ***bad timestamp
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           1.00    0.00    1.00   99.00    0.00    0.00

Device r/s w/s rkB/s wkB/s r_await w_await aqu-sz
nvme11n1 0.00 41.00 0.00 277.00 0.00 300.11 1.00
`
	filename := filepath.Join(t.TempDir(), "iostat.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 iostat 文件失败: %v", err)
	}

	log, err := (&IOStatParser{}).ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	if len(log.Data) != 1 {
		t.Fatalf("坏时间戳后的数据不应生成或污染快照, got=%d snapshots: %+v", len(log.Data), log.Data)
	}

	got := log.Data[0]
	if got.Timestamp.Format("2006-01-02 15:04:05") != "2026-04-21 03:00:04" {
		t.Fatalf("正常快照时间戳不正确: %s", got.Timestamp.Format("2006-01-02 15:04:05"))
	}
	if got.CPU.IOWait != 0 || got.CPU.Idle != 98 {
		t.Fatalf("坏时间戳后的 CPU 行污染了正常快照: %+v", got.CPU)
	}
	if len(got.Devices) != 1 || got.Devices[0].Device != "nvme0n1" || got.Devices[0].WriteAwait != 0.20 {
		t.Fatalf("坏时间戳后的设备行污染了正常快照: %+v", got.Devices)
	}
}

func TestParseDeviceStatsHeaderDrivenAggregateAwaitAvgQueueFallback(t *testing.T) {
	parser := &IOStatParser{}
	parser.parseDeviceHeader("Device r/s w/s rkB/s wkB/s await avgqu-sz")

	device, err := parser.parseDeviceStats("nvme0n1 0 10 0 64 80 0.4")
	if err != nil {
		t.Fatalf("aggregate await/avgqu-sz 表头应可解析: %v", err)
	}
	if device.WriteReqPerSec != 10 || device.WriteAwait != 80 || device.AvgQueueSize != 0.4 {
		t.Fatalf("aggregate await/avgqu-sz fallback 映射不正确: %+v", device)
	}
}

func TestParseDeviceStatsHeaderDrivenMissingAwaitDoesNotInventLatency(t *testing.T) {
	parser := &IOStatParser{}
	parser.parseDeviceHeader("Device r/s w/s rkB/s wkB/s aqu-sz")

	device, err := parser.parseDeviceStats("nvme0n1 0 10 0 64 0.01")
	if err != nil {
		t.Fatalf("缺少 await 字段但有吞吐/队列字段时仍应解析基础 I/O: %v", err)
	}
	if device.WriteReqPerSec != 10 || device.WriteKBPerSec != 64 || device.AvgQueueSize != 0.01 {
		t.Fatalf("基础 I/O 字段映射不正确: %+v", device)
	}
	if device.ReadAwait != 0 || device.WriteAwait != 0 || device.DiscardAwait != 0 {
		t.Fatalf("缺少 await 字段时不应凭空生成延迟: %+v", device)
	}
}

func TestGetIOPSTrendIncludesDiscardRequests(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := IOStatLog{
		Data: []IOStatData{{
			Timestamp: start,
			Devices: []DeviceStats{{
				Device:           "nvme0n1",
				ReadReqPerSec:    0,
				WriteReqPerSec:   0,
				DiscardReqPerSec: 50,
			}},
		}},
	}

	got := log.GetIOPSTrend("nvme0n1", start, start)
	if len(got) != 1 {
		t.Fatalf("expected one IOPS point, got=%+v", got)
	}
	if got[0].Value != 50 {
		t.Fatalf("IOPS 应包含 discard 请求, got=%.2f", got[0].Value)
	}
}

func TestGetThroughputStatsIncludesDiscardThroughput(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := IOStatLog{
		Data: []IOStatData{
			{
				Timestamp: start,
				Devices: []DeviceStats{{
					Device:          "nvme0n1",
					ReadKBPerSec:    10,
					WriteKBPerSec:   20,
					DiscardKBPerSec: 200,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				Devices: []DeviceStats{{
					Device:          "nvme0n1",
					ReadKBPerSec:    30,
					WriteKBPerSec:   40,
					DiscardKBPerSec: 400,
				}},
			},
		},
	}

	readMax, writeMax, discardMax, readAvg, writeAvg, discardAvg := log.GetThroughputStats("nvme0n1", start, start.Add(5*time.Second))
	if readMax != 30 || writeMax != 40 || discardMax != 400 {
		t.Fatalf("吞吐最大值不正确: read=%.1f write=%.1f discard=%.1f", readMax, writeMax, discardMax)
	}
	if readAvg != 20 || writeAvg != 30 || discardAvg != 300 {
		t.Fatalf("吞吐平均值不正确: read=%.1f write=%.1f discard=%.1f", readAvg, writeAvg, discardAvg)
	}
}

func TestGetWriteLatencyStatsDetectsSingleSpikeWhenMADIsZero(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 2, 0, loc)
	values := []float64{0, 0, 0, 0, 300.11, 0, 0}
	log := IOStatLog{}
	for i, value := range values {
		log.Data = append(log.Data, IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			Devices: []DeviceStats{
				{
					Device:         "nvme11n1",
					WriteReqPerSec: 41,
					WriteAwait:     value,
				},
			},
		})
	}

	stats := log.GetWriteLatencyStats("nvme11n1", log.Data[0].Timestamp, log.Data[len(log.Data)-1].Timestamp)
	if len(stats.Anomalies) == 0 {
		t.Fatalf("expected single high w_await spike to be detected, stats=%+v", stats)
	}
	if got := stats.Anomalies[0].Value; got != 300.11 {
		t.Fatalf("expected anomaly value 300.11, got %.2f", got)
	}
}

func TestGetWriteLatencyStatsDetectsAbsoluteHighLatencyWithSingleSample(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := IOStatLog{
		Data: []IOStatData{{
			Timestamp: start,
			Devices: []DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 41,
				WriteAwait:     300.11,
			}},
		}},
	}

	stats := log.GetWriteLatencyStats("nvme11n1", start, start)
	if len(stats.Anomalies) == 0 {
		t.Fatalf("expected absolute high w_await to be detected with one sample, stats=%+v", stats)
	}
	if got := stats.Anomalies[0].Method; got != "threshold" {
		t.Fatalf("expected threshold method, got %q", got)
	}
}
