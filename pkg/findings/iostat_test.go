package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oswbb-analyse/internal/config"
	"oswbb-analyse/pkg/iostat"
)

func TestBuildIOStatFindingsReportsSingleHighWriteLatency(t *testing.T) {
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

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("expected write latency finding, got=%+v", got)
	}
	if finding.Source != "iostat" {
		t.Fatalf("source mismatch: got=%q", finding.Source)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity mismatch: got=%q", finding.Severity)
	}
	if finding.Target != "nvme11n1" {
		t.Fatalf("target mismatch: got=%q", finding.Target)
	}
	if finding.Metric != "write_await_ms" {
		t.Fatalf("metric mismatch: got=%q", finding.Metric)
	}
	if finding.Operator != ">=" {
		t.Fatalf("operator mismatch: got=%q", finding.Operator)
	}
	if finding.Threshold != 8.0 {
		t.Fatalf("threshold mismatch: got=%.2f", finding.Threshold)
	}
	if finding.ObservedValue != 300.11 {
		t.Fatalf("observed value mismatch: got=%.2f", finding.ObservedValue)
	}
	if finding.Time != "2026-04-21 03:29:12" {
		t.Fatalf("time mismatch: got=%q", finding.Time)
	}
	if finding.EvidenceRef == "" {
		t.Fatalf("expected stable evidence ref, got empty")
	}
	if !strings.Contains(finding.Summary, "未见队列或 iowait 系统级压力") {
		t.Fatalf("单点高写延迟有 IOPS 证据但无队列/iowait 时，应说明系统级压力弱: %s", finding.Summary)
	}
	if finding.Metrics["latency_system_pressure"] != 0 {
		t.Fatalf("无队列/iowait 时不应标记系统级压力: %+v", finding.Metrics)
	}
	if finding.Nature != FindingNatureCandidate {
		t.Fatalf("无系统级压力的设备级慢请求应标记为候选线索, got=%q finding=%+v", finding.Nature, finding)
	}
}

func TestBuildIOStatFindingsLatencyPeakIOPSIncludesDiscard(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:           "nvme11n1",
				WriteReqPerSec:   1,
				DiscardReqPerSec: 50,
				WriteAwait:       300.11,
			}},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("expected write latency finding, got=%+v", got)
	}
	if finding.Metrics["write_iops_at_peak"] != 1 {
		t.Fatalf("write_iops_at_peak 不正确: %+v", finding.Metrics)
	}
	if value, ok := finding.Metrics["discard_iops_at_peak"]; !ok || value != 50 {
		t.Fatalf("应记录峰值时 discard IOPS, metrics=%+v", finding.Metrics)
	}
	if finding.Metrics["total_iops_at_peak"] != 51 {
		t.Fatalf("total_iops_at_peak 应包含 discard IOPS, metrics=%+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsReportsHighDiscardLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:           "nvme11n1",
				DiscardReqPerSec: 20,
				DiscardKBPerSec:  4096,
				DiscardAwait:     120,
			}},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-discard-latency-nvme11n1")
	if !ok {
		t.Fatalf("discard-only 高延迟应生成 discard latency finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("discard IOPS 明确且延迟高时应为 high, got=%q", finding.Severity)
	}
	if finding.Metric != "discard_await_ms" || finding.ObservedValue != 120 || finding.Threshold != 8 {
		t.Fatalf("discard latency finding 字段不完整: %+v", finding)
	}
	if finding.Metrics["discard_iops_at_peak"] != 20 || finding.Metrics["total_iops_at_peak"] != 20 {
		t.Fatalf("discard latency metrics 应记录 discard IOPS: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsDowngradesUpperLayerDuplicateDiscardLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{
				{Device: "nvme11n1", DiscardReqPerSec: 20, DiscardKBPerSec: 4096, DiscardAwait: 120},
				{Device: "dm-0", DiscardReqPerSec: 20, DiscardKBPerSec: 4096, DiscardAwait: 120},
			},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	physical, ok := findByRuleID(got, "iostat-discard-latency-nvme11n1")
	if !ok {
		t.Fatalf("expected physical discard latency finding, got=%+v", got)
	}
	if physical.Severity != SeverityHigh {
		t.Fatalf("底层物理盘 discard finding 应保持 high, got=%q", physical.Severity)
	}
	upper, ok := findByRuleID(got, "iostat-discard-latency-dm-0")
	if !ok {
		t.Fatalf("expected upper discard latency finding, got=%+v", got)
	}
	if upper.Severity != SeverityMedium {
		t.Fatalf("与底层盘同时间同方向重复的 dm discard finding 不应并列 high, got=%q", upper.Severity)
	}
	if upper.Metrics["stack_duplicate_with_physical"] != 1 {
		t.Fatalf("上层 discard 重复线索应标记 physical duplicate: %+v", upper.Metrics)
	}
}

func TestBuildIOStatFindingsUsesAggregateAwaitForActiveWriteOnly(t *testing.T) {
	content := strings.Join([]string{
		"Linux OSWbb v7.3.3",
		"zzz ***Tue Apr 21 03:29:12 CST 2026",
		"avg-cpu: %user %nice %system %iowait %steal %idle",
		"0.00 0.00 1.00 0.00 0.00 99.00",
		"Device r/s w/s rkB/s wkB/s await avgqu-sz",
		"nvme0n1 0 10 0 64 80 0.4",
		"",
	}, "\n")
	filename := filepath.Join(t.TempDir(), "legacy-iostat.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 iostat 文件失败: %v", err)
	}

	log, err := (&iostat.IOStatParser{}).ParseFile(filename)
	if err != nil {
		t.Fatalf("解析 legacy iostat 文件失败: %v", err)
	}
	start, end := log.GetTimeRange()
	got := BuildIOStatFindings(log, start, end)
	if _, ok := findByRuleID(got, "iostat-write-latency-nvme0n1"); !ok {
		t.Fatalf("aggregate await 应用于活跃写 I/O 后应生成写延迟 finding, got=%+v", got)
	}
	if finding, ok := findByRuleID(got, "iostat-read-latency-nvme0n1"); ok {
		t.Fatalf("无读 I/O 时 aggregate await 不应生成读延迟 finding: %+v", finding)
	}
}

func TestBuildIOStatFindingsIgnoresWriteAwaitWithoutWriteIO(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:        "nvme11n1",
					ReadReqPerSec: 100,
					WriteAwait:    300.11,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				Devices: []iostat.DeviceStats{{
					Device:          "nvme11n1",
					WriteReqPerSec:  5,
					WriteKBPerSec:   20,
					WriteAwait:      0.8,
					ReadReqPerSec:   0,
					ReadKBPerSec:    0,
					ReadAwait:       300.11,
					AvgQueueSize:    0.01,
					ReadMergePerSec: 0,
				}},
			},
		},
	}

	got := BuildIOStatFindings(log, start, start.Add(5*time.Second))
	if finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1"); ok {
		t.Fatalf("没有写请求的 w_await 不应生成写延迟 finding: %+v", finding)
	}
	if finding, ok := findByRuleID(got, "iostat-read-latency-nvme11n1"); ok {
		t.Fatalf("没有读请求的 r_await 不应生成读延迟 finding: %+v", finding)
	}
}

func TestBuildIOStatFindingsIgnoresAwaitAndQueueWhenDeviceHasNoIO(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:       "nvme11n1",
					ReadAwait:    300.11,
					WriteAwait:   300.11,
					AvgQueueSize: 2.5,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				Devices: []iostat.DeviceStats{{
					Device:       "nvme11n1",
					ReadAwait:    500,
					WriteAwait:   500,
					AvgQueueSize: 3.0,
				}},
			},
		},
	}

	got := BuildIOStatFindings(log, start, start.Add(5*time.Second))
	for _, ruleID := range []string{
		"iostat-read-latency-nvme11n1",
		"iostat-write-latency-nvme11n1",
		"iostat-queue-nvme11n1",
	} {
		if finding, ok := findByRuleID(got, ruleID); ok {
			t.Fatalf("设备无 I/O 时不应生成 %s: %+v", ruleID, finding)
		}
	}
}

func TestBuildIOStatFindingsDowngradesSingleLowIOPSHighWriteLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     300.11,
				AvgQueueSize:   0.01,
			}},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("低 IOPS 高写延迟仍应保留 finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("单点低 IOPS 高写延迟缺少 iowait/队列佐证时应降为 medium, got=%q", finding.Severity)
	}
	if finding.Metrics["write_iops_at_peak"] != 0.1 {
		t.Fatalf("应记录峰值延迟时的写 IOPS, metrics=%+v", finding.Metrics)
	}
	if finding.Metrics["active_sample_count"] != 1 || finding.Metrics["latency_corroborated"] != 0 {
		t.Fatalf("应记录 active 样本数和缺少佐证状态, metrics=%+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsDowngradesSingleOneIOPSHighWriteLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 1,
				WriteKBPerSec:  4,
				WriteAwait:     300.11,
				AvgQueueSize:   0.01,
			}},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("1 IOPS 高写延迟仍应保留 finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("1 IOPS 单点高写延迟缺少 iowait/队列佐证时应降为 medium, got=%q", finding.Severity)
	}
	if finding.Metrics["total_iops_at_peak"] != 1 || finding.Metrics["latency_corroborated"] != 0 {
		t.Fatalf("1 IOPS 单点慢请求不应被 IOPS 单独佐证: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsKeepsPersistentHighWriteLatencyAsHigh(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{}
	for i, await := range []float64{20, 25, 30} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 10,
				WriteKBPerSec:  40,
				WriteAwait:     await,
				AvgQueueSize:   0.01,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("持续高写延迟应生成 finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("持续高写延迟应保持 high, got=%q", finding.Severity)
	}
	if finding.ObservedValue != 30 {
		t.Fatalf("应指向最高写延迟样本, got=%.2f", finding.ObservedValue)
	}
	if finding.Metrics["active_sample_count"] != 3 || finding.Metrics["high_latency_sample_count"] != 3 {
		t.Fatalf("持续高延迟样本计数缺失: %+v", finding.Metrics)
	}
	if finding.Metrics["latency_corroborated"] != 1 {
		t.Fatalf("持续高延迟应视为有佐证: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Title, "持续偏高") || strings.Contains(finding.Title, "突增") {
		t.Fatalf("持续高写延迟不应被描述成突增: %s", finding.Title)
	}
}

func TestBuildIOStatFindingsCapsPersistentLowIOPSLatencyWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{}
	for i, await := range []float64{20, 25, 30} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     await,
				AvgQueueSize:   0.01,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("低 IOPS 多点慢请求仍应保留为排查线索, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("低 IOPS 且无队列/iowait 佐证的多点慢请求不应升为 high, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Metrics["latency_corroborated"] != 0 || finding.Metrics["latency_system_pressure"] != 0 {
		t.Fatalf("低 IOPS 无系统压力样本应记录缺少佐证: %+v", finding.Metrics)
	}
	if finding.Nature != FindingNatureCandidate {
		t.Fatalf("无系统压力的低 IOPS 慢请求应保持候选线索: %+v", finding)
	}
}

func TestBuildIOStatFindingsSuppressesLowIOPSSoftWriteLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{}
	for i := 0; i < 4; i++ {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     7,
				AvgQueueSize:   0.01,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	if finding, ok := findByRuleID(got, "iostat-write-soft-nvme11n1"); ok {
		t.Fatalf("低 IOPS 且缺少队列/iowait 佐证的 soft 写延迟不应报告为磁盘异常: %+v", finding)
	}
}

func TestBuildIOStatFindingsReportsSoftWriteLatencyWithEnoughIOPS(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{}
	for i := 0; i < 4; i++ {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 20,
				WriteKBPerSec:  4096,
				WriteAwait:     7,
				AvgQueueSize:   0.01,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "iostat-write-soft-nvme11n1")
	if !ok {
		t.Fatalf("IOPS 足够时 soft 写延迟仍应保留 finding, got=%+v", got)
	}
	if finding.Nature != FindingNatureCandidate ||
		finding.Metrics["latency_system_pressure"] != 0 ||
		finding.Metrics["latency_corroborated"] != 1 {
		t.Fatalf("soft 写延迟有 IOPS 但无队列/iowait 时应作为设备级候选线索: %+v", finding)
	}
	if !strings.Contains(finding.Summary, "未见系统级压力") {
		t.Fatalf("soft 写延迟摘要应说明缺少系统级压力佐证: %s", finding.Summary)
	}
}

func TestBuildIOStatFindingsDoesNotUseNormalLatencyIOPSToCorroborateSoftWriteLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				CPU:       iostat.CPUStats{IOWait: 0},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 20,
					WriteKBPerSec:  4096,
					WriteAwait:     0.2,
					AvgQueueSize:   0.01,
				}},
			},
		},
	}
	for i := 1; i < 4; i++ {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     7,
				AvgQueueSize:   0.01,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	if finding, ok := findByRuleID(got, "iostat-write-soft-nvme11n1"); ok {
		t.Fatalf("正常延迟样本的高 IOPS 不应佐证后续低 IOPS soft 写延迟: %+v", finding)
	}
}

func TestBuildIOStatFindingsDowngradesMultiSampleLowIOPSWriteLatencySpike(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{}
	for i, await := range []float64{0.2, 0.3, 300.11, 0.2} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     await,
				AvgQueueSize:   0.01,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("低 IOPS 单点写延迟尖峰仍应保留 finding, got=%+v", got)
	}
	if finding.Severity != SeverityMedium {
		t.Fatalf("多采样窗口中的低 IOPS 单点慢请求缺少 iowait/队列佐证时应降为 medium, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Metrics["active_sample_count"] != 4 ||
		finding.Metrics["high_latency_sample_count"] != 1 ||
		finding.Metrics["latency_corroborated"] != 0 ||
		finding.Metrics["total_iops_at_peak"] != 0.1 {
		t.Fatalf("低 IOPS 单点尖峰 metrics 不完整: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsKeepsSingleLowIOPSLatencyHighWhenCorroborated(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			CPU:       iostat.CPUStats{IOWait: 25},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     300.11,
				AvgQueueSize:   1.2,
			}},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-write-latency-nvme11n1")
	if !ok {
		t.Fatalf("有 iowait/队列佐证的高写延迟应生成 finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("有 iowait/队列佐证的高写延迟应保持 high, got=%q", finding.Severity)
	}
	if finding.Metrics["latency_corroborated"] != 1 {
		t.Fatalf("应记录 latency_corroborated=1: %+v", finding.Metrics)
	}
	if finding.Metrics["write_iops_at_peak"] != 0.1 || finding.Metrics["cpu_iowait_at_peak"] != 25 || finding.Metrics["avg_queue_at_peak"] != 1.2 {
		t.Fatalf("峰值样本佐证 metrics 缺失: %+v", finding.Metrics)
	}
	if _, ok := findByRuleID(got, "iostat-cpu-iowait"); !ok {
		t.Fatalf("应同时存在 CPU iowait finding: %+v", got)
	}
	if _, ok := findByRuleID(got, "iostat-queue-nvme11n1"); !ok {
		t.Fatalf("应同时存在队列 finding: %+v", got)
	}
}

func TestBuildIOStatFindingsDoesNotReportSingleCPUWaitSpikeWithoutDiskEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				CPU:       iostat.CPUStats{IOWait: 0},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 10,
					WriteKBPerSec:  40,
					WriteAwait:     0.5,
					AvgQueueSize:   0.01,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				CPU:       iostat.CPUStats{IOWait: 25},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 10,
					WriteKBPerSec:  40,
					WriteAwait:     0.5,
					AvgQueueSize:   0.01,
				}},
			},
			{
				Timestamp: start.Add(10 * time.Second),
				CPU:       iostat.CPUStats{IOWait: 0},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 10,
					WriteKBPerSec:  40,
					WriteAwait:     0.5,
					AvgQueueSize:   0.01,
				}},
			},
		},
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "iostat-cpu-iowait"); ok {
		t.Fatalf("单点 CPU iowait 尖峰且无磁盘延迟/队列佐证时不应报告: %+v", finding)
	}
}

func TestBuildIOStatFindingsDoesNotUseInactiveReadAwaitAsCPUWaitEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				CPU:       iostat.CPUStats{IOWait: 0},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 10,
					WriteKBPerSec:  40,
					WriteAwait:     0.5,
					ReadAwait:      300,
					AvgQueueSize:   0.01,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				CPU:       iostat.CPUStats{IOWait: 25},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 10,
					WriteKBPerSec:  40,
					WriteAwait:     0.5,
					ReadAwait:      300,
					AvgQueueSize:   0.01,
				}},
			},
			{
				Timestamp: start.Add(10 * time.Second),
				CPU:       iostat.CPUStats{IOWait: 0},
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 10,
					WriteKBPerSec:  40,
					WriteAwait:     0.5,
					ReadAwait:      300,
					AvgQueueSize:   0.01,
				}},
			},
		},
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "iostat-cpu-iowait"); ok {
		t.Fatalf("没有读请求时 r_await 不应佐证单点 CPU iowait 尖峰: %+v", finding)
	}
	if finding, ok := findByRuleID(got, "iostat-read-latency-nvme11n1"); ok {
		t.Fatalf("没有读请求时 r_await 不应生成读延迟 finding: %+v", finding)
	}
}

func TestBuildIOStatFindingsDowngradesUpperLayerDuplicateLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{
				{
					Device:         "dm-0",
					WriteReqPerSec: 20,
					WriteKBPerSec:  80,
					WriteAwait:     300,
					AvgQueueSize:   0.5,
				},
				{
					Device:         "nvme0n1",
					WriteReqPerSec: 20,
					WriteKBPerSec:  80,
					WriteAwait:     300,
					AvgQueueSize:   0.5,
				},
			},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	physical, ok := findByRuleID(got, "iostat-write-latency-nvme0n1")
	if !ok {
		t.Fatalf("底层物理盘异常应保留, got=%+v", got)
	}
	if physical.Severity != SeverityHigh {
		t.Fatalf("底层物理盘应保持 high, got=%q", physical.Severity)
	}
	upper, ok := findByRuleID(got, "iostat-write-latency-dm-0")
	if !ok {
		t.Fatalf("上层 dm 异常应保留为路径线索, got=%+v", got)
	}
	if upper.Severity != SeverityMedium {
		t.Fatalf("与底层盘同时间同方向重复的 dm finding 不应并列 high, got=%q", upper.Severity)
	}
	if upper.Metrics["stack_duplicate_with_physical"] != 1 || upper.Metrics["physical_peer_count"] != 1 {
		t.Fatalf("应标注设备栈重复证据: %+v", upper.Metrics)
	}
}

func TestBuildIOStatFindingsUsesConservativeThresholdForMDLatency(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:         "md0",
					WriteReqPerSec: 20,
					WriteKBPerSec:  80,
					WriteAwait:     20,
					AvgQueueSize:   0.01,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				Devices: []iostat.DeviceStats{{
					Device:         "md0",
					WriteReqPerSec: 20,
					WriteKBPerSec:  80,
					WriteAwait:     300,
					AvgQueueSize:   0.5,
				}},
			},
		},
	}

	early := BuildIOStatFindings(log, start, start)
	if finding, ok := findByRuleID(early, "iostat-write-latency-md0"); ok {
		t.Fatalf("md0 上层设备 20ms 不应套用 nvme 8ms 阈值报警: %+v", finding)
	}

	full := BuildIOStatFindings(log, start, start.Add(5*time.Second))
	finding, ok := findByRuleID(full, "iostat-write-latency-md0")
	if !ok {
		t.Fatalf("md0 严重写延迟仍应保留为上层设备线索, got=%+v", full)
	}
	if finding.Threshold != 50 {
		t.Fatalf("md0 应使用保守上层设备阈值 50ms, got=%.2f", finding.Threshold)
	}
	if finding.ObservedValue != 300 {
		t.Fatalf("md0 严重写延迟观测值不正确: %+v", finding)
	}
}

func TestBuildIOStatFindingsReportsShortSevereQueuePeak(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i := 0; i < 10; i++ {
		queue := 0.01
		iowait := 0.0
		if i == 5 {
			queue = 2.0
			iowait = 25
		}
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: iowait},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 50,
				WriteKBPerSec:  200,
				WriteAwait:     0.8,
				AvgQueueSize:   queue,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(45*time.Second))
	finding, ok := findByRuleID(got, "iostat-queue-nvme11n1")
	if !ok {
		t.Fatalf("短时严重队列峰值不应被平均值稀释掉, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("队列峰值伴随 iowait 应为 high, got=%q", finding.Severity)
	}
	if finding.Metric != "avg_queue_peak" {
		t.Fatalf("metric 应指向队列峰值, got=%q", finding.Metric)
	}
	if finding.ObservedValue != 2.0 {
		t.Fatalf("observed 应为队列峰值, got=%.2f", finding.ObservedValue)
	}
	if finding.Time != "2026-04-21 03:29:25" {
		t.Fatalf("队列 finding 应指向峰值时间, got=%q", finding.Time)
	}
	if finding.Metrics["avg_queue_depth"] >= config.Default().Iostat.QueueSoft ||
		finding.Metrics["avg_queue_peak"] != 2.0 ||
		finding.Metrics["queue_depth_peak"] != 2.0 ||
		finding.Metrics["high_queue_sample_count"] != 1 ||
		finding.Metrics["active_sample_count"] != 10 ||
		finding.Metrics["write_iops_at_peak"] != 50 ||
		finding.Metrics["total_iops_at_peak"] != 50 ||
		finding.Metrics["cpu_iowait_at_peak"] != 25 {
		t.Fatalf("队列峰值 metrics 不完整: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsReportsPersistentActiveQueueAsHigh(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i, queue := range []float64{1.1, 1.2, 1.3} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 20,
				WriteKBPerSec:  80,
				WriteAwait:     0.8,
				AvgQueueSize:   queue,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	finding, ok := findByRuleID(got, "iostat-queue-nvme11n1")
	if !ok {
		t.Fatalf("持续活跃队列应生成 finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("持续活跃队列平均值超过硬阈值应为 high, got=%q", finding.Severity)
	}
	if finding.Metrics["active_avg_queue_depth"] != 1.2 ||
		finding.Metrics["queue_depth_peak"] != 1.3 ||
		finding.Metrics["active_sample_count"] != 3 ||
		finding.Metrics["high_queue_sample_count"] != 3 {
		t.Fatalf("持续队列 metrics 不完整: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsTreatsDiscardOnlyQueueAsActiveIO(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			Devices: []iostat.DeviceStats{{
				Device:           "nvme0n1",
				DiscardReqPerSec: 50,
				DiscardKBPerSec:  200,
				DiscardAwait:     5,
				AvgQueueSize:     1.2,
			}},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-queue-nvme0n1")
	if !ok {
		t.Fatalf("discard-only 活跃 I/O 队列压力应生成 queue finding, got=%+v", got)
	}
	if finding.Metrics["total_iops_at_peak"] != 50 {
		t.Fatalf("队列峰值 IOPS 应包含 discard IOPS, metrics=%+v", finding.Metrics)
	}
	if value, ok := finding.Metrics["discard_iops_at_peak"]; !ok || value != 50 {
		t.Fatalf("队列峰值应记录 discard IOPS, metrics=%+v", finding.Metrics)
	}
	for _, ruleID := range []string{
		"iostat-read-latency-nvme0n1",
		"iostat-write-latency-nvme0n1",
	} {
		if finding, ok := findByRuleID(got, ruleID); ok {
			t.Fatalf("discard-only 样本不应生成读写延迟 finding %s: %+v", ruleID, finding)
		}
	}
}

func TestBuildIOStatFindingsIgnoresInactiveQueueBeforeLowActiveIO(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{
			{
				Timestamp: start,
				Devices: []iostat.DeviceStats{{
					Device:       "nvme11n1",
					AvgQueueSize: 3.0,
				}},
			},
			{
				Timestamp: start.Add(5 * time.Second),
				Devices: []iostat.DeviceStats{{
					Device:       "nvme11n1",
					AvgQueueSize: 4.0,
				}},
			},
			{
				Timestamp: start.Add(10 * time.Second),
				Devices: []iostat.DeviceStats{{
					Device:         "nvme11n1",
					WriteReqPerSec: 20,
					WriteKBPerSec:  80,
					WriteAwait:     0.8,
					AvgQueueSize:   0.02,
				}},
			},
		},
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "iostat-queue-nvme11n1"); ok {
		t.Fatalf("无 I/O 样本中的高队列不应污染活跃队列判断: %+v", finding)
	}
}

func TestBuildIOStatFindingsIgnoresSingleSoftQueuePeakWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i, queue := range []float64{0.01, 0.35, 0.01} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 20,
				WriteKBPerSec:  80,
				WriteAwait:     0.8,
				AvgQueueSize:   queue,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "iostat-queue-nvme11n1"); ok {
		t.Fatalf("单点轻微队列峰值且无压力佐证时不应报告: %+v", finding)
	}
}

func TestBuildIOStatFindingsIgnoresSingleLowIOPSHardQueuePeakWithoutPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: start,
			CPU:       iostat.CPUStats{IOWait: 0.5},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 0.1,
				WriteKBPerSec:  4,
				WriteAwait:     0.8,
				AvgQueueSize:   1.2,
			}},
		}},
	}

	got := BuildIOStatFindings(log, start, start)
	if finding, ok := findByRuleID(got, "iostat-queue-nvme11n1"); ok {
		t.Fatalf("单点低 IOPS hard 队列峰值且无 iowait 佐证时不应报告: %+v", finding)
	}
}

func TestBuildIOStatFindingsReportsSustainedHighUtilizationWithLatencyEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i := 0; i < 4; i++ {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 50,
				WriteKBPerSec:  200,
				WriteAwait:     12,
				AvgQueueSize:   0.05,
				Utilization:    96,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "iostat-util-nvme11n1")
	if !ok {
		t.Fatalf("持续高 util 且有延迟佐证时应生成 utilization finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("持续高 util 且有延迟佐证应为 high, got=%q finding=%+v", finding.Severity, finding)
	}
	if finding.Metric != "util_pct" || finding.ObservedValue != 96 || finding.Time != "2026-04-21 03:29:00" {
		t.Fatalf("util finding 关键字段不正确: %+v", finding)
	}
	if finding.Metrics["util_avg_pct"] != 96 ||
		finding.Metrics["util_high_sample_count"] != 4 ||
		finding.Metrics["util_corroborated"] != 1 ||
		finding.Metrics["write_await_at_peak"] != 12 {
		t.Fatalf("util finding metrics 不完整: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsReportsSustainedHighUtilizationWhenEvidenceIsNotAtPeak(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i, sample := range []struct {
		util       float64
		writeAwait float64
	}{
		{util: 97, writeAwait: 12},
		{util: 96, writeAwait: 12},
		{util: 98, writeAwait: 0.8},
		{util: 96, writeAwait: 12},
	} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 50,
				WriteKBPerSec:  200,
				WriteAwait:     sample.writeAwait,
				AvgQueueSize:   0.05,
				Utilization:    sample.util,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "iostat-util-nvme11n1")
	if !ok {
		t.Fatalf("持续高 util 的佐证不一定落在峰值样本，仍应报告 utilization finding, got=%+v", got)
	}
	if finding.Severity != SeverityHigh || finding.ObservedValue != 98 {
		t.Fatalf("持续高 util 应按峰值记录 high finding: %+v", finding)
	}
	if finding.Metrics["util_corroborated"] != 1 || finding.Metrics["util_high_sample_count"] != 4 {
		t.Fatalf("util finding 应记录同窗口佐证和持续样本数: %+v", finding.Metrics)
	}
}

func TestBuildIOStatFindingsDoesNotUseInactiveAwaitAsUtilEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i := 0; i < 4; i++ {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				ReadReqPerSec:  0,
				ReadKBPerSec:   0,
				ReadAwait:      300,
				WriteReqPerSec: 50,
				WriteKBPerSec:  200,
				WriteAwait:     0.8,
				AvgQueueSize:   0.01,
				Utilization:    96,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "iostat-util-nvme11n1")
	if !ok {
		t.Fatalf("持续高 util 应作为候选线索保留，但不能被无读 I/O 的残留 r_await 佐证, got=%+v", got)
	}
	if finding.Nature != FindingNatureCandidate ||
		finding.Metrics["util_corroborated"] != 0 ||
		finding.Metrics["read_await_at_peak"] != 300 {
		t.Fatalf("无读 I/O 时残留 r_await 不应把高 util 升级为风险: %+v", finding)
	}
	if finding, ok := findByRuleID(got, "iostat-read-latency-nvme11n1"); ok {
		t.Fatalf("无读 I/O 时残留 r_await 不应生成读延迟 finding: %+v", finding)
	}
}

func TestBuildIOStatFindingsKeepsSustainedHardUtilizationWithoutPressureAsCandidate(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i := 0; i < 4; i++ {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			CPU:       iostat.CPUStats{IOWait: 0.5},
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 800,
				WriteKBPerSec:  102400,
				WriteAwait:     0.8,
				AvgQueueSize:   0.01,
				Utilization:    96,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(15*time.Second))
	finding, ok := findByRuleID(got, "iostat-util-nvme11n1")
	if !ok {
		t.Fatalf("持续 hard util 即使无延迟/队列/iowait 佐证，也应作为吞吐或利用率候选线索保留, got=%+v", got)
	}
	if finding.Severity != SeverityMedium || finding.Nature != FindingNatureCandidate {
		t.Fatalf("无压力佐证的持续 hard util 不应作为高风险，got=%+v", finding)
	}
	if finding.Metrics["util_corroborated"] != 0 ||
		finding.Metrics["util_high_sample_count"] != 4 ||
		finding.Metrics["throughput_kb_s_at_peak"] != 102400 {
		t.Fatalf("util candidate metrics 不完整: %+v", finding.Metrics)
	}
	if !strings.Contains(finding.Summary, "未见延迟/队列/iowait 佐证") {
		t.Fatalf("util candidate summary 应说明缺少压力佐证: %s", finding.Summary)
	}
}

func TestBuildIOStatFindingsIgnoresSingleHighUtilizationWithoutPressureEvidence(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2026, time.April, 21, 3, 29, 0, 0, loc)
	log := &iostat.IOStatLog{}
	for i, util := range []float64{5, 100, 5} {
		log.Data = append(log.Data, iostat.IOStatData{
			Timestamp: start.Add(time.Duration(i) * 5 * time.Second),
			Devices: []iostat.DeviceStats{{
				Device:         "nvme11n1",
				WriteReqPerSec: 50,
				WriteKBPerSec:  200,
				WriteAwait:     0.8,
				AvgQueueSize:   0.01,
				Utilization:    util,
			}},
		})
	}

	got := BuildIOStatFindings(log, start, start.Add(10*time.Second))
	if finding, ok := findByRuleID(got, "iostat-util-nvme11n1"); ok {
		t.Fatalf("单点高 util 且无延迟/队列/iowait 佐证时不应报告: %+v", finding)
	}
}

func TestBuildIOStatFindingsReportsMultiDeviceWriteLatencyPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			CPU:       iostat.CPUStats{IOWait: 22},
			Devices: []iostat.DeviceStats{
				{
					Device:         "nvme11n1",
					WriteReqPerSec: 40,
					WriteKBPerSec:  4096,
					WriteAwait:     120,
					AvgQueueSize:   1.2,
				},
				{
					Device:         "nvme13n1",
					WriteReqPerSec: 35,
					WriteKBPerSec:  4096,
					WriteAwait:     150,
					AvgQueueSize:   1.1,
				},
			},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-multi-device-write-latency")
	if !ok {
		t.Fatalf("同一时间多块物理盘写延迟高且有 iowait/队列时应生成系统级 finding, got=%+v", got)
	}
	if finding.Nature != FindingNatureRisk || finding.Severity != SeverityHigh {
		t.Fatalf("多设备同窗口写延迟应作为系统级风险, got=%+v", finding)
	}
	if finding.Target != "storage" || finding.Metric != "write_await_ms" || finding.Time != "2026-04-21 03:29:12" {
		t.Fatalf("多设备写延迟 finding 定位字段不完整: %+v", finding)
	}
	if finding.Metrics["affected_device_count"] != 2 ||
		finding.Metrics["cpu_iowait_at_peak"] != 22 ||
		finding.Metrics["max_latency_ms"] != 150 ||
		finding.Metrics["max_queue_depth"] != 1.2 {
		t.Fatalf("多设备写延迟 metrics 不完整: %+v", finding.Metrics)
	}
	for _, want := range []string{"nvme11n1", "nvme13n1", "共同出现", "系统级 I/O 压力"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("summary 应说明多设备共同异常和系统级压力 %q: %s", want, finding.Summary)
		}
	}
}

func TestBuildIOStatFindingsIncludesMPathInMultiDeviceLatencyPressure(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	at := time.Date(2026, time.April, 21, 3, 29, 12, 0, loc)
	log := &iostat.IOStatLog{
		Data: []iostat.IOStatData{{
			Timestamp: at,
			CPU:       iostat.CPUStats{IOWait: 22},
			Devices: []iostat.DeviceStats{
				{
					Device:         "mpatha",
					WriteReqPerSec: 40,
					WriteKBPerSec:  4096,
					WriteAwait:     120,
					AvgQueueSize:   1.2,
				},
				{
					Device:         "mpathb",
					WriteReqPerSec: 35,
					WriteKBPerSec:  4096,
					WriteAwait:     150,
					AvgQueueSize:   1.1,
				},
			},
		}},
	}

	got := BuildIOStatFindings(log, at, at)
	finding, ok := findByRuleID(got, "iostat-multi-device-write-latency")
	if !ok {
		t.Fatalf("同一时间多个 mpath 设备写延迟高且有 iowait/队列时应生成系统级 finding, got=%+v", got)
	}
	if finding.Metrics["affected_device_count"] != 2 {
		t.Fatalf("mpath 多设备 finding 应记录受影响设备数: %+v", finding.Metrics)
	}
	for _, want := range []string{"mpatha", "mpathb"} {
		if !strings.Contains(finding.Summary, want) {
			t.Fatalf("summary 应包含 mpath 设备 %q: %s", want, finding.Summary)
		}
	}
}

func findByRuleID(findings []Finding, ruleID string) (Finding, bool) {
	for _, item := range findings {
		if item.RuleID == ruleID {
			return item, true
		}
	}
	return Finding{}, false
}
