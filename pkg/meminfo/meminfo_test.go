package meminfo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseMemoryLineCapturesCommitLimitAndCommittedAS(t *testing.T) {
	parser := &MemInfoParser{}
	var stats MemStats

	parser.parseMemoryLine("CommitLimit:    1000000 kB", &stats)
	parser.parseMemoryLine("Committed_AS:    950000 kB", &stats)

	if stats.CommitLimit != 1000000 {
		t.Fatalf("CommitLimit 未解析, got=%d", stats.CommitLimit)
	}
	if stats.Committed != 950000 {
		t.Fatalf("Committed_AS 未解析, got=%d", stats.Committed)
	}
}

func TestParseFileDropsSnapshotAfterInvalidTimestamp(t *testing.T) {
	content := `zzz ***Tue Apr 21 03:00:04 CST 2026
MemTotal:       1048576 kB
MemAvailable:   900000 kB
zzz ***bad timestamp
MemTotal:       1048576 kB
MemAvailable:    10000 kB
`
	filename := filepath.Join(t.TempDir(), "meminfo.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 meminfo 文件失败: %v", err)
	}

	log, err := (&MemInfoParser{}).ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	if len(log.Data) != 1 {
		t.Fatalf("坏时间戳后的数据不应重复污染旧快照, got=%d snapshots: %+v", len(log.Data), log.Data)
	}
	if got := log.Data[0].MemStats.MemAvailable; got != 900000 {
		t.Fatalf("坏时间戳后的 MemAvailable 不应写入上一快照, got=%d", got)
	}
}

func TestGetMemoryUsageTrendUsesFallbackWhenMemAvailableMissing(t *testing.T) {
	start := time.Date(2026, time.April, 23, 5, 4, 3, 0, time.UTC)
	log := &MemInfoLog{
		Data: []MemStatData{{
			Timestamp: start,
			MemStats: MemStats{
				MemTotal:     128 * 1024 * 1024,
				MemFree:      4 * 1024 * 1024,
				Buffers:      2 * 1024 * 1024,
				Cached:       88 * 1024 * 1024,
				SReclaimable: 2 * 1024 * 1024,
			},
		}},
	}

	got := log.GetMemoryUsageTrend(start, start)
	if len(got) != 1 {
		t.Fatalf("期望 1 个趋势点, got=%d", len(got))
	}
	if got[0].Value != 25 {
		t.Fatalf("缺 MemAvailable 时应使用 MemFree+Buffers+Cached+SReclaimable 估算，got=%.1f", got[0].Value)
	}
}
