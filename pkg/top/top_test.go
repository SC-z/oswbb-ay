package top

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFileSkipsSnapshotsWithoutCPUStats(t *testing.T) {
	content := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:04 CST 2026
  17932 root      20   0 1921636   1.0g  73756 S  13.3   0.1 327:28.60 kube-ap+
zzz ***Tue Apr 21 03:00:09 CST 2026

top - 03:00:10 up  9:50,  0 users,  load average: 3.27, 6.64, 5.26
Tasks: 2191 total,   1 running, 2190 sleeping,   0 stopped,   0 zombie
%Cpu(s):  3.5 us,  0.6 sy,  0.0 ni, 95.4 id,  0.0 wa,  0.2 hi,  0.3 si,  0.0 st
MiB Mem : 1542584.+total, 1492947.+free,  27023.7 used,  22613.6 buff/cache

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
  26075 root      20   0  247.3g   2.3g 936060 S 292.5   0.2 457:28.08 prometh+
`
	filename := filepath.Join(t.TempDir(), "top.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 top 文件失败: %v", err)
	}

	log, err := NewTopParser().ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	if len(log.Snapshots) != 1 {
		t.Fatalf("应跳过缺少 CPU 行的不完整快照, got=%d snapshots: %+v", len(log.Snapshots), log.Snapshots)
	}

	got := log.Snapshots[0]
	if got.Timestamp.Format("2006-01-02 15:04:05") != "2026-04-21 03:00:09" {
		t.Fatalf("timestamp mismatch: got=%s", got.Timestamp.Format("2006-01-02 15:04:05"))
	}
	if got.Load1 != 3.27 || got.TaskTotal != 2191 || got.CpuIdle != 95.4 || got.CpuUser != 3.5 {
		t.Fatalf("完整快照解析不符合预期: %+v", got)
	}
}

func TestParseFileSupportsCompactPercentCPUStats(t *testing.T) {
	content := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:09 CST 2026

top - 03:00:10 up  9:50,  0 users,  load average: 3.27, 6.64, 5.26
Tasks: 2191 total,   1 running, 2190 sleeping,   0 stopped,   0 zombie
Cpu(s): 3.5%us, 0.6%sy, 0.0%ni, 95.4%id, 0.2%wa, 0.0%hi, 0.3%si, 0.0%st
`
	filename := filepath.Join(t.TempDir(), "top.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 top 文件失败: %v", err)
	}

	log, err := NewTopParser().ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	if len(log.Snapshots) != 1 {
		t.Fatalf("compact %% CPU 格式应保留一个完整快照, got=%d", len(log.Snapshots))
	}

	got := log.Snapshots[0]
	if got.CpuUser != 3.5 || got.CpuSys != 0.6 || got.CpuIdle != 95.4 || got.CpuWait != 0.2 || got.CpuSteal != 0.0 {
		t.Fatalf("compact %% CPU 格式解析错误: %+v", got)
	}
}

func TestParseFileSkipsMalformedCPUStats(t *testing.T) {
	content := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:09 CST 2026

top - 03:00:10 up  9:50,  0 users,  load average: 3.27, 6.64, 5.26
Tasks: 2191 total,   1 running, 2190 sleeping,   0 stopped,   0 zombie
Cpu(s): this line is corrupt
`
	filename := filepath.Join(t.TempDir(), "top.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 top 文件失败: %v", err)
	}

	log, err := NewTopParser().ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	if len(log.Snapshots) != 0 {
		t.Fatalf("无法解析 CPU 字段的快照不应进入后续规则, got=%d: %+v", len(log.Snapshots), log.Snapshots)
	}
}

func TestParseFileCapturesProcessRows(t *testing.T) {
	content := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:09 CST 2026

top - 03:00:10 up  9:50,  0 users,  load average: 3.27, 6.64, 5.26
Tasks: 2191 total,   1 running, 2190 sleeping,   0 stopped,   0 zombie
%Cpu(s):  3.5 us,  0.6 sy,  0.0 ni, 95.4 id,  0.0 wa,  0.2 hi,  0.3 si,  0.0 st

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
  26075 root      20   0  247.3g   2.3g 936060 S 292.5   0.2 457:28.08 prometh+
3666962 root      20   0   13888   6796   5976 D   0.0   0.0   0:00.00 sshd
`
	filename := filepath.Join(t.TempDir(), "top.dat")
	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试 top 文件失败: %v", err)
	}

	log, err := NewTopParser().ParseFile(filename)
	if err != nil {
		t.Fatalf("ParseFile 返回错误: %v", err)
	}
	if len(log.Snapshots) != 1 {
		t.Fatalf("expected one snapshot, got=%d", len(log.Snapshots))
	}

	processes := log.Snapshots[0].Processes
	if len(processes) != 2 {
		t.Fatalf("expected two process rows, got=%d: %+v", len(processes), processes)
	}
	if processes[0].PID != 26075 || processes[0].Command != "prometh+" || processes[0].CPUPercent != 292.5 {
		t.Fatalf("top CPU process parsed incorrectly: %+v", processes[0])
	}
	if processes[0].ResKB != 2411724 {
		t.Fatalf("RES with g suffix should be converted to KB, got=%d", processes[0].ResKB)
	}
	if processes[1].PID != 3666962 || processes[1].State != "D" || processes[1].Command != "sshd" {
		t.Fatalf("D-state process parsed incorrectly: %+v", processes[1])
	}
}
