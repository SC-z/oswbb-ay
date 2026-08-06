package processor

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecompressGzFilesPreservesSourceAndUsesTemporaryOutput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat.gz")
	content := []byte("zzz ***Tue Apr 21 03:00:04 CST 2026\n")
	writeGzipFile(t, source, content)

	decompressed, cleanup, err := decompressGzFiles([]string{source})
	if err != nil {
		t.Fatalf("decompressGzFiles 返回错误: %v", err)
	}
	defer cleanup()

	if _, err := os.Stat(source); err != nil {
		t.Fatalf("解压不应删除原 .gz 文件: %v", err)
	}
	if len(decompressed) != 1 {
		t.Fatalf("应返回 1 个临时解压文件, got=%d files=%v", len(decompressed), decompressed)
	}
	if decompressed[0] == filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat") {
		t.Fatalf("不应在原 archive 目录旁边创建解压文件: %s", decompressed[0])
	}
	got, err := os.ReadFile(decompressed[0])
	if err != nil {
		t.Fatalf("读取临时解压文件失败: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("临时解压内容不一致: got=%q want=%q", got, content)
	}

	cleanup()
	if _, err := os.Stat(decompressed[0]); !os.IsNotExist(err) {
		t.Fatalf("cleanup 应删除临时解压文件, stat err=%v", err)
	}
}

func TestDecompressGzFilesLogsFailuresToStderr(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat.gz")
	if err := os.WriteFile(source, []byte("not gzip"), 0o644); err != nil {
		t.Fatalf("写入坏 gzip 文件失败: %v", err)
	}

	var decompressed []string
	var cleanup func()
	var err error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			decompressed, cleanup, err = decompressGzFiles([]string{source})
		})
	})
	if cleanup != nil {
		defer cleanup()
	}

	if err == nil {
		t.Fatalf("坏 gzip 应返回解压错误")
	}
	if len(decompressed) != 0 {
		t.Fatalf("坏 gzip 不应返回解压文件: %v", decompressed)
	}
	if strings.Contains(stdout, "解压失败") {
		t.Fatalf("解压失败日志不应写入 stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "WARN 解压失败 "+source) {
		t.Fatalf("解压失败日志应写入 stderr warning: %q", stderr)
	}
}

func TestProcessDirectoryAnalyzesGzWithoutMutatingArchive(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat.gz")
	content := []byte(`Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:04 CST 2026
avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           1.00    0.00    1.00    0.00    0.00   98.00

Device r/s w/s rkB/s wkB/s r_await w_await aqu-sz
nvme0n1 0.00 1.00 0.00 4.00 0.00 0.20 0.00
`)
	writeGzipFile(t, source, content)

	var stderr string
	output := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			err := NewFileProcessor().ProcessDirectory(
				dir,
				"",
				"",
				false,
				outputFormatReport,
				time.FixedZone("CST", 8*3600),
				AIConfig{Enabled: false},
			)
			if err != nil {
				t.Fatalf("ProcessDirectory 返回错误: %v", err)
			}
		})
	})

	if _, err := os.Stat(source); err != nil {
		t.Fatalf("目录分析不应删除原 .gz 文件: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat")); !os.IsNotExist(err) {
		t.Fatalf("目录分析不应在原目录旁边留下解压文件, stat err=%v", err)
	}
	if !strings.Contains(output, "nvme0n1") {
		t.Fatalf("目录分析应处理 .gz 内部日志并输出报告内容:\n%s", output)
	}
	for _, forbidden := range []string{"扫描目录:", "发现 0 个iostat文件", "临时解压完成", "合并模式:", "主机:"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("目录处理进度不应写入 stdout %q:\n%s", forbidden, output)
		}
	}
	for _, want := range []string{"INFO 发现 1 个压缩文件(.gz)，正在临时解压", "INFO 临时解压完成，继续分析压缩文件内容"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("解压进度应写入 stderr log %q:\n%s", want, stderr)
		}
	}
	for _, want := range []string{"INFO 扫描目录:", "INFO 发现 0 个iostat文件", "INFO 合并模式: 按主机名分组统一分析", "INFO 主机:"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("目录处理进度应写入 stderr log %q:\n%s", want, stderr)
		}
	}
}

func TestScanDirectoryIgnoresGeneratedOutputFiles(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat")
	for _, filename := range []string{
		input,
		filepath.Join(dir, "iostat_rdsmaster1_20260618144603_000000000.html"),
		filepath.Join(dir, "iostat_rdsmaster1_20260618144603_000000000.csv"),
	} {
		if err := os.WriteFile(filename, []byte("test"), 0o644); err != nil {
			t.Fatalf("写入测试文件失败 %s: %v", filename, err)
		}
	}

	iostatFiles, meminfoFiles, topFiles, mpstatFiles, gzFiles, err := scanDirectory(dir)
	if err != nil {
		t.Fatalf("scanDirectory 返回错误: %v", err)
	}
	if len(iostatFiles) != 1 || iostatFiles[0] != input {
		t.Fatalf("应只把 .dat 原始日志识别为 iostat, got=%v", iostatFiles)
	}
	if len(meminfoFiles) != 0 || len(topFiles) != 0 || len(mpstatFiles) != 0 || len(gzFiles) != 0 {
		t.Fatalf("生成输出文件不应进入任何输入分类, mem=%v top=%v mp=%v gz=%v", meminfoFiles, topFiles, mpstatFiles, gzFiles)
	}
}

func TestProcessSingleFilesReturnsErrorWhenAnyFileFails(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "rdsmaster1_iostat_26.04.21.0300.dat")

	var err error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			err = NewFileProcessor().processSingleFiles(
				[]string{missing},
				nil,
				nil,
				"",
				"",
				outputFormatReport,
				time.FixedZone("CST", 8*3600),
				AIConfig{Enabled: false},
			)
		})
	})
	if err == nil {
		t.Fatal("processSingleFiles 应返回失败文件的汇总错误")
	}
	if !strings.Contains(err.Error(), "有 1 个文件分析失败") {
		t.Fatalf("错误信息应包含失败文件数量, got=%v", err)
	}
	if strings.Contains(stdout, "分析失败") {
		t.Fatalf("分析失败日志不应写入 stdout: %q", stdout)
	}
	for _, forbidden := range []string{"单文件模式:", "正在分析iostat文件"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("单文件处理进度不应写入 stdout %q:\n%s", forbidden, stdout)
		}
	}
	if !strings.Contains(stderr, "ERROR 分析失败:") {
		t.Fatalf("分析失败日志应写入 stderr error: %q", stderr)
	}
	for _, want := range []string{"INFO 单文件模式: 每个文件独立分析", "INFO 正在分析iostat文件"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("单文件处理进度应写入 stderr log %q:\n%s", want, stderr)
		}
	}
}

func TestProcessMergedFilesReturnsErrorWhenAnyHostFails(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "rdsmaster1_meminfo_26.04.21.0300.dat")

	var err error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			err = NewFileProcessor().processMergedFiles(
				nil,
				[]string{missing},
				nil,
				nil,
				"",
				"",
				outputFormatReport,
				time.FixedZone("CST", 8*3600),
				AIConfig{Enabled: false},
			)
		})
	})
	if err == nil {
		t.Fatal("processMergedFiles 应返回失败主机的汇总错误")
	}
	if !strings.Contains(err.Error(), "有 1 个主机分析失败") {
		t.Fatalf("错误信息应包含失败主机数量, got=%v", err)
	}
	if strings.Contains(stdout, "分析失败") {
		t.Fatalf("主机分析失败日志不应写入 stdout: %q", stdout)
	}
	for _, forbidden := range []string{"合并模式:", "主机:"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("合并处理进度不应写入 stdout %q:\n%s", forbidden, stdout)
		}
	}
	if !strings.Contains(stderr, "ERROR 主机 rdsmaster1 分析失败:") {
		t.Fatalf("主机分析失败日志应写入 stderr error: %q", stderr)
	}
	for _, want := range []string{"INFO 合并模式: 按主机名分组统一分析", "INFO 主机: rdsmaster1"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("合并处理进度应写入 stderr log %q:\n%s", want, stderr)
		}
	}
}

func TestParseMergedBundleAppliesMPStatCPUCountToTopSnapshots(t *testing.T) {
	dir := t.TempDir()
	topFile := filepath.Join(dir, "rdsmaster1_top_26.04.21.0300.dat")
	topContent := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:09 CST 2026

top - 03:00:10 up  9:50,  0 users,  load average: 5.27, 6.64, 5.26
Tasks: 2191 total,   5 running, 2186 sleeping,   0 stopped,   0 zombie
%Cpu(s):  3.5 us,  0.6 sy,  0.0 ni, 95.4 id,  0.0 wa,  0.2 hi,  0.3 si,  0.0 st
`
	if err := os.WriteFile(topFile, []byte(topContent), 0o644); err != nil {
		t.Fatalf("写入 top 测试文件失败: %v", err)
	}

	mpstatFile := filepath.Join(dir, "rdsmaster1_mpstat_26.04.21.0300.dat")
	mpstatContent := `Linux OSWbb v7.3.3
zzz ***Tue Apr 21 03:00:04 CST 2026
Linux 4.19.90-89.11.v2401.ky10.x86_64 (rdsmaster1) 	04/21/26 	_x86_64_	(16 CPU)

03:00:04     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
03:00:05     all    3.01    0.00    0.50    0.00    0.16    0.16    0.00    0.00    0.00   96.17
`
	if err := os.WriteFile(mpstatFile, []byte(mpstatContent), 0o644); err != nil {
		t.Fatalf("写入 mpstat 测试文件失败: %v", err)
	}

	bundle, err := parseMergedBundle("rdsmaster1", map[string][]string{
		"top":    {topFile},
		"mpstat": {mpstatFile},
	})
	if err != nil {
		t.Fatalf("parseMergedBundle 返回错误: %v", err)
	}
	if bundle.Top == nil || len(bundle.Top.Snapshots) != 1 {
		t.Fatalf("期望 1 个 top 快照, got=%+v", bundle.Top)
	}
	if bundle.Top.Snapshots[0].CPUCount != 16 {
		t.Fatalf("mpstat CPU 核数应注入 top 快照, got=%d", bundle.Top.Snapshots[0].CPUCount)
	}
}

func writeGzipFile(t *testing.T, filename string, content []byte) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("创建 gzip 文件失败: %v", err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(content); err != nil {
		t.Fatalf("写入 gzip 内容失败: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 gzip writer 失败: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("关闭 gzip 文件失败: %v", err)
	}
}
