# OSWbb 三节点延迟监控实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保持 OSWbb 原生主循环、子采集脚本、小时归档、压缩和保留机制不变的前提下，增加 56/8192 字节 ICMP 延迟采集，并让 `oswbb-analyse` 输出长期延迟、丢包和大小包对比。

**Architecture:** 采集侧交付一个可应用到 OSWbb 7.3.3 的最小补丁和独立 `latencysub.sh`，每个节点读取两个对端并写入 `oswlatency` 小时文件。分析侧以 `pkg/latency` 保存解析模型，以 `internal/modules/latency` 完成无副作用统计和报告，再通过现有 `core -> app registry -> processor -> output` 链路自动发现并导出。

**Tech Stack:** POSIX shell、Linux iputils `ping`、Go 1.23+、Go 标准库、现有 `internal/report` 与 `internal/output`。

## Global Constraints

- 小包必须执行 `ping -n -c 1 -W 1 -s 56 TARGET`。
- 大包必须执行 `ping -n -c 1 -W 1 -s 8192 TARGET`，不得增加 `-M do`；MTU 1500 下按 IPv4 分片大报文解释。
- 三节点每个节点只配置另外两个节点，最终形成 6 条有方向链路。
- 不引入守护进程、cron、`fping`、第三方 Go 依赖或另一套归档保留机制。
- 保留原始 ping 输出，并为每次探测增加一条 `OSWLATENCY|` 结构化记录。
- 当前工作树已有大量相关未提交改动；只编辑必要文件，提交时不得夹带修改前已存在的内容。
- 所有新增逻辑先写失败测试，再写最小实现。

## 文件结构

- `release/oswbb-latency/latencysub.sh`：单周期 56/8192 探测、结构化记录、原始输出和锁清理。
- `release/oswbb-latency/oswlatency.conf.example`：两对端配置样例。
- `release/oswbb-latency/OSWatcher-latency.patch`：向上游 `OSWatcher.sh` 和 `OSWatcherFM.sh` 增加原生调度、小时归档和保留清理。
- `release/oswbb-latency/README.md`：部署、配置和验证命令。
- `scripts/test_oswbb_latency_collector.sh`：使用假 `ping` 验证采集脚本及补丁。
- `pkg/latency/types.go`：采样、日志和时间范围模型。
- `pkg/latency/parser.go`：`OSWLATENCY|` 行解析与逐行错误收集。
- `pkg/latency/parser_test.go`：解析器红绿测试。
- `internal/modules/latency/models.go`：模块输入、路径统计、大小包对比和分析结果。
- `internal/modules/latency/analyzer.go`：过滤、分组、丢包率和最近秩百分位计算。
- `internal/modules/latency/report.go`：原始样本、汇总、大小包对比和大包失败 finding。
- `internal/modules/latency/latency_test.go`：统计和报告红绿测试。
- `internal/modules/module.go`、`internal/core/types.go`、`internal/app/builtin_modules.go`：文件类型、bundle 和内置模块注册。
- `pkg/processor/processor.go`、`pkg/processor/ai_bundle.go`、`pkg/processor/analyzer_latency.go`：目录扫描、合并解析和统一输出。
- `README.md`：新增模块和使用说明。

---

### Task 1: OSWbb 原生延迟采集器

**Files:**
- Create: `scripts/test_oswbb_latency_collector.sh`
- Create: `release/oswbb-latency/latencysub.sh`
- Create: `release/oswbb-latency/oswlatency.conf.example`
- Create: `release/oswbb-latency/OSWatcher-latency.patch`
- Create: `release/oswbb-latency/README.md`

**Interfaces:**
- Consumes: `$1` 为 OSWbb 小时输出文件；环境变量 `OSWBB_LATENCY_CONF`、`OSWBB_LATENCY_LOCK`、`OSWBB_LATENCY_SOURCE` 仅用于覆盖默认配置、锁和源节点名。
- Produces: 每次探测一条 `OSWLATENCY|timestamp=...|source=...|target=...|address=...|size=...|status=...|rtt_ms=...`。

- [ ] **Step 1: 写失败的 shell 测试**

```sh
#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 15
mkdir -p "$tmp/bin" "$tmp/locks"
cat > "$tmp/bin/ping" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PING_CALLS"
case " $* " in
  *" -s 56 "*) echo '64 bytes from 10.0.0.12: icmp_seq=1 ttl=64 time=0.183 ms'; exit 0 ;;
  *" -s 8192 "*) exit 1 ;;
esac
exit 2
EOF
chmod +x "$tmp/bin/ping"
printf 'node2 10.0.0.12\nnode3 10.0.0.13\n' > "$tmp/oswlatency.conf"
touch "$tmp/locks/latencylock.file"
PING_CALLS="$tmp/calls" PATH="$tmp/bin:$PATH" \
OSWBB_LATENCY_CONF="$tmp/oswlatency.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
OSWBB_LATENCY_SOURCE=node1 \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/output"
test "$(grep -c -- '-s 56' "$tmp/calls")" -eq 2
test "$(grep -c -- '-s 8192' "$tmp/calls")" -eq 2
grep -q 'size=56|status=ok|rtt_ms=0.183' "$tmp/output"
grep -q 'size=8192|status=timeout|rtt_ms=$' "$tmp/output"
test ! -e "$tmp/locks/latencylock.file"
```

- [ ] **Step 2: 运行测试确认红灯**

Run: `sh scripts/test_oswbb_latency_collector.sh`

Expected: FAIL，提示 `release/oswbb-latency/latencysub.sh` 不存在。

- [ ] **Step 3: 写最小采集实现**

```sh
#!/bin/sh
output=$1
conf=${OSWBB_LATENCY_CONF:-oswlatency.conf}
lock=${OSWBB_LATENCY_LOCK:-locks/latencylock.file}
source_host=${OSWBB_LATENCY_SOURCE:-`hostname`}
cleanup() { rm -f "$lock"; }
trap cleanup 0 1 2 15
now() { date '+%Y-%m-%dT%H:%M:%S%z'; }

echo "zzz ***`date '+%a %b %e %T %Z %Y'`" >> "$output"
if [ ! -r "$conf" ]; then
  printf 'OSWLATENCY|timestamp=%s|source=%s|target=|address=|size=0|status=config_error|rtt_ms=\n' "`now`" "$source_host" >> "$output"
  exit 0
fi

valid=0
while read -r target address extra; do
  case "$target" in ''|'#'*) continue ;; esac
  invalid=0
  [ -n "$address" ] && [ -z "$extra" ] || invalid=1
  case "$target" in *[!A-Za-z0-9._-]*) invalid=1 ;; esac
  case "$address" in ''|*[!0-9.]*) invalid=1 ;; esac
  if [ "$invalid" -eq 1 ]; then
    printf 'OSWLATENCY|timestamp=%s|source=%s|target=%s|address=%s|size=0|status=config_error|rtt_ms=\n' "`now`" "$source_host" "$target" "$address" >> "$output"
    continue
  fi
  valid=1
  for size in 56 8192; do
    timestamp=`now`
    raw=`ping -n -c 1 -W 1 -s "$size" "$address" 2>&1`
    rc=$?
    printf '%s\n' "$raw" >> "$output"
    rtt=`printf '%s\n' "$raw" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^time[=<]/) {sub(/^time[=<]/,"",$i); print $i; exit}}'`
    if [ "$rc" -eq 0 ] && [ -n "$rtt" ]; then status=ok
    elif [ "$rc" -eq 1 ]; then status=timeout; rtt=
    else status=ping_error; rtt=
    fi
    printf 'OSWLATENCY|timestamp=%s|source=%s|target=%s|address=%s|size=%s|status=%s|rtt_ms=%s\n' "$timestamp" "$source_host" "$target" "$address" "$size" "$status" "$rtt" >> "$output"
  done
done < "$conf"
[ "$valid" -eq 1 ] || printf 'OSWLATENCY|timestamp=%s|source=%s|target=|address=|size=0|status=config_error|rtt_ms=\n' "`now`" "$source_host" >> "$output"
```

`OSWatcher-latency.patch` 必须把以下完整逻辑插入上游对应区段：

```sh
latencystatus=0

case $PLATFORM in
  Linux)
    mkdir -p $OSWBB_ARCHIVE_DEST/oswlatency
  ;;
esac

if [ -f locks/latencylock.file ]; then
  rm locks/latencylock.file
fi

case $PLATFORM in
  Linux)
    if command -v ping > /dev/null 2>&1; then
      echo "PING found on your system."
      PINGFOUND=1
    else
      echo "Warning... PING not found on your system. No latency data will be collected."
      PINGFOUND=0
    fi
  ;;
  *)
    PINGFOUND=0
  ;;
esac
```

主循环中的完整采集块为：

```sh
if [ $PINGFOUND = 1 ]; then
  if [ $hour != $lasthour ]; then
    echo $PLATFORM OSWbb $version $hostn >> $OSWBB_ARCHIVE_DEST/oswlatency/${hostn}_latency_$hour
    if [ $zipfiles = 1 ]; then
      if [ -f $OSWBB_ARCHIVE_DEST/oswlatency/${hostn}_latency_$lasthour ]; then
        $zip $OSWBB_ARCHIVE_DEST/oswlatency/${hostn}_latency_$lasthour &
      fi
    fi
  fi
  if [ -f locks/latencylock.file ]; then
    latencystatus=1
  else
    touch locks/latencylock.file
    if [ $latencystatus = 1 ]; then
      echo "***Warning. LATENCY response is spanning snapshot intervals."
      latencystatus=0
    fi
    ./latencysub.sh $OSWBB_ARCHIVE_DEST/oswlatency/${hostn}_latency_$hour &
  fi
fi
```

`OSWatcherFM.sh` 中的完整保留块为：

```sh
if [ -d $2/oswlatency ]; then
  numberOfFiles=`ls -t $2/oswlatency | wc -l`
  numberToDelete=`expr $numberOfFiles - $archiveInterval`
  if [ $numberOfFiles -gt $archiveInterval ]; then
    ls -t $2/oswlatency/* | tail -$numberToDelete | xargs rm
  fi
fi
```

- [ ] **Step 4: 验证采集器和补丁**

Run: `sh -n release/oswbb-latency/latencysub.sh scripts/test_oswbb_latency_collector.sh`

Expected: PASS，无输出。

Run: `sh scripts/test_oswbb_latency_collector.sh`

Expected: PASS，无输出。

Run: `tmp=$(mktemp -d); cp other/oswbb-upstream/OSWatcher.sh other/oswbb-upstream/OSWatcherFM.sh "$tmp"; patch --dry-run -s -p1 -d "$tmp" < release/oswbb-latency/OSWatcher-latency.patch`

Expected: PASS，退出码 0。

### Task 2: 延迟日志模型与解析器

**Files:**
- Create: `pkg/latency/types.go`
- Create: `pkg/latency/parser.go`
- Create: `pkg/latency/parser_test.go`

**Interfaces:**
- Produces: `type Sample`, `type Log`, `func (*Log) GetTimeRange()`, `func (Parser) ParseFile(string) (*Log, []error, error)`。
- Consumes: Task 1 定义的 `OSWLATENCY|` 键值记录。

- [ ] **Step 1: 写解析器失败测试**

```go
func TestParserKeepsValidSamplesAndReportsMalformedLines(t *testing.T) {
    input := strings.NewReader("raw ping output\n" +
        "OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=node1|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.183\n" +
        "OSWLATENCY|timestamp=bad|source=node1|target=node2|address=10.0.0.12|size=8192|status=timeout|rtt_ms=\n")
    log, warnings, err := Parser{}.Parse(input)
    if err != nil || len(log.Samples) != 1 || len(warnings) != 1 {
        t.Fatalf("log=%+v warnings=%v err=%v", log, warnings, err)
    }
    if log.Samples[0].Size != 56 || log.Samples[0].RTTMS != 0.183 {
        t.Fatalf("sample=%+v", log.Samples[0])
    }
}
```

- [ ] **Step 2: 运行测试确认红灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./pkg/latency -count=1`

Expected: FAIL，包或 `Parser` 尚不存在。

- [ ] **Step 3: 写最小模型和解析器**

```go
type Sample struct {
    Timestamp time.Time
    Source, Target, Address string
    Size int
    Status string
    RTTMS float64
}

type Log struct { Samples []Sample }

type Parser struct{}

func (Parser) Parse(r io.Reader) (*Log, []error, error)
func (Parser) ParseFile(path string) (*Log, []error, error)
```

解析器只处理 `OSWLATENCY|` 行；支持时间布局 `2006-01-02T15:04:05-0700` 和 RFC3339；`ok` 必须包含非负 `rtt_ms`；未知状态、字段缺失和数值错误作为逐行 warning，不能丢弃同文件有效样本。

- [ ] **Step 4: 运行测试确认绿灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./pkg/latency -count=1`

Expected: PASS。

### Task 3: 延迟统计和报告模块

**Files:**
- Create: `internal/modules/latency/models.go`
- Create: `internal/modules/latency/analyzer.go`
- Create: `internal/modules/latency/report.go`
- Create: `internal/modules/latency/latency_test.go`

**Interfaces:**
- Consumes: `*pkg/latency.Log`。
- Produces: `NewAnalyzer().AnalyzeRange(*ParsedData, time.Time, time.Time) (*Analysis, error)` 和 `BuildReport(*Analysis) (*report.Report, error)`。

- [ ] **Step 1: 写统计和大包失败报告测试**

```go
func TestAnalyzeAndReportComparesSmallAndLargePackets(t *testing.T) {
    at := time.Date(2026, 7, 10, 12, 0, 0, 0, time.FixedZone("CST", 8*3600))
    log := &legacylatency.Log{Samples: []legacylatency.Sample{
        {Timestamp: at, Source: "node1", Target: "node2", Address: "10.0.0.12", Size: 56, Status: "ok", RTTMS: 0.2},
        {Timestamp: at.Add(time.Second), Source: "node1", Target: "node2", Address: "10.0.0.12", Size: 56, Status: "ok", RTTMS: 0.4},
        {Timestamp: at.Add(2*time.Second), Source: "node1", Target: "node2", Address: "10.0.0.12", Size: 8192, Status: "timeout"},
    }}
    analysis, err := NewAnalyzer().AnalyzeRange(&ParsedData{Log: log}, at, at.Add(2*time.Second))
    if err != nil { t.Fatal(err) }
    report, err := BuildReport(analysis)
    if err != nil { t.Fatal(err) }
    if analysis.Paths[0].P95MS != 0.4 || len(report.Findings) != 1 || report.Findings[0].Title != "分片大报文链路故障" {
        t.Fatalf("analysis=%+v findings=%+v", analysis, report.Findings)
    }
}
```

- [ ] **Step 2: 运行测试确认红灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./internal/modules/latency -count=1`

Expected: FAIL，latency 模块尚不存在。

- [ ] **Step 3: 实现最近秩百分位和报告表**

```go
func percentile(values []float64, p float64) float64 {
    sorted := append([]float64(nil), values...)
    sort.Float64s(sorted)
    rank := int(math.Ceil(p*float64(len(sorted)))) - 1
    if rank < 0 { rank = 0 }
    return sorted[rank]
}
```

`Analysis` 必须按 `source/target/address/size` 生成 `PathStats`，并按 `source/target/address` 生成 8192 相对 56 的 `Comparison`。报告包含唯一原始样本表 `latency`、汇总表 `latency_summary`、对比表 `latency_comparison`；小包有成功样本而大包成功数为 0 时生成“分片大报文链路故障”。

- [ ] **Step 4: 运行模块测试确认绿灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./internal/modules/latency -count=1`

Expected: PASS。

### Task 4: 文件类型、bundle 和模块注册

**Files:**
- Modify: `internal/modules/module.go`
- Modify: `internal/core/types.go`
- Modify: `internal/core/types_test.go`
- Modify: `internal/app/builtin_modules.go`
- Modify: `internal/app/registry_test.go`

**Interfaces:**
- Produces: `modules.ModuleLatency`、`core.FileTypeLatency`、`core.AnalysisBundle.Latency` 和内置 `latencyRunner`。
- Consumes: Task 3 的 `latency.NewAnalyzer` 与 `latency.BuildReport`。

- [ ] **Step 1: 扩展失败测试**

```go
func TestDetectLatencyFileType(t *testing.T) {
    got, ok := DetectFileType("node1_latency_26.07.10.1200.dat")
    if !ok || got != FileTypeLatency { t.Fatalf("got=%q ok=%v", got, ok) }
}
```

并把内置模块期望顺序扩展为：`iostat, meminfo, top, latency`。

- [ ] **Step 2: 运行测试确认红灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./internal/core ./internal/app -count=1`

Expected: FAIL，`FileTypeLatency` 或 `ModuleLatency` 未定义。

- [ ] **Step 3: 最小注册实现**

```go
const ModuleLatency ModuleName = "latency"
const FileTypeLatency FileType = "latency"

type AnalysisBundle struct {
    Hostname string
    IOStat *legacyiostat.IOStatLog
    Meminfo *legacymeminfo.MemInfoLog
    Top *legacytop.TopLog
    Latency *legacylatency.Log
}
```

`latencyRunner.Run` 必须拒绝空 bundle，并将 `req.TimeRange` 原样传给 Task 3 分析器。

- [ ] **Step 4: 运行测试确认绿灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./internal/core ./internal/app -count=1`

Expected: PASS。

### Task 5: Processor 扫描、合并和输出接入

**Files:**
- Modify: `pkg/processor/processor.go`
- Modify: `pkg/processor/processor_test.go`
- Modify: `pkg/processor/ai_bundle.go`
- Create: `pkg/processor/analyzer_latency.go`
- Create: `pkg/processor/analyzer_latency_test.go`

**Interfaces:**
- Consumes: `core.FileTypeLatency`、`*pkg/latency.Log`、`internal/modules/latency.BuildReport`。
- Produces: OSWbb 归档根目录自动扫描普通和 gzip latency 文件；report/csv/json/html 输出。

- [ ] **Step 1: 写目录端到端失败测试**

```go
func TestProcessDirectoryAnalyzesLatencyArchive(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "node1_latency_26.07.10.1200.dat")
    content := "OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=node1|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.183\n"
    if err := os.WriteFile(path, []byte(content), 0o644); err != nil { t.Fatal(err) }
    stdout := captureStdout(t, func() {
        if err := NewFileProcessor().ProcessDirectory(dir, "", "", false, outputFormatReport, time.FixedZone("CST", 8*3600), AIConfig{}); err != nil { t.Fatal(err) }
    })
    if !strings.Contains(stdout, "OSWbb Analyse Report - latency") { t.Fatalf("stdout=%s", stdout) }
}
```

- [ ] **Step 2: 运行测试确认红灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./pkg/processor -run Latency -count=1`

Expected: FAIL，目录扫描忽略 latency 文件或 bundle 不含 latency。

- [ ] **Step 3: 接入扫描和 bundle**

将 latency 文件切片贯穿 `scanDirectory`、`classifyLogFiles`、`processSingleFiles`、`processMergedFiles`、`groupFilesByHost`；在 `analysisBundle` 中加入 `Latency` 和 `LatencyFiles`；新增 `mergeLatencyFiles`，把逐行 warning 加入 `ParseErrs`；扩展 `hasData`、`coreBundle` 和 bundle 时间范围。

- [ ] **Step 4: 接入统一输出**

```go
func analyzeLatencyLog(log *legacylatency.Log, opts analysisOptions) error {
    start, end, usedDefault, err := resolveTimeRange(log, opts.startTimeStr, opts.endTimeStr, opts.location)
    if err != nil { return err }
    printTimeRangeNotice(opts.rangeScope, usedDefault, start, end)
    report, err := opts.buildLatencyReport(log, start, end)
    if err != nil { return err }
    if opts.outputFormat == outputFormatReport {
        formatter, _ := internaloutput.NewFormatter(internaloutput.FormatText)
        data, err := formatter.Format(report)
        if err != nil { return err }
        return opts.outputSink.Write(context.Background(), internaloutput.OutputRequest{Format: internaloutput.FormatText, Data: data, ToStdout: true})
    }
    export := report
    if opts.outputFormat == "csv" || opts.outputFormat == "ml" {
        export = latencyRawTableReport(report)
    }
    return writeReportExportWithMessage(analysisOutputFilename("latency", opts.hostname, outputFileExt(opts.outputFormat)), "latency", opts.outputFormat, export, opts.outputSink)
}
```

`executeBundle` 在现有三个模块之后调用 latency 分析。CSV/ML 只导出 `latency` 原始样本表；JSON 和 HTML 保留完整汇总及对比表。

- [ ] **Step 5: 运行 processor 测试确认绿灯**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./pkg/processor -run Latency -count=1`

Expected: PASS。

### Task 6: 文档、全量回归和本地验收

**Files:**
- Modify: `README.md`
- Modify: `release/README.md`

**Interfaces:**
- Produces: 部署、三节点配置、归档验证和分析命令。

- [ ] **Step 1: 更新使用说明**

README 必须给出：补丁应用命令、`latencysub.sh` 权限、每节点两个对端配置、重启 OSWbb、检查 `archive/oswlatency`、运行 `./oswbb-analyse -f /path/to/archive -o html`，并明确 8192 在 MTU 1500 下是分片测试。

- [ ] **Step 2: 运行格式与针对性测试**

Run: `gofmt -w pkg/latency internal/modules/latency pkg/processor/analyzer_latency.go pkg/processor/analyzer_latency_test.go`

Run: `sh scripts/test_oswbb_latency_collector.sh`

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./pkg/latency ./internal/modules/latency ./internal/core ./internal/app ./pkg/processor -count=1`

Expected: 全部 PASS。

- [ ] **Step 3: 运行全量测试和构建**

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./... -count=1`

Expected: PASS，0 个失败。

Run: `GOCACHE=/private/tmp/oswbb-ay-go-build go build ./...`

Expected: PASS，退出码 0。

- [ ] **Step 4: 完成本地需求审计**

逐项确认：56/8192 命令、8192 无 `-M do`、OSWatcher 原生调度、小时压缩、FM 保留、六条有方向链路配置方式、结构化记录、gzip 扫描、report/csv/json/html、P50/P95/P99 和大小包对比均有文件或测试证据。

- [ ] **Step 5: 三节点实机验收**

在获得三个节点地址和 OSWbb 路径后部署，连续观察至少三个采集周期，验证六条有方向链路的 56/8192 记录、现有模块持续采集、小时压缩和保留清理，再使用 `oswbb-analyse` 分析真实归档。没有当前三节点证据时不得宣称完整目标已完成。
