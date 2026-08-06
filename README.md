# OSWbb Analyse

这是一个高效的 Oracle OSWatcher (OSWbb) 日志分析工具。它能够解析 `iostat`、`meminfo` 和 `top` 日志，并读取 `mpstat` 的 CPU 核数作为辅助元数据，生成性能分析报告、交互式图表或原始数据导出，帮助 DBA 和系统管理员快速定位性能瓶颈。

## 功能特性

*   **全方位日志支持**:
    *   **iostat**: 分析磁盘 I/O 性能，自动计算 IOPS、吞吐量、延迟，并检测异常点。
    *   **meminfo**: 分析内存使用趋势，识别内存泄漏风险、Swap 激增、Slab 异常等。
    *   **top**: 分析系统负载 (Load Average)、CPU 使用率分布（User/Sys/Idle/Wait）及进程状态。
    *   **mpstat**: 作为辅助元数据读取目标主机 CPU 核数，用于 top 的 Load/Running 队列按核数归一化判断。
*   **智能处理**:
    *   **自动扫描**: 支持扫描目录，递归查找并识别日志类型。
    *   **临时解压**: 能够直接处理 `.gz` 压缩的归档日志，分析时解压到临时目录，不删除或改写原始归档。
    *   **自动合并**: 智能识别主机名，将同一主机的多个时间段日志文件合并分析。
*   **多样化输出**:
    *   **Report (默认)**: 包含统计摘要、趋势分析、异常告警的纯文本报告。
    *   **HTML**: 生成基于 ECharts 的交互式图表报告；当前页面通过 CDN 加载 ECharts，离线环境建议优先使用 `report/csv/json`。
    *   **CSV**: 导出标准 CSV 数据，方便导入 Excel 进行透视分析。
    *   **JSON**: 导出结构化数据，易于集成到其他监控系统。
*   **规则版与 AI 版隔离**:
    *   `oswbb-analyse` 是默认规则版，不依赖本地模型，输出稳定、可复现的规则诊断和数据导出。
    *   规则版构建依赖不链接 `pkg/localai`，不会初始化本地 AI runtime。
    *   `oswbb-analyse-ai` 是本地 AI 辅助诊断版，默认进入 `ml` 分析模式。
    *   AI 版会先保存带主机名和高精度时间戳的 `ml` CSV 文件，再按原始行顺序分批输入本地模型，终端打印 AI 分析结果。
    *   meminfo 的 `ml` CSV 会包含 `slab`、`*_pct` 和 `*_delta` 派生列，作为表格字段结构的一部分交给模型分析。
    *   规则版中 `-o ml` 保持兼容行为，仍按 CSV 导出格式化数据。
    *   `ml` 模式下模型不可用或输出无法校验时，会打印 AI fallback 原因和规则异常摘要；非 AI 输出格式仍按各自格式生成。
*   **灵活过滤**:
    *   支持通过 `-start` 和 `-end` 参数指定精确的时间范围进行分析。

## 快速开始

### 编译

确保本地已安装 Go 环境 (要求 Go 1.23+；当前 `go.mod` 指定 toolchain `go1.25.5`)。

```bash
# 进入源码目录
cd oswbb-analyse

# 编译规则版
go build -o oswbb-analyse main.go

# 编译本地 AI 版
go build -o oswbb-analyse-ai ./cmd/oswbb-analyse-ai
```

### 使用示例

#### 1. 生成交互式图表报告 (推荐)

分析指定目录下的所有日志，并生成 HTML 图表：

```bash
./oswbb-analyse -f /path/to/oswbb/archive -o html
```
> 按日志模块生成 `iostat_*.html`、`meminfo_*.html`、`top_*.html` 等文件；文件名包含主机名和高精度时间戳，避免多主机同秒覆盖。

#### 2. 快速健康检查

使用默认的报告模式，快速查看系统概况和潜在异常：

```bash
./oswbb-analyse -f /path/to/oswbb/archive
```
> 建议优先传 OSWbb archive 根目录。这样工具可以同时读取 `oswtop` 与兄弟目录中的 `oswmpstat`，用目标主机 CPU 核数降低 top load/running 误判。

#### 3. 导出数据进行二次分析

将日志导出为 CSV 格式：

```bash
./oswbb-analyse -f /path/to/oswbb/archive/oswiostat -o csv
```

#### 4. 分析特定故障时间段

```bash
./oswbb-analyse -f /path/to/oswbb/archive -start "2025-12-17 09:00:00" -end "2025-12-17 10:00:00"
```
> `-start` 和 `-end` 必须同时指定；只指定其中一个会报错，避免误以为已经限定故障窗口但实际分析全量数据。

#### 5. 使用本地 AI 辅助诊断版

```bash
./oswbb-analyse-ai -f /path/to/oswbb/archive \
  --ai-runtime-path /opt/llama.cpp/llama-cli \
  --ai-model-path /opt/models/Qwen3-0.6B-Q8_0.gguf \
  --ai-timeout 180s
```

> AI 版未显式指定 `-o` 时，默认等价于 `-o ml`：先生成本地 `ml` CSV 文件，再按原始行顺序分批交给本地模型，终端打印 AI 诊断结果。
> AI 版也接受旧命令中的 `--ai-local` 参数作为兼容 no-op；在 `oswbb-analyse-ai` 中本地 AI 始终启用。
> AI 输入不是 report 文本，而是先落盘的 `ml` CSV 数据：包含 CSV 文件路径、表头、单位说明以及当前批次在完整 CSV 中的行号范围。
> meminfo 输入会携带 `mem_available_pct`、`swap_used_pct`、`slab_pct`、`s_unreclaim_pct` 以及关键 `*_delta` 变化量，这些字段会在字段结构说明中告诉模型。
> 若显式指定 `-o report`、`-o json`、`-o html` 或 `-o csv`，程序会尊重指定格式；需要稳定的“CSV 表格输入模型分析”时使用默认模式或显式 `-o ml`。
> 默认只打印 AI 诊断结果；调试本地模型输入、prompt 和 GPU/CPU 决策时，加 `--ai-debug`。
> `--ai-timeout` 控制单次本地 runtime 调用超时；CPU 或大上下文调试时可调大，例如 `180s`、`5m`。
> 缺失时，程序会同时给出官方 runtime 与模型下载链接。

显式使用 `ml` 模式：

```bash
./oswbb-analyse-ai -f /path/to/oswbb/archive/oswmeminfo \
  --ai-runtime-path /opt/llama.cpp/llama-cli \
  --ai-model-path /opt/models/Qwen3-0.6B-Q8_0.gguf \
  -o ml
```

兼容旧的格式化数据导出：

```bash
./oswbb-analyse -f /path/to/oswbb/archive/oswmeminfo -o ml
```

> 在规则版中，`-o ml` 仍映射为 CSV 输出。

## 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `-f` | - | **(必选)** 日志文件路径或目录 | - |
| `-o` | - | 输出格式: `report`, `html`, `csv`, `json`, `ml`；规则版中 `ml` 映射为 CSV，AI 版未显式指定时默认 `ml` | 规则版 `report`；AI 版 `ml` |
| `-start` | - | 分析开始时间 (格式: `YYYY-MM-DD HH:mm:ss`)；必须与 `-end` 同时指定 | - |
| `-end` | - | 分析结束时间 (格式: `YYYY-MM-DD HH:mm:ss`)；必须与 `-start` 同时指定 | - |
| `-s` | - | 单文件模式 (不按主机合并，逐个文件分析) | `false` |
| `--ai-local` | - | 仅 AI 版兼容参数；`oswbb-analyse-ai` 始终启用本地 AI，保留此参数用于兼容旧命令 | `false` |
| `--ai-debug` | - | 仅 AI 版支持；打印输入给模型的 ML 数据、prompt 构造过程和 GPU/CPU runtime 决策 | `false` |
| `--ai-timeout` | - | 仅 AI 版支持；本地 AI 单次 runtime 调用超时时间，例如 `60s`、`180s`、`5m` | 使用内置默认值 |
| `--ai-model-path` | - | 仅 AI 版支持；指定 GGUF 模型路径，覆盖默认查找规则 | 自动查找 |
| `--ai-runtime-path` | - | 仅 AI 版支持；指定 `llama.cpp` 的 `llama-cli` 路径，覆盖默认查找规则 | 自动查找 |

## 本地模型打包说明

*   Linux amd64 发行包可以随包携带默认模型与 `llama.cpp` runtime。
*   其他平台保留同样的参数接口，但推荐手动下载模型与 runtime 后通过 `--ai-model-path` / `--ai-runtime-path` 指定。
*   默认模型文件名为 `Qwen3-0.6B-Q8_0.gguf`，程序会优先从可执行文件旁边的 `models/`、`runtime/`、`bin/` 目录以及当前 `PATH` 中查找。
*   `--ai-runtime-path` 可以指定 `llama-cli`；如果同目录存在 `llama-completion`，程序会优先使用 `llama-completion` 的单轮模式执行模型分析。
*   本地模型默认先使用 llama.cpp 的 GPU/加速设备自动策略运行；如果加速路径执行失败，会自动用 `--device none -ngl 0 --no-op-offload --no-kv-offload --fit off` 回退到 CPU。
*   官方下载链接：
    *   runtime: `https://github.com/ggml-org/llama.cpp/releases`
    *   model: `https://huggingface.co/Qwen/Qwen3-0.6B-GGUF`

## 异常检测逻辑

工具内置了多种启发式规则来自动发现潜在问题：
*   **I/O**: 检测读写延迟突增 (Z-Score/MAD 算法)、队列堆积。
    *   多块物理盘在同一时间出现同方向高延迟，且有队列或 CPU iowait 佐证时，会额外输出系统级 I/O 压力或共享存储路径线索；单点低 IOPS 慢请求只作为候选线索。
*   **内存**: 检测可用内存骤降、匿名页持续增长、Swap 增长、Slab/SUnreclaim 异常、Dirty/Writeback 积压、Committed_AS 接近或超过 CommitLimit。
    *   `MemAvailable` 当前仍低或窗口内多点持续低时作为风险信号；单点短时低水位且当前已恢复时保留为候选线索，报告同时展示最低点和当前值。
    *   匿名页增长只有在伴随可用内存下降、Swap 增长或 Commit 压力时才作为风险信号；无压力佐证的小比例/短时增长只作为候选线索，避免把健康主机上的内存波动误报为泄漏。
    *   Swap、Committed_AS、Slab/SUnreclaim、Dirty/Writeback 如果只是历史峰值且当前已恢复，会保留为候选线索；当前仍触发阈值时才作为风险信号。
*   **CPU**: 检测 CPU 饱和 (Idle 低)、I/O 等待过高 (Wait 高)、CPU Steal 偏高。
    *   当同主机目录中存在 `oswmpstat` 时，会从 `(N CPU)` 读取目标主机核数，并用 `load/core`、`running/core` 判断 top 的 Load/Running 队列是否接近 CPU 容量。
    *   缺少 `oswmpstat` 或无法识别核数时，不使用当前运行机器的 CPU 数，top 的 load/runnable 规则保持兼容旧行为。
    *   top 的 `iowait` 高如果同采样存在 D 状态或运行队列佐证，会作为风险信号；持续 `iowait` 高但缺少同采样佐证时保留为候选线索，需结合 iostat 延迟/队列确认。
    *   `load` 高只有在同高负载窗口出现低 idle、iowait、运行队列或 D 状态佐证时才生成风险/线索；高 idle 场景不会把 load 直接定性为 CPU 饱和。单点 `steal` 尖峰只作为候选线索，持续或多点 `steal` 才作为风险信号。
