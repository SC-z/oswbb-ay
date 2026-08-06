# OSWbb Analyse

[English](README.md)

`oswbb-analyse` 是一个离线分析工具，用于分析 **Oracle OSWatcher / OSWbb** 生成的 archive 日志。它将 OSWbb 的 `iostat`、`meminfo`、`top` 和 `mpstat` 日志转换为可复核的诊断结论，以及文本、CSV、JSON 或 HTML 报告，帮助 DBA 和 Linux 运维人员定位性能问题。

> 本项目只分析 OSWbb 的输出，**不是** Oracle OSWbb 本体；不包含、分发、修改或安装 Oracle 的 OSWbb 脚本与二进制文件。请通过 Oracle 支持的渠道自行获取并运行 OSWbb，再将其 archive 目录传给本工具。本项目与 Oracle 没有隶属或授权关系。

## 分析范围

- **iostat**：IOPS、吞吐量、延迟、队列深度、利用率和延迟异常候选。
- **meminfo**：可用内存、匿名页增长、Swap、提交内存压力、Slab、Dirty 和 Writeback 信号。
- **top**：负载、CPU user/system/idle/iowait/steal、进程状态及代表进程候选。
- **mpstat**：读取 CPU 核数，用于对 `top` 的 load 与运行队列信号进行按核归一化。

工具会递归识别兼容的 OSWbb archive 目录，读取 `.gz` 归档时不会改写原始日志，并按主机合并相邻时间段数据。

## 快速开始

要求：Go 1.23 或更高版本；项目的 `go.mod` 指定了实际使用的精确工具链。

```bash
git clone https://github.com/SC-z/oswbb-ay.git
cd oswbb-ay

# 构建稳定、可复现的规则版分析器。
make build

# 分析 OSWbb archive 根目录。
./oswbb-analyse -f /path/to/oswbb/archive
```

规则版不依赖模型运行时，是需要可复现运维结论时的默认选择。

## 常用命令

```bash
# 生成交互式 HTML 报告。
./oswbb-analyse -f /path/to/oswbb/archive -o html

# 导出 iostat 的解析数据。
./oswbb-analyse -f /path/to/oswbb/archive/oswiostat -o csv

# 限定已知故障时间窗口。
./oswbb-analyse -f /path/to/oswbb/archive \
  -start "2025-12-17 09:00:00" \
  -end "2025-12-17 10:00:00"

# 使用 TOML 覆盖分析阈值。
./oswbb-analyse -f /path/to/oswbb/archive -config configs/default.toml
```

`-start` 和 `-end` 必须同时指定；两者都不指定时，工具会分析每份日志中可用的完整时间范围。

## 输出格式

| 格式 | 用途 |
| --- | --- |
| `report` | 默认终端报告，包含诊断结论和支撑细节。 |
| `csv` | 用于二次分析的表格化原始及派生指标。 |
| `json` | 用于系统集成的结构化输出。 |
| `html` | 交互式报告。ECharts 通过 CDN 加载；完全离线环境请使用 `report`、`csv` 或 `json`。 |
| `ml` | 规则版中为兼容 CSV 导出；AI 版中为本地模型分析流程。 |

输出文件名包含模块名、可用时的主机名和高精度时间戳，避免多主机或同秒任务互相覆盖。

## 可选的本地 AI 分析

AI 入口与默认规则版分离，避免给规则版引入本地模型依赖：

```bash
make build-ai

./oswbb-analyse-ai -f /path/to/oswbb/archive \
  --ai-runtime-path /opt/llama.cpp/llama-cli \
  --ai-model-path /opt/models/Qwen3-0.6B-Q8_0.gguf \
  --ai-timeout 180s
```

AI 版默认使用 `-o ml`：先写入面向模型的 CSV，再按原始行顺序交给本地配置的运行时。运行时不可用或输出校验失败时，工具会说明回退原因并保留规则诊断结果。本仓库不要求使用云端模型服务。

## 配置与测试

- [`configs/default.toml`](configs/default.toml) 记录默认阈值。
- `make test` 运行 Go 测试套件。
- 少数回归测试可使用体积较大的本地真实 OSWbb archive：样本存在时执行，不存在的干净检出中会跳过；已跟踪的合成测试始终执行。

## 范围与数据处理

OSWbb archive 可能包含主机名、进程信息和其他运维敏感数据。请不要提交客户 archive 或分析报告。本工具只分析现有 archive，不会启动、停止、配置或修改 OSWbb 采集。

标准库运维分析器及 archive 覆盖检查流程见 [`skills/oswbb-ops`](skills/oswbb-ops/)。
