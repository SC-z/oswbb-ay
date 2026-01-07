# OSWbb Analyse

这是一个高效的 Oracle OSWatcher (OSWbb) 日志分析工具。它能够解析 `iostat`、`meminfo` 和 `top` 日志，生成详细的性能分析报告、交互式图表或原始数据导出，帮助 DBA 和系统管理员快速定位性能瓶颈。

## 功能特性

*   **全方位日志支持**:
    *   **iostat**: 分析磁盘 I/O 性能，自动计算 IOPS、吞吐量、延迟，并检测异常点。
    *   **meminfo**: 分析内存使用趋势，识别内存泄漏风险、Swap 激增、Slab 异常等。
    *   **top**: 分析系统负载 (Load Average)、CPU 使用率分布（User/Sys/Idle/Wait）及进程状态。
*   **智能处理**:
    *   **自动扫描**: 支持扫描目录，递归查找并识别日志类型。
    *   **自动解压**: 能够直接处理 `.gz` 压缩的归档日志。
    *   **自动合并**: 智能识别主机名，将同一主机的多个时间段日志文件合并分析。
*   **多样化输出**:
    *   **Report (默认)**: 包含统计摘要、趋势分析、异常告警的纯文本报告。
    *   **HTML**: 生成基于 ECharts 的单文件交互式图表报告，零依赖，便于分享。
    *   **CSV**: 导出标准 CSV 数据，方便导入 Excel 进行透视分析。
    *   **JSON**: 导出结构化数据，易于集成到其他监控系统。
*   **灵活过滤**:
    *   支持通过 `-start` 和 `-end` 参数指定精确的时间范围进行分析。

## 快速开始

### 编译

确保本地已安装 Go 环境 (推荐 1.18+)。

```bash
# 克隆项目
git clone https://github.com/your-repo/oswbb-analyse.git
cd oswbb-analyse

# 编译
go build -o osw-analyse main.go
```

### 使用示例

#### 1. 生成交互式图表报告 (推荐)

分析指定目录下的所有日志，并生成 HTML 图表：

```bash
./osw-analyse -f /path/to/oswbb/archive -o html
```
> 输出结果将是一个 `.html` 文件，直接用浏览器打开即可查看 Load、CPU、Memory、IO 的趋势图。

#### 2. 快速健康检查

使用默认的报告模式，快速查看系统概况和潜在异常：

```bash
./osw-analyse -f /path/to/oswbb/archive/oswtop
```

#### 3. 导出数据进行二次分析

将日志导出为 CSV 格式：

```bash
./osw-analyse -f /path/to/oswbb/archive/oswiostat -o csv
```

#### 4. 分析特定故障时间段

```bash
./osw-analyse -f /path/to/oswbb/archive -start "2025-12-17 09:00:00" -end "2025-12-17 10:00:00"
```

## 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `-f` | - | **(必选)** 日志文件路径或目录 | - |
| `-o` | - | 输出格式: `report`, `html`, `csv`, `json`, `ml` | `report` |
| `-start` | - | 分析开始时间 (格式: `YYYY-MM-DD HH:mm:ss`) | - |
| `-end` | - | 分析结束时间 (格式: `YYYY-MM-DD HH:mm:ss`) | - |
| `-s` | - | 单文件模式 (不按主机合并，逐个文件分析) | `false` |

## 异常检测逻辑

工具内置了多种启发式规则来自动发现潜在问题：
*   **I/O**: 检测读写延迟突增 (Z-Score/MAD 算法)、队列堆积。
*   **内存**: 检测可用内存骤降、匿名页持续增长 (泄漏)、Swap 频繁交换。
*   **CPU**: 检测 CPU 饱和 (Idle 低)、I/O 等待过高 (Wait 高)。
