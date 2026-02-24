# Global Architecture Spec

> 本文档由 modular-spec-skill 自动生成  
> 用于描述系统整体架构、模块职责划分及其协作关系  
> 目标读者：项目开发者 / 维护者 / Reviewer / 新接手成员

---

## 1. 项目背景与目标（Context & Goals）

### 1.1 项目背景
- 项目解决的核心问题：离线解析 Oracle OSWatcher(OSWbb) 日志，生成报告与结构化数据输出。
- 当前所处阶段：功能成型期（已有 iostat/meminfo/top 解析与多格式输出）。
- 主要使用场景与用户类型：DBA/运维人员本地快速分析性能瓶颈。

### 1.2 设计目标
- 系统级核心目标：
  - 可离线运行、零外部依赖（除可选 `gzip` 与 HTML 中的 ECharts CDN）。
  - 支持多日志类型解析并统一输出。
  - 支持按时间范围过滤并提供异常检测信息。
- 明确非目标（Non-Goals）：
  - 不提供在线服务或持久化数据库。
  - 不保证对所有 OSWatcher 变体格式的完整兼容，仅覆盖当前解析器支持的格式。

---

## 2. 系统整体架构概览（High-Level Architecture）

### 2.1 架构风格
- 架构类型：单体 CLI，模块化包结构。
- 关键设计思想：
  - 解析与输出解耦（`pkg/output` 统一输出接口）。
  - 日志类型分域（`iostat/meminfo/top` 各自解析与数据结构）。
  - 处理流程集中在 `pkg/processor`。

### 2.2 架构分层
```text
[ CLI 入口 main.go ]
        ↓
[ 处理编排 processor ]
        ↓
[ 解析模块 iostat/meminfo/top ]
        ↓
[ 输出模块 output ]
```

---

## 3. 模块全景视图（Module Landscape）

### 3.1 模块列表

| 模块名 | 类型 | 核心职责 | 依赖方向 |
|------|------|----------|----------|
| cli(main.go) | 接口层 | 解析 CLI 参数并触发处理 | → processor |
| processor | 核心模块 | 文件扫描、合并、时间范围解析、报告生成 | → iostat/meminfo/top/output/common |
| iostat | 解析模块 | 解析 iostat 日志与指标计算 | → common |
| meminfo | 解析模块 | 解析 meminfo 日志与指标计算 | → common |
| top | 解析模块 | 解析 top 日志与指标抽取 | → common |
| output | 支撑模块 | 输出格式化（csv/json/html）与数据转换 | → iostat/meminfo/top |
| common | 基础模块 | 通用结构与统计工具 | → (无) |

### 3.2 模块关系总览
- 主流程从 `main.go` 进入 `processor`，由其调用各解析模块并输出结果。
- `processor` 是唯一的流程编排核心，其他模块仅提供解析或输出能力。
- `output` 依赖解析模块的结构体，但不反向依赖 `processor`。

---

## 4. 核心数据与控制流（Global Flow）

### 4.1 主流程说明
1. CLI 解析参数（输入路径、时间范围、输出格式等）。
2. `processor` 判断路径类型，扫描目录并按日志类型分组。
3. 可选解压 `.gz`，再重新扫描。
4. 解析单文件或按主机名合并分析。
5. `processor` 在 report 模式直接打印；在导出模式交由 `output` 写文件。

### 4.2 关键数据对象
- `IOStatLog` / `MemInfoLog` / `TopLog`：解析后的时间序列数据。
- `TimeValueList` / `TrendAnomaly`：趋势与异常分析的通用结构。
- `*RawMetrics`：输出层的统一行式数据格式。

---

## 5. 模块边界与职责原则（Boundary & Responsibility）

### 5.1 模块划分原则
- 按日志类型分包；按输出格式分包；编排逻辑集中处理。
- 避免输出模块直接读取文件或执行分析逻辑。

### 5.2 边界约束
- `processor` 不应解析具体文件格式细节（交给解析模块）。
- `iostat/meminfo/top` 不应关心输出格式。

---

## 6. 关键设计决策（Key Design Decisions）

- 决策 1：采用 CLI 单体而非服务化
  - 背景：目标用户以离线分析为主。
  - 取舍：牺牲在线能力，换取部署简单与可移植性。

- 决策 2：输出层统一接口
  - 背景：需要多格式输出。
  - 取舍：增加一层转换，但保证格式扩展一致性。

---

## 7. 演进方向与系统风险（Evolution & Risks）

### 7.1 当前已知风险
- iostat/top 格式兼容性依赖字符串解析，存在版本差异风险。
- `gzip` 解压使用外部命令，运行环境缺失时会失败。
- HTML 输出依赖 CDN，离线环境会丢失图表渲染能力。

### 7.2 演进建议
- 为解析器补充更严格的格式检测与兼容策略。
- 增加本地静态资源模式或离线包以替代 CDN。
- 抽象统一的日志解析接口，便于扩展新类型。

---

## 8. 与模块 Spec 的关系说明

- 本文档为全局视角。
- 每个模块详细设计与流程，见 `spec-docs/modules/<module-name>.md`。
- 架构级变更需同步更新模块 Spec。

---

## 9. 阅读与维护约定（Usage & Maintenance）

- 新成员建议阅读顺序：
  1. 本 Global Spec
  2. `processor` 与 `output`
  3. 各解析模块 `iostat/meminfo/top`
- 更新触发：新增/移除模块、流程级变更、输出策略变化。
