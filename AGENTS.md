# Repository Guidelines

## 项目结构与模块组织
入口是 `main.go`，负责把 CLI 参数接入 analyzer。核心逻辑在 `pkg/`，按领域划分：
- `pkg/iostat`、`pkg/meminfo`、`pkg/top`：OSWatcher 日志解析与指标计算。
- `pkg/processor`：编排流程、时间过滤、analyzer glue。
- `pkg/output`：report writers（`report`、`html`、`csv`、`json`）。
- `pkg/common`：共享 types 与 helpers。
测试与代码同目录，放在 `pkg/**/_test.go`。示例输入和产物位于 `archive/`、`test_log/`、`oswbb.tar.gz`、`*.html`，视为 fixtures，不是源码。

## 构建、测试与本地开发命令
使用 Go 1.23+（参考 `go.mod` toolchain）。
- `go build -o osw-analyse .`：编译 CLI。
- `go run . -f /path/to/oswbb/archive -o html`：本地分析并生成 HTML report。
- `go test ./...`：运行全量测试。
- `go test ./pkg/iostat -run TestName`：运行指定测试。

## 编码风格与命名规范
遵循 Go 标准格式化；建议 `go fmt ./...`（或 `gofmt -w`）。文件名使用小写与下划线（如 `analyzer_top.go`）。命名遵循 Go 规范：导出标识符用 `CamelCase`，非导出用 `lowerCamel`。解析包内函数保持小而专注，输出格式集中在 `pkg/output`。

## 测试指南
测试基于 Go `testing` 包。测试文件命名为 `*_test.go`，测试函数命名为 `TestXxx`。修改解析逻辑、异常检测阈值或输出格式时应补充/更新测试。优先使用确定性输入（固定时间戳、小型 fixtures）保持稳定性。

## 提交与 PR 指南
近期提交多为简短、描述性消息（常见中文），不要求固定前缀；建议保持动词导向，例如“添加 HTML 输出”。PR 建议包含：
- 行为变更摘要。
- 验证命令示例（如 `go test ./...`、`go run . -f ...`）。
- 若 report 渲染有变化，附示例输出或截图。

## 安全与数据处理
OSWatcher 日志可能包含敏感主机信息。避免提交真实客户日志，新增测试数据请优先使用脱敏或合成 fixtures。

## 对话沟通要求
- **必须使用中文回复**（技术术语可保留英文）
- 禁止使用emjoy。
- 遵循了DRY原则
  - 提高代码可读性
  - 减少重复代码
