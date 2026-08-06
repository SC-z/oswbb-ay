# OSWbb 小包/大包 ping 原始结果采集实施计划

> 范围：只采集并保存 `ping` 原始输出，不解析和检测输出数据。

**目标：** 保持 OSWbb 主循环、快照周期、小时归档、压缩和保留清理机制不变，增加 `-s 56` 与 `-s 8192` 两种探测。

**实现方式：** 对 OSWatcher 7.3.3 提供最小补丁，由主循环异步调用独立 `latencysub.sh`。脚本读取每节点两个对端，写探测上下文和原始 `ping` 标准输出/错误输出。

**约束：** 不增加 RTT 解析、状态判断、丢包统计、离线分析、守护进程、cron、`fping` 或第三方依赖；8192 字节探测不使用 `-M do`。

---

## 任务 1：固定原始输出契约

**文件：** `scripts/test_oswbb_latency_collector.sh`

1. 在临时 `PATH` 中提供假的 `ping`。
2. 模拟成功、无响应和命令错误三类原始文本。
3. 验证每个目标都执行 `-s 56` 和 `-s 8192`。
4. 验证输出保留原始文本，并明确不存在 `status=` 和 `rtt_ms=`。
5. 验证非零退出码不阻止后续探测，退出时锁文件被清理。
6. 模拟三节点连续三个周期，验证 6 条有方向链路的两种包长结果均持续追加。

## 任务 2：实现最小采集脚本

**文件：** `release/oswbb-latency/latencysub.sh`

1. 接收一个小时归档文件路径。
2. 从 `oswlatency.conf` 读取 `目标名称 IPv4地址`。
3. 对每个有效目标依次执行：

```sh
ping -n -c 1 -W 1 -s 56 TARGET
ping -n -c 1 -W 1 -s 8192 TARGET
```

4. 每次命令前写入 `OSWLATENCY target=... address=... size=...`。
5. 使用追加重定向保存 `ping` 的标准输出和标准错误，不读取、不匹配、不转换其内容。
6. 配置错误写简单文本；使用 trap 确保退出时清理锁。

## 任务 3：接入 OSWatcher 原架构

**文件：**

- `release/oswbb-latency/OSWatcher-latency.patch`
- `release/oswbb-latency/oswlatency.conf.example`

补丁完成以下最小接入：

1. 检查 Linux 环境是否存在 `ping`。
2. 创建 `archive/oswlatency`。
3. 按 OSWbb 当前快照周期启动 `latencysub.sh`。
4. 使用 `latencylock.file` 避免跨周期重入。
5. 小时切换时沿用原压缩设置。
6. 由 `OSWatcherFM.sh` 按 `archiveInterval` 清理历史文件。

## 任务 4：收敛代码和文档范围

**文件：**

- 删除 `pkg/latency/types.go`
- 删除 `pkg/latency/parser.go`
- 删除 `pkg/latency/parser_test.go`
- 更新 `docs/superpowers/specs/2026-07-10-oswbb-latency-monitor-design.md`
- 更新 `release/oswbb-latency/README.md`

删除已不需要的 Go 解析器。文档只描述采集和部署，不承诺 `oswbb-analyse`、RTT 汇总、丢包率、百分位或告警。

## 任务 5：本地验证

执行：

```sh
sh -n release/oswbb-latency/latencysub.sh scripts/test_oswbb_latency_collector.sh
sh scripts/test_oswbb_latency_collector.sh
GOCACHE=/private/tmp/oswbb-ay-go-build go test ./... -count=1
GOCACHE=/private/tmp/oswbb-ay-go-build go build ./...
git diff --check
```

通过标准：shell 测试覆盖原始输出契约，仓库 Go 测试和构建无回归，补丁可应用到仓库内保存的 OSWbb 7.3.3 原始脚本。

## 任务 6：三节点现场验证

获得三个节点的地址、登录方式和 OSWbb 安装路径后部署。至少观察三个采集周期，检查：

1. 每个节点每轮对两个对端分别产生 56/8192 两组原始输出。
2. 6 条有方向链路都有数据。
3. `ping` 失败文本可见，且后续探测仍继续。
4. OSWbb 原有采集类型持续工作。
5. 小时切换压缩和历史文件清理正常。

没有三节点现场证据时，只能声明本地实现和测试完成，不能声明部署验收完成。
