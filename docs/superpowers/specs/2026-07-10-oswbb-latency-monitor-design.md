# OSWbb 小包/大包 ping 原始结果采集设计

## 1. 目标

在不改变 OSWbb 原有监控采集架构的前提下，为三节点 Linux 集群增加两种报文大小的 ICMP 探测：

- 小包：`ping -s 56`；
- 大包：`ping -s 8192`；
- 每个 OSWbb 快照周期，每个节点分别探测另外两个节点；
- 采集结果进入 OSWbb 小时归档，并复用原有压缩和历史文件清理机制。

本功能只保存 `ping` 的原始输出，不解析 RTT、不计算丢包率、不判断成功或失败、不产生告警，也不接入 `oswbb-analyse`。

## 2. 报文含义

`ping -s` 指定的是 ICMP 数据负载长度，不包含 ICMP 头和 IP 头。命令固定为：

```sh
ping -n -c 1 -W 1 -s 56 TARGET
ping -n -c 1 -W 1 -s 8192 TARGET
```

在 MTU 1500 的 IPv4 网络中，8192 字节负载会被分片。本功能观察的是分片大报文的实际 `ping` 结果，不是 8192 字节的单个以太网帧，也不是 PMTU 探测，因此不增加 `-M do`。

## 3. 架构设计

采集链路继续沿用 OSWbb：

```text
OSWatcher.sh 主循环
  -> 按原 snapshotInterval 触发
  -> latencylock.file 防止上一轮未结束时重复启动
  -> latencysub.sh 执行两种包长的 ping
  -> archive/oswlatency/<主机名>_latency_<小时>
  -> 原有小时压缩
  -> OSWatcherFM.sh 按 archiveInterval 清理
```

不增加守护进程、cron、数据库、`fping` 或第三方依赖。OSWatcher 只增加一个采集类型，具体命令放在独立的 `latencysub.sh` 中，与现有子采集脚本模式一致。

## 4. 配置

OSWbb 安装目录新增 `oswlatency.conf`。每行格式为 `目标名称 IPv4地址`，空行和以 `#` 开头的行忽略：

```text
node2 10.0.0.12
node3 10.0.0.13
```

三节点分别配置另外两个节点，从而形成 6 条有方向链路：

```text
node1 -> node2    node1 -> node3
node2 -> node1    node2 -> node3
node3 -> node1    node3 -> node2
```

## 5. 采集与输出

每轮采集先写 OSWbb 风格时间头。每次执行 `ping` 前写一行上下文标记，随后把该命令的标准输出和标准错误原样追加到同一文件：

```text
zzz ***Fri Jul 10 12:00:00 CST 2026
zzz ***OSWLATENCY target=node2 address=10.0.0.12 size=56
PING 10.0.0.12 (10.0.0.12) 56(84) bytes of data.
64 bytes from 10.0.0.12: icmp_seq=1 ttl=64 time=0.183 ms
...
zzz ***OSWLATENCY target=node2 address=10.0.0.12 size=8192
PING 10.0.0.12 (10.0.0.12) 8192(8220) bytes of data.
...
```

上下文标记仅用于区分目标和包长，不包含 `status`、`rtt_ms` 或任何从 `ping` 输出推导出的字段。超时、不可达和命令错误均保留 `ping` 自己输出的文本；单次 `ping` 返回非零不会阻止后续目标和包长继续采集。

配置文件缺失或配置行非法时，脚本写入 `OSWLATENCY config error` 文本，并继续处理其他有效配置。这只用于暴露采集配置问题，不分析网络结果。

## 6. 资源与并发

每个节点每轮执行 4 次 `ping`，三节点合计执行 12 次。每次只发送一个请求，按节点串行执行。OSWbb 锁文件确保上一轮尚未结束时不重复启动采集脚本；脚本退出时清理锁文件。

## 7. 验证方案

自动测试使用假的 `ping` 命令验证：

- 两个目标分别执行 56 和 8192 字节探测；
- 模拟三节点连续三个采集周期，验证 6 条有方向链路均持续追加两种包长的结果；
- 成功、超时及命令错误文本均原样进入归档；
- 输出中不存在 `status=` 和 `rtt_ms=`；
- 一次探测失败后仍继续执行其他探测；
- 配置错误可见且锁文件始终清理；
- OSWatcher 补丁可应用，修改后的脚本通过 shell 语法检查。

三节点现场验收至少观察三个采集周期，确认每个节点每轮产生 4 组原始结果、6 条有方向链路均有 56/8192 输出，并确认现有 OSWbb 采集、小时压缩及历史清理未受影响。

## 8. 验收边界

本次交付完成标准是“持续获得两种包长的原始 `ping` 输出”。小包和大包延迟差异、丢包、抖动、百分位或异常原因均由使用者根据原始结果另行判断，不属于本功能。
