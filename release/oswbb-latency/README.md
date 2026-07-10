# OSWbb 延迟采集扩展

该扩展保持 OSWbb 原有采集架构，为 Linux 节点增加 `oswlatency` 小时归档：

- 小包：ICMP 负载 56 字节；
- 大包：ICMP 负载 8192 字节；
- 每个 OSWbb 快照周期，对配置中的每个对端各探测一次；
- 复用 OSWatcher 主循环、锁、小时压缩和 `OSWatcherFM.sh` 保留清理。

MTU 1500 环境下，8192 字节探测会发生 IPv4 分片，监控的是分片大报文的往返延迟，不是单个巨型帧。因此命令不使用 `-M do`。

## 安装

在 OSWbb 安装目录执行：

```sh
patch -p1 < /path/to/release/oswbb-latency/OSWatcher-latency.patch
install -m 0755 /path/to/release/oswbb-latency/latencysub.sh ./latencysub.sh
cp /path/to/release/oswbb-latency/oswlatency.conf.example ./oswlatency.conf
```

编辑 `oswlatency.conf`，每个节点只填写另外两个节点：

```text
node2 10.0.0.12
node3 10.0.0.13
```

格式为 `节点名 IPv4地址`。空行和以 `#` 开头的行会被忽略。

## 启动与验证

按照原方式重启 OSWbb，然后检查：

```sh
sh -n OSWatcher.sh OSWatcherFM.sh latencysub.sh
ls -l archive/oswlatency
grep 'OSWLATENCY|' archive/oswlatency/*_latency_*.dat
```

每个对端应同时出现 `size=56` 和 `size=8192`。状态值：

- `ok`：收到响应并解析出 RTT；
- `timeout`：`ping` 返回 1，没有收到响应；
- `ping_error`：`ping` 命令或目标错误；
- `config_error`：配置文件缺失、为空或配置行无效。

原始 `ping` 输出与结构化记录保存在同一小时文件中。上一小时文件继续按 OSWbb 原配置压缩，`OSWatcherFM.sh` 按 `archiveInterval` 清理历史文件。

## 三节点配置

三台节点分别配置两个远端地址，得到以下 6 条有方向链路：

```text
node1 -> node2
node1 -> node3
node2 -> node1
node2 -> node3
node3 -> node1
node3 -> node2
```

## 卸载补丁

停止 OSWbb 后，在安装目录执行：

```sh
patch -R -p1 < /path/to/release/oswbb-latency/OSWatcher-latency.patch
rm -f latencysub.sh oswlatency.conf locks/latencylock.file
```
