# OSWbb 小包/大包 ping 原始结果采集扩展

该扩展保持 OSWbb 原有采集架构，为 Linux 节点增加 `oswlatency` 小时归档：

- 小包使用 ICMP 负载 56 字节；
- 大包使用 ICMP 负载 8192 字节；
- 每个 OSWbb 快照周期，对配置中的每个对端各探测一次；
- 只保存 `ping` 原始输出，不解析 RTT、不判断状态、不统计丢包；
- 复用 OSWatcher 主循环、锁、小时压缩和 `OSWatcherFM.sh` 保留清理。

MTU 1500 环境下，8192 字节探测会发生 IPv4 分片，观察的是分片大报文的实际 `ping` 结果，不是单个巨型帧。因此命令不使用 `-M do`。

三节点逐台部署、验证和回滚步骤见 [DEPLOYMENT.md](DEPLOYMENT.md)。

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

## 输出

每次探测先输出目标和包长标记，随后原样追加 `ping` 的标准输出和标准错误：

```text
zzz ***OSWLATENCY target=node2 address=10.0.0.12 size=56
PING 10.0.0.12 (10.0.0.12) 56(84) bytes of data.
64 bytes from 10.0.0.12: icmp_seq=1 ttl=64 time=0.183 ms
...
zzz ***OSWLATENCY target=node2 address=10.0.0.12 size=8192
PING 10.0.0.12 (10.0.0.12) 8192(8220) bytes of data.
...
```

扩展不会输出 `status=` 或 `rtt_ms=`，也不会根据 `ping` 返回值生成检测结论。即使一次 `ping` 超时或报错，脚本仍继续执行其他目标和包长。

## 启动与验证

按照原方式重启 OSWbb，然后检查：

```sh
sh -n OSWatcher.sh OSWatcherFM.sh latencysub.sh
ls -l archive/oswlatency
grep 'OSWLATENCY target=' archive/oswlatency/*_latency_*.dat
tail -n 80 archive/oswlatency/*_latency_*.dat
```

每个对端应同时出现 `size=56` 和 `size=8192`，对应标记下面应为该次 `ping` 的原始结果。上一小时文件继续按 OSWbb 原配置压缩，`OSWatcherFM.sh` 按 `archiveInterval` 清理历史文件。

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
