# OSWbb 三节点大包/小包延迟采集部署手册

## 1. 部署目标

在三台 Linux 节点现有 OSWbb 7.3.3 中增加长期 `ping` 原始结果采集：

- 每个节点探测另外两个节点；
- 每个目标分别执行 `ping -s 56` 和 `ping -s 8192`；
- 沿用 OSWbb 的采集周期、小时文件、压缩和保留清理机制；
- 只保存 `ping` 标准输出和标准错误，不解析 RTT、不判断状态、不统计丢包。

MTU 1500 下，8192 字节 ICMP 负载会发生 IPv4 分片。本扩展不使用 `-M do`。

## 2. 部署信息表

部署前填写真实信息。管理地址和被 `ping` 的业务地址可以不同。

| 节点 | SSH 管理地址 | ping 源/目标网络地址 | OSWbb 安装目录 | 原启动命令 |
| --- | --- | --- | --- | --- |
| node1 | `<NODE1_MGMT_IP>` | `<NODE1_PING_IP>` | `<NODE1_OSWBB_HOME>` | `<NODE1_START_CMD>` |
| node2 | `<NODE2_MGMT_IP>` | `<NODE2_PING_IP>` | `<NODE2_OSWBB_HOME>` | `<NODE2_START_CMD>` |
| node3 | `<NODE3_MGMT_IP>` | `<NODE3_PING_IP>` | `<NODE3_OSWBB_HOME>` | `<NODE3_START_CMD>` |

`<NODE*_PING_IP>` 必须替换为真实 IPv4 地址，不能保留尖括号占位符。

## 3. 部署前检查

三台节点都以 OSWbb 运行用户执行以下检查：

```sh
OSWBB_HOME=/path/to/oswbb
cd "$OSWBB_HOME"
uname -s
grep '^version=' OSWatcher.sh
command -v ping
test -f startOSWbb.sh
test -f stopOSWbb.sh
test -f OSWatcher.sh
test -f OSWatcherFM.sh
ps -ef | grep '[O]SWatcher.sh'
```

预期：

- `uname -s` 输出 `Linux`；
- OSWatcher 版本为 `v7.3.3`；
- 能找到 `ping`；
- 记录当前 `OSWatcher.sh` 的完整启动参数，后续必须原样恢复。

从每台节点分别手工确认另外两个业务地址可执行两种包长：

```sh
PEER_PING_IP=192.0.2.12
ping -n -c 1 -W 1 -s 56 "$PEER_PING_IP"
ping -n -c 1 -W 1 -s 8192 "$PEER_PING_IP"
```

`192.0.2.12` 是文档示例地址，执行前替换为当前节点的真实对端业务地址。此步骤只确认命令可运行并观察原始输出，不根据输出生成检测结论。

## 4. 分发部署文件

从代码机将发布目录传到三台节点。以下命令中的用户、地址和路径需要替换：

```sh
SSH_USER=oswbb
NODE1_MGMT_IP=192.0.2.11
NODE2_MGMT_IP=192.0.2.12
NODE3_MGMT_IP=192.0.2.13
scp -r release/oswbb-latency "$SSH_USER@$NODE1_MGMT_IP:/tmp/"
scp -r release/oswbb-latency "$SSH_USER@$NODE2_MGMT_IP:/tmp/"
scp -r release/oswbb-latency "$SSH_USER@$NODE3_MGMT_IP:/tmp/"
```

上述 `192.0.2.0/24` 地址仅用于文档示例，执行前替换为真实 SSH 管理地址。

每台节点应得到：

```text
/tmp/oswbb-latency/OSWatcher-latency.patch
/tmp/oswbb-latency/latencysub.sh
/tmp/oswbb-latency/oswlatency.conf.example
```

## 5. 节点配置

每台节点的 `oswlatency.conf` 只填写另外两个节点。

node1：

```text
node2 <NODE2_PING_IP>
node3 <NODE3_PING_IP>
```

node2：

```text
node1 <NODE1_PING_IP>
node3 <NODE3_PING_IP>
```

node3：

```text
node1 <NODE1_PING_IP>
node2 <NODE2_PING_IP>
```

格式固定为 `目标名称 IPv4地址`。空行和以 `#` 开头的行会被忽略。

## 6. 单节点安装步骤

按照 node1、node2、node3 的顺序逐台安装。每完成一台先验证，再继续下一台。

### 6.1 停止并备份

```sh
OSWBB_HOME=/path/to/oswbb
cd "$OSWBB_HOME"
./stopOSWbb.sh

backup_dir="backup-latency-$(date +%Y%m%d%H%M%S)"
mkdir "$backup_dir"
cp -p OSWatcher.sh OSWatcherFM.sh "$backup_dir/"
test ! -e latencysub.sh || cp -p latencysub.sh "$backup_dir/"
test ! -e oswlatency.conf || cp -p oswlatency.conf "$backup_dir/"
echo "$backup_dir"
```

保存输出的备份目录名。确认 OSWatcher 已停止：

```sh
ps -ef | grep '[O]SWatcher.sh'
```

预期无输出。

### 6.2 检查并应用补丁

```sh
OSWBB_HOME=/path/to/oswbb
cd "$OSWBB_HOME"
patch --dry-run -p1 < /tmp/oswbb-latency/OSWatcher-latency.patch
patch -p1 < /tmp/oswbb-latency/OSWatcher-latency.patch
```

`--dry-run` 必须成功。若提示补丁已经应用或上下文不匹配，不要强制执行，应先核对 OSWbb 版本和当前脚本内容。

### 6.3 安装脚本和配置

```sh
OSWBB_HOME=/path/to/oswbb
cd "$OSWBB_HOME"
install -m 0755 /tmp/oswbb-latency/latencysub.sh ./latencysub.sh
install -m 0644 /tmp/oswbb-latency/oswlatency.conf.example ./oswlatency.conf
vi ./oswlatency.conf
```

按照第 5 节写入当前节点对应的两个真实对端地址，然后检查：

```sh
awk 'NF && $1 !~ /^#/ {print}' oswlatency.conf
sh -n OSWatcher.sh OSWatcherFM.sh latencysub.sh
grep -nE 'latencysub\.sh|oswlatency' OSWatcher.sh OSWatcherFM.sh
```

配置应只有两个有效目标，三个脚本的语法检查必须成功。

### 6.4 启动 OSWbb

使用部署前记录的原启动命令，不要擅自修改采集周期、保留小时、压缩工具或归档目录。例如：

```sh
OSWBB_HOME=/path/to/oswbb
cd "$OSWBB_HOME"
./startOSWbb.sh 30 48 gzip
```

若原来没有参数，则继续执行：

```sh
./startOSWbb.sh
```

确认主进程存在：

```sh
ps -ef | grep '[O]SWatcher.sh'
```

## 7. 单节点采集验证

默认归档目录为 `<OSWBB_HOME>/archive`。如果原启动命令设置了第 4 个参数或 `OSWBB_ARCHIVE_DEST`，使用实际归档目录。

```sh
OSWBB_HOME=/path/to/oswbb
archive_dir="$OSWBB_HOME/archive"
ls -ld "$archive_dir/oswlatency"
ls -ltr "$archive_dir/oswlatency"
latest=$(ls -t "$archive_dir"/oswlatency/*_latency_*.dat | head -1)
echo "$latest"
tail -n 100 "$latest"
```

每个采集周期应追加 4 组结果：两个目标乘以两种包长。文件内容结构如下：

```text
zzz ***OSWLATENCY target=node2 address=<NODE2_PING_IP> size=56
<ping 原始输出>
zzz ***OSWLATENCY target=node2 address=<NODE2_PING_IP> size=8192
<ping 原始输出>
```

检查目标和包长标记：

```sh
grep 'OSWLATENCY target=' "$latest"
```

连续观察至少三个原采集周期。每台节点每周期应增加 4 个标记，三个周期应增加 12 个标记。标记后面的内容必须是 `ping` 原始输出，不应出现扩展生成的 `status=` 或 `rtt_ms=` 字段。

## 8. 三节点验收

三台节点都部署后，确认以下 6 条有方向链路均同时出现 `size=56` 和 `size=8192`：

```text
node1 -> node2
node1 -> node3
node2 -> node1
node2 -> node3
node3 -> node1
node3 -> node2
```

验收项：

- 三台 OSWatcher 主进程持续运行；
- 每台节点每周期产生 4 组原始 `ping` 结果；
- 连续至少三个周期无采集缺口；
- 单次 `ping` 超时或报错后，后续目标和包长仍继续采集；
- `archive/oswlatency` 小时文件持续追加；
- 小时切换后，上一小时文件按照 OSWbb 原压缩参数处理；
- 历史文件按照原 `archiveInterval` 保留；
- OSWbb 原有 vmstat、iostat、netstat 等采集不受影响。

本扩展不对原始输出做延迟阈值、丢包率或异常检测。

## 9. 常见问题

### 9.1 没有 `oswlatency` 目录

检查 `uname -s` 是否为 Linux、系统能否找到 `ping`、补丁是否已进入当前运行的 `OSWatcher.sh`。

### 9.2 文件中出现配置错误

检查 `oswlatency.conf` 是否存在、OSWbb 运行用户是否可读、每行是否严格包含名称和数字 IPv4 地址。

### 9.3 锁文件长期存在

先检查是否仍有 `latencysub.sh` 进程：

```sh
ps -ef | grep '[l]atencysub.sh'
```

只有确认没有采集进程后，才可删除 `<OSWBB_HOME>/locks/latencylock.file` 并重新观察。

### 9.4 8192 字节没有响应

保留并上报该次 `ping` 原始输出。MTU 1500 下该报文需要 IPv4 分片，但本扩展不自动判断失败原因。

## 10. 回滚

在单个节点执行：

```sh
OSWBB_HOME=/path/to/oswbb
cd "$OSWBB_HOME"
./stopOSWbb.sh
patch --dry-run -R -p1 < /tmp/oswbb-latency/OSWatcher-latency.patch
patch -R -p1 < /tmp/oswbb-latency/OSWatcher-latency.patch
sh -n OSWatcher.sh OSWatcherFM.sh
./startOSWbb.sh 30 48 gzip
```

最后一条启动命令只是示例，必须替换为部署前记录的原启动命令。反向补丁已经停止调用延迟采集器，默认保留 `latencysub.sh` 和 `oswlatency.conf`，避免误删升级前已有文件。若反向补丁检查失败，使用第 6.1 节保存的备份恢复 `OSWatcher.sh` 和 `OSWatcherFM.sh`，不要强制反向应用补丁。回滚后确认原 OSWbb 采集恢复正常。
