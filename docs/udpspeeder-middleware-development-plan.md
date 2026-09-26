# UDPspeeder 连接中间层开发计划

## 1. 文档目的

本文规划在 Link42 的受管 WireGuard 连接中增加 `UDPspeeder` 中间层。目标是利用 Forward Error Correction（FEC）降低随机丢包和部分突发丢包对 WireGuard UDP 报文的影响，并同时支持普通 Linux 节点和 OpenWrt 节点。

本文是开发和测试计划，不代表功能已经实现。实现过程中必须保持现有 `udp2raw`、`mimic`、GRE 和普通 WireGuard 流程兼容。

## 2. 需求边界

### 2.1 第一阶段必须支持

- 在受管 WireGuard 连接创建/编辑时选择 `UDPspeeder`。
- Agent 自动安装匹配 CPU 架构的 UDPspeeder 二进制。
- Linux systemd 节点使用 systemd 管理 UDPspeeder client/server。
- OpenWrt 节点使用 procd 管理 UDPspeeder client/server。
- WireGuard 一端作为 UDPspeeder client，另一端作为 UDPspeeder server。
- server 将解包后的 UDP 转发到服务端 WireGuard 本地监听端口。
- client 将 WireGuard 的 Peer Endpoint 指向本机 UDPspeeder 监听端口。
- 支持 IPv4 和 IPv6 的外层 UDP 地址。
- 支持 FEC 数据包数、冗余包数、FEC 模式、超时和 MTU 等核心参数。
- 连接停止、启动、编辑、删除、改名和 Agent 重启后可以恢复或清理中间层实例。
- 旧版本 Agent 不支持时，主控明确显示能力不足，不创建无法执行的任务。

### 2.2 第一阶段不做

- 不把 UDPspeeder 实现成 WireGuard 本身的替代协议。
- 不修改现有 WireGuard 密钥、Peer 加密和 AllowedIPs 语义。
- 不把 UDPspeeder 的简单 XOR 当作安全加密；WireGuard 仍是唯一的安全边界。
- 不支持导入扫描已有 UDPspeeder 配置。
- 不支持域名作为 UDPspeeder 外层地址；第一阶段使用 IPv4/IPv6 字面量，避免 Agent 内部 DNS 和地址族不确定性。
- 不与 `udp2raw`、`mimic` 同时启用。
- 不在第一阶段实现 UDPspeeder 与 udp2raw 的串联。
- 不在第一阶段暴露 UDPspeeder 全部实验参数，避免用户组合出不可用的 MTU/FEC 配置。

第二阶段再评估 `UDPspeeder + udp2raw` 串联。串联必须先明确链路顺序、双端端口模型和故障回滚，不直接复用第一阶段的 endpoint 覆盖逻辑。

## 3. 当前代码基线

当前连接中间层已经具备以下能力：

- 受管连接配置保存在 WireGuard 接口 `extras.middleware` 中。
- 主控通过 `normalize_middleware_config()` 规范化中间层配置。
- 主控通过 `apply_*_to_peers()` 覆盖最终 WireGuard Peer Endpoint。
- 主控通过 `enqueue_middleware_tasks()` 创建独立中间层任务。
- Agent 在 `middleware.py` 中实现安装、apply、start、stop、status、delete。
- Linux 通过 systemd 模板管理实例，OpenWrt 通过 procd init 脚本管理实例。
- Agent 注册时上报平台、服务管理器和中间层能力，主控用任务版本和能力门禁拒绝不支持的节点。

实现 UDPspeeder 时应复用这些边界，但使用独立的任务名、配置目录、资产下载接口和服务名，不能把新逻辑塞进 udp2raw 的参数解析中。

## 4. 数据流和角色模型

### 4.1 标准链路

```text
本端 WireGuard
    -> 本端 UDPspeeder client 监听端口
    -> UDP 网络
    -> 对端 UDPspeeder server 监听端口
    -> 对端 WireGuard ListenPort
```

本端 WireGuard Peer Endpoint 指向本机 UDPspeeder client 的监听地址，一般是 `127.0.0.1:<client_port>`。对端 UDPspeeder server 解包后，将原始 WireGuard UDP 转发到对端本机的 `127.0.0.1:<wireguard_listen_port>`。

### 4.2 角色约束

- `client` 负责主动连接 server，可位于 NAT 后。
- `server` 必须有可被 client 访问的外层地址和监听端口。
- server 侧必须配置 WireGuard `ListenPort`，否则无法固定 `server_forward_port`。
- client 侧 WireGuard `ListenPort` 可以为空；如果填写，必须与 client UDPspeeder 本地监听端口不同。
- 一条受管连接只允许一端 server、另一端 client，第一阶段不做双向对称模式。
- WireGuard 的 server/client 角色与业务流向不一定相同，应由中间层配置明确指定。

### 4.3 NAT 约束

- client 可以在普通 NAT 后主动访问 server。
- server 必须具备公网地址、端口映射或其它可达入口。
- UDPspeeder 不会自动打洞，也不会改变 WireGuard 的 NAT 行为。
- server 外层地址如果是云厂商 EIP/NAT 地址，必须区分 `server_connect_host` 和 `server_listen_host`：前者是 client 访问的地址，后者必须是 server 机器实际可绑定的地址。
- 不承诺两个被动节点在没有任何入口的情况下建立连接。

## 5. 配置模型

第一阶段继续使用现有 `extras.middleware` JSON，不新增数据库表，降低迁移风险。后续中间层种类稳定后再考虑独立表。

建议结构：

```json
{
  "type": "udpspeeder",
  "enabled": true,
  "server_side": "peer",
  "server_listen_host": "0.0.0.0",
  "server_connect_host": "203.0.113.20",
  "server_listen_port": 24000,
  "server_forward_host": "127.0.0.1",
  "server_forward_port": 24001,
  "client_listen_host": "127.0.0.1",
  "client_listen_port": 24002,
  "fec_data": 10,
  "fec_redundancy": 5,
  "fec_timeout_ms": 8,
  "fec_mode": 0,
  "fec_mtu": 1400,
  "fec_queue_len": 200,
  "decode_buffer": 2000,
  "delay_capacity": 0,
  "socket_buffer_kib": 1024,
  "disable_obscure": false,
  "disable_checksum": false
}
```

### 5.1 字段规则

| 字段 | 规则 | 默认值 |
| --- | --- | --- |
| `type` | 固定为 `udpspeeder` | - |
| `server_side` | 只能是 `local` 或 `peer` | `peer` |
| `server_listen_host` | IPv4/IPv6 字面量，可为通配地址 | `0.0.0.0` |
| `server_connect_host` | client 可访问的 server IP 字面量 | 无 |
| `server_listen_port` | 1-65535，server 必填 | 无 |
| `server_forward_host` | server 本地转发地址，必须是 IP 字面量 | `127.0.0.1` |
| `server_forward_port` | 对端 WireGuard ListenPort，1-65535 | 自动取 server WG 端口 |
| `client_listen_host` | client 本地监听地址，通常为 `127.0.0.1` | `127.0.0.1` |
| `client_listen_port` | 1-65535，必须填写 | 无 |
| `fec_data` | FEC 原始数据包数量，1-255；与 `fec_redundancy` 之和不超过 255 | `10` |
| `fec_redundancy` | FEC 冗余包数量，0-254；与 `fec_data` 之和不超过 255 | `5` |
| `fec_timeout_ms` | 0-1000 毫秒 | `8` |
| `fec_mode` | 只允许 `0` 或 `1` | `0` |
| `fec_mtu` | 100-2000，用于承载 MTU 1280 的 IPv6 WireGuard 加密报文 | `1400` |
| `fec_queue_len` | 1-10000；mode 0 下设置为 1 可尽快发送 | `200` |
| `decode_buffer` | 300-20000 | `2000` |
| `socket_buffer_kib` | 10-10240；UDP socket 接收/发送缓冲目标，单位 KiB | `4096` |
| `delay_capacity` | 0-20000，0 表示由 UDPspeeder 默认处理 | `0` |
| `socket_buffer_kib` | 64-10240 | `1024` |
| `disable_obscure` | 是否关闭非安全性的报文混淆 | `false` |
| `disable_checksum` | 是否关闭 UDPspeeder 自身校验 | `false` |

`fec_data` 和 `fec_redundancy` 在 Agent 中渲染为 `-f <data>:<redundancy>`。第一阶段不接受用户直接填写原始命令行，所有命令参数必须由结构化字段生成。

### 5.2 校验规则

后端必须校验以下内容：

- 两个节点在线，且两端 Agent 都支持 UDPspeeder 任务。
- `server_connect_host`、`server_listen_host`、`server_forward_host`、`client_listen_host` 均为合法 IPv4/IPv6 字面量。
- server 连接地址和监听地址的地址族一致；IPv4/IPv6 不混用。
- 两个节点的 server/client 端口不与本节点 WireGuard ListenPort 冲突。
- server 的 forward port 必须等于 server WireGuard ListenPort，除非明确支持本机额外 UDP 转发；第一阶段不做隐式转发。
- client UDPspeeder 监听端口必须与本地 WireGuard ListenPort 不同。
- `fec_data >= 1`，`fec_redundancy >= 0`，且 `fec_data + fec_redundancy <= 255`。
- `fec_mtu` 不得大于外层路径 MTU 的安全上限；创建时提示用户 WireGuard MTU 需要配合调整。
- `fec_mode=1` 时要求明确填写有效 MTU，并提示该模式对 MTU 更敏感。
- 连接名、实例名、接口名继续使用现有安全字符校验，不能参与 shell 解释。
- 同一节点上的 UDPspeeder 实例名、监听端口和服务单元不能冲突。
- 禁止同时启用 `udp2raw`、`mimic` 和 `udpspeeder`。

## 6. Agent 安装和资产管理

### 6.1 资产来源

- 固定 UDPspeeder 上游仓库和 commit/tag，不在运行时拉取任意 URL。
- 发布包中携带二进制、版本信息和 SHA-256 清单。
- 每个目标平台单独构建，优先使用静态 musl 产物。
- 必须新增 ARM64/musl 原生资产，不能把当前 32 位 `udp2raw_arm` 或旧 ARM 资产冒充 ARM64。

建议资产键：

```text
udpspeeder-x64-static
udpspeeder-arm64-musl
udpspeeder-arm-musl
udpspeeder-mips24kc-le-musl
udpspeeder-mips24kc-be-musl
```

第一阶段至少交付 `x64-static`、`arm64-musl` 和当前实际需要的 OpenWrt 架构。其它架构没有构建产物时，主控必须给出“暂无匹配资产”，不能让 Agent 下载后才失败。

### 6.2 主控资产接口

新增独立接口，不复用 udp2raw 资产路径：

```text
GET /api/agent/plugins/udpspeeder/assets/{asset_name}
```

要求：

- 只允许固定白名单资产名。
- 继续走 Agent token 鉴权豁免规则，但不能扩大到任意文件路径。
- 返回二进制时设置固定 `Content-Length` 和 `Content-Type`。
- 资产清单与校验值由服务端内置或随发布包提供。
- 记录资产版本和请求节点，日志不得打印 token。

### 6.3 Agent 安装任务

复用通用任务名 `middleware.install`，payload 增加明确插件类型：

```json
{
  "plugin": "udpspeeder",
  "asset_version": "<pinned-version>"
}
```

安装流程：

1. 根据 `platform.machine()`、OpenWrt/procd、musl/glibc 选择资产。
2. 检查当前平台是否支持对应服务管理器。
3. 创建 `/etc/link42/middleware/udpspeeder` 配置目录。
4. 下载到同目录临时文件。
5. 校验 SHA-256、文件类型、目标架构和可执行权限。
6. 执行 `udpspeeder --help` 或等价无副作用自检。
7. 原子替换二进制，不覆盖正在使用的临时文件。
8. 写入服务模板或确认 procd 管理脚本可用。
9. 返回资产版本、架构、校验值、服务后端和自检结果。

安装失败时：

- 不删除已存在且可用的旧版本。
- 不创建半成品服务单元。
- 返回明确的 `asset_missing`、`checksum_failed`、`binary_arch_mismatch`、`service_backend_unsupported` 等错误码。
- 主控把安装失败显示为中间层失败，不继续下发 WireGuard Endpoint 覆盖。

### 6.4 Agent 能力

新增任务需求：

```text
middleware.udpspeeder.apply
middleware.udpspeeder.start
middleware.udpspeeder.stop
middleware.udpspeeder.status
middleware.udpspeeder.delete
```

建议新增能力：

```text
middleware.udpspeeder
middleware.udpspeeder.fec
middleware.udpspeeder.systemd
middleware.udpspeeder.openwrt-procd
middleware.install.udpspeeder
```

Agent 只有在平台资产可用、二进制自检通过并且服务后端可用时，才上报运行能力。可安装但尚未安装的节点可以只上报 `middleware.install.udpspeeder`，主控应显示“可安装”，不能显示“已可运行”。

任务最低 Agent 版本必须与实际发布版本同步，避免旧 Agent 上报能力或前端显示可用但执行返回 409。版本更新时同时更新：

- `packages/link42_common/connection_types.py`
- `packages/link42_common/version.py`
- Agent release manifest
- Web/Controller 版本
- 发布脚本和构建产物

## 7. Agent 运行实现

### 7.1 代码组织

新增独立模块：

```text
apps/agent/link42_agent/udpspeeder.py
```

建议函数职责：

```text
detect_udpspeeder_asset()
validate_udpspeeder_payload()
render_udpspeeder_args()
write_udpspeeder_config()
apply_udpspeeder()
start_udpspeeder()
stop_udpspeeder()
status_udpspeeder()
delete_udpspeeder()
install_udpspeeder()
```

每个函数都必须有中文 docstring，参数校验、路径校验、命令生成和服务管理职责分离。不得把新逻辑继续堆入 `middleware.py` 的 udp2raw 分支。

### 7.2 配置文件

每个实例使用独立 JSON 文件：

```text
/etc/link42/middleware/udpspeeder/<instance>.json
```

示例：

```json
{
  "instance": "wg-12-15",
  "mode": "client",
  "listen": "127.0.0.1:24002",
  "remote": "203.0.113.20:24000",
  "fec": "10:5",
  "timeout_ms": 8,
  "fec_mode": 0,
  "mtu": 1250,
  "queue_len": 200,
  "decode_buffer": 2000,
  "delay_capacity": 0,
  "socket_buffer_kib": 1024
}
```

文件写入必须使用临时文件和原子替换，权限不低于 `0600`。虽然配置不包含 WireGuard 私钥，但仍可能包含入口地址、端口和可选密钥，不能用 world-readable 权限保存。

### 7.3 命令生成

client 命令语义：

```text
udpspeeder -c \
  -l 127.0.0.1:24002 \
  -r 203.0.113.20:24000 \
  -f 10:5 \
  --timeout 8 \
  --mode 0 \
  --mtu 1250 \
  -q 200 \
  --decode-buf 2000
```

server 命令语义：

```text
udpspeeder -s \
  -l 0.0.0.0:24000 \
  -r 127.0.0.1:24001 \
  -f 10:5 \
  --timeout 8 \
  --mode 0 \
  --mtu 1250 \
  -q 200 \
  --decode-buf 2000
```

实际执行必须使用参数数组，不得把用户输入拼接成 `eval` 或未经转义的 shell 字符串。服务模板只负责读取已校验的 JSON 配置并调用固定 Agent helper；helper 也必须再次校验实例名和配置路径。

### 7.4 服务后端

Linux systemd：

```text
/etc/systemd/system/link42-udpspeeder-client@.service
/etc/systemd/system/link42-udpspeeder-server@.service
```

要求：

- `ExecStart` 使用正式 Agent/helper 入口，不直接执行源码路径。
- `Restart=on-failure`，但设置重试间隔，避免配置错误时高频重启。
- `User=root` 仅用于需要绑定入口端口的服务，后续可评估降权。
- status 任务同时返回 unit 状态、进程状态、监听地址、资产版本和最近错误摘要。

OpenWrt procd：

- 写入 `/etc/init.d/link42-udpspeeder-<role>-<instance>`。
- 使用 `procd_open_instance`、`procd_set_param command` 和 `respawn`。
- 通过安全的固定配置读取逻辑传递参数，禁止 `eval` 用户输入。
- `enable/start/stop/reload/status` 必须幂等。
- 不自动修改 OpenWrt firewall zone；server 入口需要用户在对应 zone 放行 UDP 端口。

## 8. 主控后端改造

### 8.1 Schema

在 `apps/api/link42_api/schemas.py` 增加 `UdpSpeederMiddlewareConfig`，并在受管连接请求中增加 `udpspeeder` 字段。

保留旧字段：

```text
udp2raw
mimic
```

新旧请求的兼容规则：

- 只有一个中间层字段允许 `enabled=true`。
- 没有启用中间层时，三个字段均可为空或 disabled。
- 读取旧连接时原样返回已有 udp2raw/mimic 配置。
- 更新旧连接时，如果用户不改变中间层，不能重置旧配置。
- 从 udp2raw/mimic 切换到 UDPspeeder 前，必须生成旧中间层 stop/delete 清理任务。

### 8.2 主控服务函数

新增与 udp2raw 对称但独立的函数：

```text
normalize_udpspeeder_config()
validate_udpspeeder_port_conflicts()
require_udpspeeder_supported()
apply_udpspeeder_to_peers()
udpspeeder_endpoint_payloads()
enqueue_udpspeeder_tasks()
```

`apply_udpspeeder_to_peers()` 只覆盖 WireGuard Peer Endpoint，不修改 AllowedIPs、Peer 公钥、Keepalive 或用户自定义配置。

### 8.3 任务依赖和部署顺序

创建或更新连接时必须使用明确的阶段顺序：

1. 校验两端在线、版本、能力、地址族、端口和 MTU。
2. 必要时向两端创建 `middleware.install`。
3. 向两端下发 `middleware.udpspeeder.apply`，只写配置，不启动新服务。
4. 停止旧的 UDPspeeder 实例；如果是首次创建则跳过。
5. 启动两端新的 UDPspeeder 实例。
6. 确认两端服务进入 active/running，失败则停止新实例并保留旧配置/旧 Endpoint。
7. 计算被中间层覆盖后的 WireGuard Peer Endpoint。
8. 下发两端 `wireguard.apply_config`。
9. 启动或重载两端 WireGuard 接口。
10. 查询中间层和 WireGuard 状态，更新端点聚合状态。

如果 Agent 任务系统暂时不支持显式依赖，应由主控按顺序创建任务并在每一阶段检查结果，不能一次性把所有任务入队后假设执行顺序。

### 8.4 失败和回滚

- 任一端安装失败：不修改 WireGuard Endpoint，连接状态为 `failed`，展示具体错误。
- 任一端 apply 失败：不启动另一端新服务，恢复旧服务配置。
- 一端 start 成功、另一端失败：停止已成功端，连接状态为 `failed`，不得停留在 `changing`。
- WireGuard apply 失败：保留已写入的中间层配置以便诊断，但停止中间层并恢复旧 Endpoint。
- 更新 FEC/端口/地址时不能先删除唯一可用的旧实例，至少要保留旧配置的内存快照或备份文件。
- 删除连接时按 stop -> WireGuard stop -> middleware delete -> WireGuard config delete 的顺序执行，并清理改名前的旧实例名。

## 9. 前端改造

### 9.1 入口

在“创建受管连接”协议选择中增加：

```text
WireGuard
GRE
```

中间层选择只在 WireGuard 表单中显示：

```text
无
udp2raw
UDPspeeder
mimic
```

不改变 GRE 表单，也不把 UDPspeeder 误显示为 GRE 的能力。

### 9.2 表单字段

基础字段：

- 中间层类型
- server 所在端
- server 外层连接地址
- server 监听地址
- server 监听端口
- server 转发地址/端口
- client 本地监听地址/端口

FEC 字段：

- 数据包数
- 冗余包数
- FEC 模式
- FEC 等待时间
- FEC MTU
- 编码队列长度
- 解码缓冲区
- 延迟容量

高级字段默认折叠，只显示经过验证的必要参数。页面应实时显示估算冗余比例，例如 `10:5` 约增加 50% 的原始报文冗余，不承诺固定的实际带宽比例。

### 9.3 用户提示

必须明确提示：

- UDPspeeder 会增加带宽和 CPU 消耗。
- FEC 只能恢复一定范围内的丢包，不能解决完全断网或严重拥塞。
- WireGuard MTU 需要结合 FEC MTU 和实际外层路径调整。
- server 入口需要放行 UDP 端口；OpenWrt 不会自动修改 firewall zone。
- UDPspeeder 不提供加密，隧道安全由 WireGuard 提供。
- server 需要可被 client 访问，client 可以位于 NAT 后。

错误提示应使用中文业务文案，不把 Agent 原始 traceback 直接显示给用户。

## 10. 版本、安装和升级策略

### 10.1 版本门禁

实现时统一提升 Agent、Controller、Web 版本，并在任务需求表登记最低 Agent 版本。发布前检查：

- 旧 Agent 仍可运行无中间层连接。
- 旧 Agent 仍可运行已有 udp2raw/mimic 连接。
- 新主控对不支持 UDPspeeder 的节点显示不可用，而不是显示可用后返回 409。
- Agent 升级后能力快照变化会被主控记录。

### 10.2 安装脚本和发布资产

- 发布脚本增加 UDPspeeder 二进制构建、SHA-256 和 manifest 生成。
- Agent 安装脚本本身不直接下载第三方最新版本；由主控资产接口提供固定版本。
- Docker 主控镜像必须包含 UDPspeeder 资产。
- OpenWrt source Agent 包升级后必须仍能下载并执行 UDPspeeder ARM64 资产。
- 发布前检查磁盘空间，构建产物不能把多个历史版本无限打入镜像。

### 10.3 升级中的运行连接

- Agent 自升级不应删除 `/etc/link42/middleware/udpspeeder` 配置。
- 服务重启前先保存当前实例 JSON 和二进制版本信息。
- 新二进制 `--help` 或版本自检失败时保留旧二进制。
- 升级完成后重新上报能力，主控重新计算节点是否可执行任务。

## 11. 测试计划

### 11.1 单元测试

后端：

- Schema 默认值、边界值和非法字段。
- IPv4/IPv6 地址族校验。
- server/client 端口冲突校验。
- FEC 参数到 `-f data:redundancy` 的渲染。
- `fec_mode`、MTU 和超时组合校验。
- middleware 互斥校验。
- Peer Endpoint 覆盖只影响 endpoint，不影响其它 WireGuard 字段。
- 新旧中间层切换时生成正确 stop/delete 任务。
- 离线节点、缺能力节点、低版本 Agent 的稳定错误码。

Agent：

- x64、ARM64、ARM、MIPS 资产选择。
- 资产校验失败和架构不匹配处理。
- JSON 配置原子写入和权限。
- client/server 参数数组渲染。
- 实例名和路径穿越校验。
- systemd/procd 服务命令生成。
- apply/start/stop/delete/status 幂等。
- 服务启动失败时保留错误摘要，不吞掉 stderr。
- OpenWrt 无 systemd 时不调用 systemctl。

### 11.2 Agent 本地集成测试

使用临时目录和临时端口：

- 原生 ARM64 二进制 `--help` 自检。
- IPv4 UDP echo：0% 丢包、10%、20%、30% 丢包。
- IPv6 UDP echo：0% 和至少 20% 丢包。
- FEC `10:3`、`10:5`、`20:10` 对比恢复率。
- 连续突发丢包和随机丢包分别测试。
- 统计回包率、P50/P95 延迟、发送包数、带宽放大比例和 CPU。
- 测试进程退出后服务可重启，重复 apply 不产生重复监听。

### 11.3 Linux 实机测试

使用本机与 `vpstest` 或其它隔离测试节点：

1. 创建普通受管 WireGuard 链路，确认无中间层仍正常。
2. 创建 UDPspeeder IPv4 链路，验证两端服务、WG handshake、隧道 ping。
3. 创建 UDPspeeder IPv6 外层链路，验证 IPv6 endpoint 和隧道内 IPv4/IPv6 流量。
4. 修改 FEC 参数、client/server 端口和外层地址，确认旧实例清理且无残留监听端口。
5. stop/start、Agent 重启、主控刷新和节点重连后验证状态恢复。
6. 删除连接，确认服务、配置、WireGuard 端点和旧改名实例全部清理。
7. 人为制造一端 start 失败，确认连接显示 failed 而不是 changing。

### 11.4 OpenWrt/mrouter 实机测试

只使用专用测试实例、临时端口和临时连接：

- 当前 `mrouter` ARM64 OpenWrt 上验证原生 ARM64/musl 资产。
- 验证 Agent 安装、资产校验、procd enable/start/stop/status/delete。
- OpenWrt 作为 client 和 server 各测试一次。
- 验证 OpenWrt firewall zone 放行要求，Link42 不自动改生产防火墙。
- 验证与 Linux server/client 的混合链路。
- 验证设备重启后的 procd 恢复；若测试需要重启，必须提前确认并使用专用窗口。
- 测试结束执行清理脚本，确认没有残留临时服务、二进制、配置和监听端口。

### 11.5 真实 Link42 流程测试

必须通过主控完整流程，不允许只手工启动 UDPspeeder：

1. 启动临时主控。
2. 注册两个测试 Agent，其中至少一个为 OpenWrt，另一个为 Linux。
3. 在面板创建受管 WireGuard + UDPspeeder。
4. 检查安装任务、apply 任务、start 任务和 WireGuard 任务顺序。
5. 检查面板显示的中间层状态和错误提示。
6. 检查 Endpoint 实际指向本地 client 监听端口。
7. 对端抓包确认 server 监听端口收到 UDPspeeder 外层报文。
8. 对隧道内 IPv4/IPv6 做 ping 和小流量传输。
9. 修改、停止、启动、删除并检查清理结果。
10. 测试失败后关闭临时主控和 Agent，清理全部测试资产。

## 12. 性能和参数验收

默认值不能只依据回环结果。至少使用以下矩阵：

| FEC | 适用场景 | 预期关注点 |
| --- | --- | --- |
| `5:1` | 轻度随机丢包 | 带宽开销较低，恢复能力有限 |
| `10:3` | 常规丢包 | 默认候选，平衡恢复和开销 |
| `10:5` | 中度丢包 | 恢复能力更高，带宽增加明显 |
| `20:10` | 较差链路 | CPU、带宽和延迟上升 |

验收记录必须包含：

- 原始 UDP 和 UDPspeeder 的成功率。
- 单向和双向丢包率。
- 随机丢包和连续突发丢包结果。
- FEC 参数、MTU、WireGuard MTU 和链路实际 MTU。
- mrouter CPU、内存和带宽占用。
- WireGuard handshake 是否因中间层重启而长期失效。

## 13. 日志和可观测性

主控日志：

- 记录 middleware 类型、连接 ID、两端节点、任务 ID、阶段和最终状态。
- 不记录 WireGuard 私钥、Agent token 或中间层敏感配置明文。
- 记录资产选择结果、版本、架构和失败错误码。

Agent 日志：

- INFO 记录安装开始/结束、apply、start、stop、status 和实例名。
- DEBUG 记录参数摘要、不能记录完整可复用密钥。
- 命令失败记录 return code、stderr 摘要和耗时。
- 不能每秒输出高频状态，状态轮询使用 INFO 摘要或 DEBUG 细节。

前端：

- 中间层服务失败显示错误弹窗或错误提示。
- 任务输出仅用于诊断详情，不直接把原始命令和 traceback 放在主流程页面。
- 一端成功、一端失败时显示“单端失败”和失败节点。

## 14. 发布前检查清单

- [ ] `udpspeeder` 任务和能力门禁已加入公共任务需求表。
- [ ] ARM64/musl 原生资产已构建并通过 mrouter 执行检查。
- [ ] 资产 SHA-256、manifest 和发布脚本已更新。
- [ ] Linux systemd 和 OpenWrt procd 运行后端均通过测试。
- [ ] 普通 WireGuard、udp2raw、mimic、GRE 回归测试通过。
- [ ] 受管连接创建、编辑、启动、停止、删除和改名通过。
- [ ] IPv4/IPv6 外层和隧道内流量通过。
- [ ] FEC 参数边界、MTU 和端口冲突校验通过。
- [ ] 一端失败时连接状态为 failed，且不会残留新服务。
- [ ] Agent 升级后配置和服务可恢复。
- [ ] OpenWrt firewall zone 提示清晰，未偷偷修改用户生产防火墙。
- [ ] `pytest`、Agent 编译、前端构建、`compileall` 和 `git diff --check` 通过。
- [ ] 真实 E2E 测试资产已清理，仓库无临时二进制和测试配置。

## 15. 推荐实施顺序

### 阶段 0：构建验证

- 固定 UDPspeeder 上游版本。
- 增加 x64 和 ARM64/musl 构建流程。
- 在本机检查静态链接、架构、SHA-256 和 `--help`。
- 在 mrouter 临时目录验证原生二进制可执行。

### 阶段 1：Agent 能力和安装

- 新增资产清单和下载接口。
- 新增 Agent 资产选择、校验和安装任务。
- 新增 systemd/procd 服务管理骨架。
- 完成 Agent 单测和临时回环测试。

### 阶段 2：Agent 配置和任务

- 新增 `udpspeeder.py`。
- 实现 JSON 配置、参数渲染、apply/start/stop/status/delete。
- 完成服务幂等、失败回滚和日志。

### 阶段 3：主控后端

- 增加 schema、版本能力门禁和配置校验。
- 增加 Endpoint 覆盖、任务生成、旧中间层清理。
- 完成创建/编辑/删除和异常状态聚合。

### 阶段 4：前端

- 增加中间层选项和 FEC 表单。
- 增加动态必填校验、端口冲突提示、MTU/FEC 风险提示。
- 增加服务状态和一端失败展示。

### 阶段 5：双节点真实测试

- Linux-Linux、Linux-OpenWrt、OpenWrt-Linux 三组链路。
- IPv4/IPv6 外层、NAT client、FEC 丢包矩阵和重启恢复。
- 全流程清理和回归。

### 阶段 6：发布和第二阶段评估

- 更新版本号和 Agent 发布资产。
- 发布变更报告和测试报告。
- 根据真实链路数据决定默认 FEC 参数。
- 只有第一阶段稳定后，才评估 UDPspeeder 与 udp2raw 的组合模式。

## 16. 完成判定

该功能只有同时满足以下条件才能发布：

1. 新版 Agent 能在 Linux 和 mrouter 上安装并启动正确架构的 UDPspeeder。
2. 主控能在能力不足、资产缺失、安装失败和一端启动失败时阻止错误的 WireGuard 下发。
3. Link42 创建的连接能通过 UDPspeeder 完成 WireGuard handshake 和 IPv4/IPv6 流量传输。
4. 在约定的丢包测试矩阵中，FEC 恢复率相对裸 UDP 有明确改善，并记录带宽和延迟代价。
5. 旧 WireGuard、udp2raw、mimic、GRE 和 OpenWrt 现有连接无回归。
6. stop/start/delete/升级/回滚后无残留进程、配置、服务和监听端口。
7. 测试、构建、发布和清理流程全部可重复执行。
