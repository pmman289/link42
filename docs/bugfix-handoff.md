# Link42 Bug 修复交接指南

本文给接手修 bug 的 Agent 使用。目标不是重新讲完整产品，而是帮助快速定位问题、理解关键约束，并避免修复时破坏现有设计。

## 当前架构速览

Link42 是“中心主控 + 节点 Agent”的架构：

```text
Browser
  -> React/Vite Web
  -> FastAPI API + SQLite
  <- Agent 主动轮询任务
Node Agent
  -> wg / wg-quick / systemd / OpenRC / OpenWrt UCI
```

核心原则：

- API 不主动 SSH 到节点。
- Agent 主动注册、心跳、轮询任务、上报结果。
- 前端修改的是数据库里的期望状态；真正写节点文件必须通过 Agent 任务。
- WireGuard 配置被建模为点对点虚拟网线：一个接口最多一个有效 Peer。
- 受管节点间连接是双端对象，任何编辑、启动、停止、删除都必须考虑双方。

## 主要代码入口

后端：

```text
apps/api/link42_api/main.py        # API 路由、任务创建、受管连接逻辑
apps/api/link42_api/models.py      # SQLAlchemy 模型
apps/api/link42_api/schemas.py     # Pydantic 请求/响应模型
apps/api/link42_api/database.py    # SQLite 初始化和轻量补列
apps/api/link42_api/wireguard_service.py
                                  # WireGuard 配置渲染、diff、部署 payload
```

Agent：

```text
apps/agent/link42_agent/main.py           # Agent 主循环和任务分发
apps/agent/link42_agent/client.py         # Agent 调用 API
apps/agent/link42_agent/system.py         # WireGuard 文件和状态操作
apps/agent/link42_agent/service_manager.py
                                         # systemd/OpenRC/OpenWrt 后端
apps/agent/link42_agent/middleware.py     # udp2raw 中间层任务
apps/agent/link42_agent/upgrade.py        # Agent 自升级任务
```

前端：

```text
apps/web/src/main.tsx      # 当前主要 UI 和交互逻辑集中在这里
apps/web/src/styles.css    # 样式
```

共享包：

```text
packages/link42_common/security.py
packages/link42_common/version.py
packages/link42_wireguard/parser.py
packages/link42_wireguard/renderer.py
```

测试：

```text
tests/test_point_to_point_rules.py  # 后端规则和业务流测试
tests/test_agent_system.py          # Agent 本机执行逻辑测试
```

## 数据模型理解

### Node

节点代表一台运行 Agent 的机器。重要字段：

```text
endpoint_ips              # 节点可被对端访问的入口地址列表
agent_token_hash
agent_token_value         # 可信面板允许再次查看 token
agent_version
agent_protocol_version
agent_capabilities
agent_platform
agent_update_status
last_seen_at
status
```

节点是否在线不要只看 `status`。后端通常会调用 `refresh_node_runtime_status()`，根据 `last_seen_at` 和 `LINK42_AGENT_OFFLINE_AFTER_SECONDS` 重新判断。

### WireGuardInterface

一个接口等同一根点对点虚拟网线的一端。重要字段：

```text
node_id
name
tunnel_ips
listen_port               # 可为空，WireGuard 支持被动模式
private_key_value
public_key
mtu
table_name                # dn42 场景默认 Table=off
source                    # manual / imported / managed-node
managed
runtime_status
deployed_config           # 成功部署后的配置快照，生成 diff 的基线
extras                    # udp2raw middleware 等扩展信息
```

### WireGuardPeer

当前设计中一个接口只应有一个有效 Peer。`set_unique_peer()` 会替换旧 peer，避免追加多个 Peer。

重要字段：

```text
allowed_ips               # 必须补全，不能遗漏
endpoint_host
endpoint_port
peer_node_id
peer_interface_id
enabled
```

### AgentTask

后端创建任务，Agent 轮询领取。常见状态：

```text
pending
running
succeeded
failed
```

重复点击问题通常要检查是否有幂等逻辑，例如 `enqueue_interface_task_once()` 和 `has_active_interface_task()`。

## 核心流程

### 普通手动连接部署

1. 前端保存接口和 Peer 到数据库。
2. 用户点击生成部署计划。
3. 后端用 `deployed_config` 作为旧配置，用当前期望配置渲染新配置，生成 diff。
4. 用户确认计划。
5. 后端创建 `wireguard.apply_config` 任务。
6. Agent 写入 `/etc/wireguard/<iface>.conf`，必要时备份旧文件，并调用对应 service manager。
7. Agent 上报结果，后端更新 change plan 和 `deployed_config`。

注意：

- 没有 diff 时不能下发任务。
- 私钥和预共享密钥可以在可信面板展示，但不要写进日志或无关错误。

### 导入现有 wg-quick

1. 前端请求扫描。
2. 后端创建 `wireguard.import_scan`。
3. Agent 扫描 `/etc/wireguard/*.conf`，返回 parsed 内容和 warnings。
4. 后端写入 ImportCandidate。
5. 用户导入后先成为非管理连接，不能马上让系统接管真实文件。
6. 只有确认接管或导入为受管连接后，系统才可以覆盖/管理对应文件。

常见 bug 点：

- 已导入的候选下一次扫描不应再次出现为可导入。
- 既要按路径判断，也要按接口名也就是文件名判断。
- 删除未管理导入记录时不应删除节点上的真实 wg-quick 文件。

### 受管节点间连接

受管连接由两个 `WireGuardInterface` 和两个互相指向的 `WireGuardPeer` 组成。

创建时：

- 后端生成双方密钥和预共享密钥。
- 双方配置直接下发，不走手动 diff 确认。
- 双方任务应一起创建：中间层任务、WireGuard apply、启动/enable。

编辑、启动、停止、删除时：

- 必须成对操作双方。
- 删除前要求双方都停止。
- 重复点击不能重复创建 pending/running 任务。

### udp2raw 连接中间层

udp2raw 是单向传输中间层，不是双向对等插件。它的模型是：

```text
WireGuard UDP -> udp2raw client 本地 UDP 监听端口
udp2raw client -> raw TCP/faketcp/icmp -> udp2raw server IP:port
udp2raw server -> 转回 UDP -> server 本机 WireGuard ListenPort
```

关键语义：

- 只有 udp2raw server 侧需要 WireGuard `ListenPort`。
- udp2raw client 侧 WireGuard 可以被动运行，`ListenPort` 可为空。
- server 侧 udp2raw 转发到本机 `127.0.0.1:<server_wireguard_listen_port>`。
- client 侧本地监听 `client_listen_host:client_listen_port`，WireGuard Peer Endpoint 指向这里。
- client 连接 server 使用的是 udp2raw 表单中的 `server_connect_host:server_listen_port`。
- udp2raw 的 IP 参数必须是 IPv4/IPv6 字面量，不能填写域名；受管连接普通 Endpoint 可以支持域名，但启用 udp2raw 时被插件接管。
- 被 udp2raw 接管的 WireGuard Endpoint 不应再由原始 Endpoint 字段直接控制。

相关后端函数：

```text
normalize_udp2raw_config()
apply_udp2raw_to_peers()
udp2raw_endpoint_payloads()
enqueue_udp2raw_tasks()
```

相关 Agent 任务：

```text
middleware.install
middleware.udp2raw.apply
middleware.udp2raw.start
middleware.udp2raw.stop
middleware.udp2raw.delete
middleware.udp2raw.status
```

## 认证与会话

Web 端：

- 单用户登录。
- 用户名默认 `pmman`。
- 初次启动生成密码并输出到 Docker 日志。
- Web API 需要 Bearer token。
- token 过期或 401 时前端应立即弹回登录状态。

Agent 端：

- Agent API 使用 `node_id + token` 在 JSON payload 中认证。
- `/api/agent/...` 是 Agent 侧接口白名单，但具体任务接口仍会调用 `require_agent()` 校验 token。
- 不要把 Web 鉴权白名单扩大到业务 API。

排查鉴权相关 bug：

```text
is_api_auth_exempt()
require_web_auth()
require_agent()
apps/web/src/main.tsx 中 api() 对 401 的处理
```

## Agent 版本、能力和升级

Agent 会在注册、心跳、轮询时上报：

```text
agent_version
protocol_version
capabilities
platform
```

任务下发前后端用 `TASK_REQUIREMENTS` 做门禁。新增任务必须补：

```text
TASK_REQUIREMENTS
Agent build_capabilities()
Agent execute_task()
测试
```

Agent 自升级流程：

- release manifest 来自 `/opt/link42/releases/agent/manifest.json`。
- 主控 API 提供 `/api/agent/releases` 和下载接口。
- 旧 Agent 不支持 `agent.self_upgrade` 时，前端显示手动覆盖安装命令。
- 支持自升级的 systemd Agent 可执行 `agent.self_upgrade`。

相关文档：

```text
docs/agent-versioning-and-upgrade.md
docs/release-build-and-push.md
```

## 前端交互设计约束

当前前端主要在 `apps/web/src/main.tsx`，状态集中在顶层 `App()`。

修 UI bug 时注意：

- 离线节点不能进入配置列表，但仍可打开节点设置查看 token。
- 弹窗打开后如果节点离线，提交时也必须拦截。
- 导入为受管连接的弹窗必须可操作，不能被旧弹窗遮挡。
- Endpoint 输入应同时支持下拉选择和直接输入，当前使用 `react-select/creatable`。
- 连接中间层开启后，被插件接管的字段应只读或明确显示由插件接管。
- 不要把功能说明写成大段页面文本；控件 hint 可以简短说明。
- 表单里的端口都应允许空值，除非业务明确要求必填。

常见 UI 排查入口：

```text
selectedNode
selectedNodeOnline
selectedConfig
selectedConfigIsManagedLink
selectedConfigIsUnmanagedImport
replaceLocalConfig / replacePeerConfig
Udp2RawFields
EndpointSelect
api()
runAction()
```

## WireGuard 配置渲染约束

渲染由 `packages/link42_wireguard/renderer.py` 和 `apps/api/link42_api/wireguard_service.py` 负责。

必须保留：

- `[Interface] Address` 支持多个地址。
- `ListenPort` 可省略。
- `MTU` 默认 1420。
- dn42 倾向默认 `Table = off`。
- `[Peer] AllowedIPs` 必须写入，不能遗漏。
- Endpoint 可省略，支持 IPv6 方括号格式。
- 高级自定义配置插入位置稳定。

修复渲染 bug 后优先补 `tests/test_point_to_point_rules.py`。

## 服务管理后端

Agent 不直接假设所有系统都有 systemd。

当前支持：

```text
systemd       wg-quick@<iface>.service
openrc        rc-service / rc-update
openwrt-uci   uci / ifup / ifdown
direct        wg-quick
```

相关文件：

```text
apps/agent/link42_agent/service_manager.py
apps/agent/link42_agent/system.py
tests/test_agent_system.py
```

OpenWrt 是用户真实家庭路由器环境，修复时不要做破坏性假设。

## 日志与噪音

主控 Docker 启动命令使用：

```text
uvicorn ... --no-access-log
```

如果仍看到大量请求日志，优先检查：

- Dockerfile `CMD` 是否包含 `--no-access-log`。
- `logging.getLogger("uvicorn.access").disabled = True` 是否仍在。
- 是否由别的反代或容器日志产生。

Agent 高频接口：

```text
/api/agent/register
/api/agent/heartbeat
/api/agent/tasks/poll
```

这些不应在正常运行时刷屏。

## 测试和验证命令

完整测试策略、实机测试注意事项和回归清单见 `docs/testing-guide.md`。

常规验证：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall apps/api apps/agent packages tests
npm run build --prefix apps/web
git diff --check
```

按问题范围跑：

```bash
.venv/bin/python -m pytest tests/test_point_to_point_rules.py -q
.venv/bin/python -m pytest tests/test_agent_system.py -q
```

前端只做类型和构建：

```bash
npm run build --prefix apps/web
```

## Bug 修复建议流程

1. 先复现或写下用户给出的触发路径。
2. 用 `rg` 找相关字段、接口、任务类型。
3. 判断问题属于前端状态、后端规则、Agent 执行、还是渲染。
4. 优先加或补测试，尤其是后端规则和 Agent 行为。
5. 小范围修复，不做无关重构。
6. 跑对应测试，再跑全量常规验证。
7. 如果改了主控镜像行为，按 `docs/release-build-and-push.md` 交给构建 Agent 打包推送。

## 高风险修改清单

修下面内容时要特别谨慎：

- `TASK_REQUIREMENTS`：可能导致旧 Agent 收不到任务或新任务被错误下发。
- `apply_udp2raw_to_peers()`：容易把 udp2raw 单向语义改错。
- `set_unique_peer()`：影响“单接口单 Peer”核心模型。
- `render_interface_config()`：影响所有部署 diff 和真实配置文件。
- `agent_task_result()`：影响导入候选、Change Plan、升级状态回写。
- `delete_interface()` 和受管连接删除：可能误删节点真实配置文件。
- 前端 `api()` 的 401 处理：影响 token 过期后是否能立刻回登录页。
- 安装脚本 `deploy/sh/link42-agent.sh`：实机会以 root 执行，必须幂等。

## 不要做的事

- 不要清空数据库，除非用户明确要求。
- 不要删除 `/etc/wireguard` 里的真实配置，除非流程和用户都明确确认。
- 不要把多 Peer 当作第一版受管目标。
- 不要让非管理导入配置自动归系统管理。
- 不要为了修 UI bug 大改状态管理框架。
- 不要在 bug 修复中升级大量 npm/pip 依赖。
- 不要把私钥、预共享密钥写进普通日志。
