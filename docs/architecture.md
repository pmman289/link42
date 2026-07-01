# Link42 架构与开发状态

本文用于恢复项目上下文、辅助后续开发和 bug 修复。当前产品描述统一为：

> Link42 是 WireGuard 点对点链路管理面板，偏向 DN42、家庭网络和小型内网场景。

## 1. 当前开发进度

截至当前提交，Link42 已从最初的“节点 + WireGuard 配置管理”推进到以下阶段：

- 主控可用 Docker 部署，同端口托管 FastAPI API 和 React/Vite 构建产物。
- Web 面板已实现单用户登录、节点管理、节点地域、节点入口地址、拓扑展示地址和主控访问地址设置。
- 节点 Agent 已支持 Linux systemd、OpenRC 和 OpenWrt UCI/procd 后端。
- WireGuard 按点对点虚拟网线建模：一个受管配置最多一个 Peer，受管双向链路由两端配置组成。
- 已支持导入现有 `wg-quick` 配置、手动连接、受管双向连接、保留节点文件删除、受管配置双端启动/停止/删除。
- 已支持连接中间层插件：
  - `udp2raw`：Linux systemd 与 OpenWrt/procd 路径，单向 client -> server 封装。
  - `mimic`：非 OpenWrt Linux、kernel > 6.1、GitHub latest release 安装，透明中间层。
- 已支持链路延迟监测：Agent 定期探测，主控记录样本，前端展示当前延迟、丢包率、稳定度和历史曲线。
- 已支持首页拓扑图：根据节点和受管链路自动渲染，节点可拖动保存位置，可一键还原自动布局。
- 当前重点仍在前端拓扑/节点交互细节、真实系统兼容、mimic/udp2raw 边界和测试回归。

## 2. 产品边界

当前已覆盖：

- 添加、编辑、删除节点。
- 管理点对点 WireGuard 链路配置。
- 通过节点 Agent 部署、启动、停止、读取、删除 WireGuard 配置。
- 导入现有 `wg-quick` 配置，并防止重复导入已接管接口。
- 创建完全受管的节点间 WireGuard 双向链路。
- 对链路启用 udp2raw 或 mimic 中间层。
- 对指定对端 IP 做延迟、丢包率和稳定度监测。
- 在首页展示节点拓扑和链路状态。

当前不覆盖或暂不建议扩展：

- GRE/IPIP/VXLAN 等非 WireGuard 连接方式的完整实现。
- 多租户、RBAC、企业级权限体系。
- Redis、消息队列、Prometheus、分布式调度。
- Kubernetes 部署。
- 多 Peer hub-spoke 作为受管配置直接管理。

产品模型约束：

- Link42 把一个 WireGuard 配置视为一根虚拟网线的一端。
- 一根受管虚拟网线只连接两个端点。
- 一个节点可以拥有多根虚拟网线，因此节点详情页展示多个 WireGuard 配置。
- 受管 WireGuard 配置应含 exactly one `[Peer]`；草稿阶段允许暂时没有 Peer。
- 多 Peer `wg-quick` 配置可以导入为观察记录，但不应直接作为受管配置部署。
- 手动配置连接非 Link42 对端，使用 Change Plan + diff 确认。
- Link42 受管节点间链路拥有两端配置，编辑、启动、停止、删除必须尽量保持双端一致。

## 2. Architecture

Link42 uses a central API plus per-node agent model.

```text
Browser
  |
  v
Web Panel
  |
  v
FastAPI Server + SQLite
  |
  | Agent polling
  v
Python Node Agent
  |
  v
wg-quick / wg / ip / systemd
```

The API does not need direct SSH access to managed nodes. Each node runs an
agent that polls the API for tasks and reports results. This keeps deployment
simple and works even when nodes are behind NAT, as long as they can reach the
central API.

## 3. Technology Choices

### 3.1 Backend

- Language: Python
- Framework: FastAPI
- ORM: SQLAlchemy
- Migration: Alembic
- Default database: SQLite
- Optional later database: MySQL

SQLite is the default for minimal deployment. Database access must go through
SQLAlchemy so that switching to MySQL later remains practical.

### 3.2 Agent

- Language: Python
- Runtime mode: systemd service
- Communication: HTTPS polling
- Local operations:
  - Read existing `wg-quick` files.
  - Write managed WireGuard config files.
  - Run `wg`, `wg-quick`, `ip`, and related commands.

The agent is node-local and should not contain global topology logic. It only
executes tasks for the node on which it runs.

### 3.3 Frontend

- React
- TypeScript
- Vite

The frontend should focus on operational clarity:

- Show nodes.
- Show each node's WireGuard configs.
- Show the single remote peer inside the selected config.
- Preview config changes before deployment.
- Require explicit user confirmation before sending deployment tasks.

## 4. Repository Layout

Target layout:

```text
link42/
  apps/
    web/                      # React management panel
    api/                      # FastAPI backend
    agent/                    # Python node agent

  packages/
    link42_common/            # Shared schemas and protocol helpers
    link42_wireguard/         # WireGuard parsing, rendering, validation

  docs/
    architecture.md           # This document

  deploy/
    docker-compose.yml        # API + web for central server
    systemd/
      link42-api.service
      link42-agent.service
```

For the very first implementation, shared packages may be kept simple. If the
project starts faster with duplicated schemas in `apps/api` and `apps/agent`,
that is acceptable, but WireGuard parsing and rendering should be centralized
early because both import and deployment depend on it.

## 5. Core Domain Model

The first release models each WireGuard configuration as one point-to-point
link. In Link42, WireGuard is treated as a virtual cable: one local node, one
remote node, and exactly one peer in the generated `wg-quick` config.

A node may have many WireGuard configurations, because a server can have many
virtual cables. However, each configuration should connect to only one remote
endpoint.

The first release must not model hub-spoke or mesh by putting many peers into
one WireGuard interface. If a node needs to connect to three other nodes,
Link42 should create or import three separate WireGuard configs.

### 5.1 Node

A node represents a managed server.

Important fields:

```text
id
name
hostname
management_ip
public_ip
endpoint_ips            # JSON array of selectable endpoint addresses
status
agent_token_hash
agent_token_value       # stored so trusted admins can view install token again
last_seen_at
created_at
updated_at
```

Node status examples:

```text
pending
online
offline
disabled
```

### 5.2 WireGuard Link Config

A WireGuard link config is a node-local `wg-quick` configuration file that
represents one virtual cable to one remote endpoint.

Important fields:

```text
id
node_id
name                    # wg0, wg1, or another interface/config name
tunnel_ips              # JSON array, for example ["10.42.0.1/24"]
listen_port
private_key_ref
public_key
peer_node_id
peer_config_id
peer_name
peer_public_key
preshared_key_ref
endpoint_host
endpoint_port
allowed_ips             # JSON array
persistent_keepalive
mtu
fwmark
table_name
interface_custom_config # text inserted after [Interface]
pre_up
post_up
pre_down
post_down
source                  # created, imported
managed                 # true/false
enabled
created_at
updated_at
```

The implementation may still keep a separate peer table internally, because
`wg-quick` itself has a `[Peer]` section. The product rule is stricter than the
file format: every managed WireGuard config must have zero or one peer while it
is being drafted, and exactly one peer before deployment.

`private_key_ref` should be an abstraction even if the first version stores the
encrypted or protected value locally. Avoid scattering raw private keys through
business logic.

`source = imported` means the interface originally came from an existing
`wg-quick` file.

`managed = true` means Link42 is allowed to deploy changes for this config.

### 5.3 WireGuard Peer

A peer is the remote end of one WireGuard link config. First-release business
logic must allow only one peer per config.

Important fields:

```text
id
interface_id
peer_node_id
peer_interface_id
name
public_key
preshared_key_ref
endpoint_host
endpoint_port
allowed_ips             # JSON array
persistent_keepalive
peer_custom_config      # text inserted after [Peer]
source                  # created, imported
enabled
created_at
updated_at
```

`peer_node_id` and `peer_interface_id` may be null for imported peers that have
not yet been matched to another managed node.

Imported configs containing multiple `[Peer]` sections must be marked with a
warning. They may be imported for observation, but they should not become
managed until the user splits them into separate point-to-point configs or
explicitly removes extra peers.

### 5.4 Change Plan

All deployment-affecting changes go through a change plan.

Important fields:

```text
id
title
status
summary
affected_node_ids       # JSON array
diff
created_by
confirmed_by
created_at
confirmed_at
```

Status values:

```text
draft
confirmed
dispatching
running
succeeded
failed
cancelled
```

A change plan is created when the user edits WireGuard state. The frontend shows
the plan summary and rendered config diff. Only after confirmation should the
API create agent tasks.

### 5.5 Agent Task

Tasks are the API-to-agent execution mechanism.

Important fields:

```text
id
node_id
change_plan_id
type
payload
status
result
created_at
started_at
finished_at
```

Task types for the first release:

```text
wireguard.import_scan
wireguard.apply_config
wireguard.read_config
wireguard.start_interface
wireguard.stop_interface
wireguard.delete_config
wireguard.status
```

## 6. WireGuard Configuration Management

### 6.1 Managed Config Location

The agent should keep Link42-managed configuration under:

```text
/etc/link42/wireguard/
```

Example:

```text
/etc/link42/wireguard/wg0.conf
```

The system may then either:

- Use `wg-quick` directly with this config path.
- Or create a controlled symlink/copy into `/etc/wireguard/`.

The first release should choose the simplest reliable method per platform. On
most Linux hosts, using `/etc/wireguard/<name>.conf` with `wg-quick@<name>` is
the most familiar operational model.

### 6.2 Do Not Silently Overwrite Existing Config

When importing an existing config, Link42 must not silently overwrite the
original file.

Recommended import behavior:

1. Agent scans known locations:
   - `/etc/wireguard/*.conf`
   - Optional later: user-provided paths.
2. Agent parses candidate `wg-quick` files.
3. API presents import candidates in the frontend.
4. User selects which configs to import.
5. Link42 stores parsed state in the database.
6. Link42 marks imported configs as `managed = false` by default.
7. User explicitly chooses "Take over management".
8. API creates a change plan showing the exact resulting config.
9. After confirmation, Agent writes a backup and then writes managed config.

Backup format:

```text
/etc/wireguard/wg0.conf.link42-backup-YYYYMMDDHHMMSS
```

### 6.3 Import Parser Requirements

The WireGuard parser must support common `wg-quick` fields:

```ini
[Interface]
PrivateKey =
Address =
ListenPort =
DNS =
MTU =
Table =
FwMark =
PreUp =
PostUp =
PreDown =
PostDown =

[Peer]
PublicKey =
PresharedKey =
AllowedIPs =
Endpoint =
PersistentKeepalive =
```

Unknown fields should not be discarded silently. They should be preserved in an
`extras` structure and shown in the import preview.

Unsupported fields must make the import candidate visible but flagged with a
warning. The user should be able to import as "observed only" even if Link42
cannot safely manage every field yet.

### 6.4 Config Rendering

Rendered WireGuard config must be deterministic:

- Stable field order.
- Stable peer order.
- No unnecessary whitespace churn.
- Explicit warnings for fields Link42 does not manage.

Deterministic rendering is important because the frontend will show config diffs
before deployment.

## 7. User Flows

### 7.1 Add Node

```text
User creates node in web panel
  -> API creates node and one-time agent token
  -> User installs agent on server
  -> Agent registers with API
  -> API marks node online
```

The panel should show the install command or config snippet after node creation.

### 7.2 Create New WireGuard Link Config

```text
User selects node
  -> Chooses manual connection to a non-managed peer
  -> Creates config/interface name, addresses, listen port
  -> Adds exactly one remote peer
  -> API validates state
  -> API generates change plan
  -> Frontend shows config preview and diff
  -> User confirms
  -> API creates agent task
  -> Agent applies config
  -> Agent reports result
```

### 7.2.1 Create Managed Node-To-Node Link

```text
User selects node
  -> Chooses connect to another Link42 node
  -> Selects peer node
  -> Enters interface name, both side addresses, both listen ports
  -> Selects both endpoint addresses from node endpoint address lists
  -> Optionally sets MTU, Table policy, and per-side advanced config
  -> API generates both key pairs and preshared key
  -> API creates both configs and peers
  -> API directly dispatches apply/start/enable tasks for both nodes
  -> UI shows the pair as one managed link
```

Managed node-to-node links do not use the manual change-plan confirmation
model. Link42 owns both sides and must keep them consistent. Edit, start, stop,
and delete actions operate on both endpoint configs as one logical link.

### 7.3 Edit Peer on Existing Link Config

```text
User opens link config
  -> Edits the single peer data
  -> API validates duplicate keys, duplicate AllowedIPs, endpoint format
  -> API generates change plan
  -> User confirms
  -> Agent deploys updated config
```

### 7.4 Import Existing wg-quick Config

```text
User opens node detail
  -> Clicks scan wg-quick configs
  -> API creates wireguard.import_scan task
  -> Agent scans /etc/wireguard/*.conf
  -> Agent returns parsed candidates
  -> Frontend shows candidates, warnings, and raw file path
  -> User imports selected candidate
  -> API stores the config and its single peer as source=imported, managed=false
  -> User may later choose take over management
  -> API creates change plan and requires confirmation before writing files
```

### 7.5 Take Over Imported Config

```text
User clicks take over management
  -> API renders Link42 version of the config
  -> Frontend shows diff against imported original
  -> User confirms
  -> Agent backs up original file
  -> Agent writes managed config
  -> Agent reloads or restarts the WireGuard interface according to user choice
```

The takeover action must be explicit because it changes ownership of a live
network configuration.

## 8. API Outline

Initial API routes:

```text
POST   /api/auth/login
POST   /api/auth/logout
GET    /api/me

GET    /api/nodes
POST   /api/nodes
GET    /api/nodes/{node_id}
PATCH  /api/nodes/{node_id}
DELETE /api/nodes/{node_id}
POST   /api/nodes/{node_id}/rotate-agent-token

GET    /api/nodes/{node_id}/wireguard/configs
POST   /api/nodes/{node_id}/wireguard/configs
POST   /api/nodes/{node_id}/wireguard/managed-links
GET    /api/wireguard/configs/{config_id}
PATCH  /api/wireguard/configs/{config_id}
DELETE /api/wireguard/configs/{config_id}

GET    /api/wireguard/configs/{config_id}/managed-link
PATCH  /api/wireguard/configs/{config_id}/managed-link
POST   /api/wireguard/configs/{config_id}/managed-link/start
POST   /api/wireguard/configs/{config_id}/managed-link/stop
DELETE /api/wireguard/configs/{config_id}/managed-link

PUT    /api/wireguard/configs/{config_id}/peer
GET    /api/wireguard/configs/{config_id}/peer
DELETE /api/wireguard/configs/{config_id}/peer

POST   /api/nodes/{node_id}/wireguard/import-scan
GET    /api/nodes/{node_id}/wireguard/import-candidates
POST   /api/nodes/{node_id}/wireguard/import
POST   /api/wireguard/configs/{config_id}/take-over

POST   /api/change-plans
GET    /api/change-plans/{plan_id}
POST   /api/change-plans/{plan_id}/confirm
POST   /api/change-plans/{plan_id}/cancel

POST   /api/agent/register
POST   /api/agent/heartbeat
POST   /api/agent/tasks/poll
POST   /api/agent/tasks/{task_id}/result
```

The exact route shapes may change during implementation, but the separation
between user-facing APIs and agent APIs should remain.

## 9. Agent Protocol

The agent polls for work:

```text
POST /api/agent/tasks/poll
```

Request:

```json
{
  "node_id": "node_123",
  "agent_version": "0.1.0",
  "protocol_version": 1,
  "capabilities": ["wireguard", "wg_quick_import", "service:systemd"]
}
```

Response:

```json
{
  "tasks": [
    {
      "id": "task_123",
      "type": "wireguard.apply_config",
      "payload": {}
    }
  ]
}
```

The agent reports completion:

```text
POST /api/agent/tasks/{task_id}/result
```

Result:

```json
{
  "status": "succeeded",
  "result": {
    "stdout": "",
    "stderr": "",
    "changed": true
  }
}
```

Failed tasks should include enough information for the UI to show a useful
message, but secrets must be redacted.

Agent versioning is part of this protocol. New task types, such as connection
middleware and udp2raw installation, must declare their minimum Agent version
and required capabilities before the API creates tasks for a node. See
`docs/agent-versioning-and-upgrade.md` for the version, capability, and upgrade
design.

## 10. Security Rules

First release security requirements:

- Agent tokens must be random and stored hashed on the API side.
- Agent endpoints must require node identity plus token authentication.
- Private keys and preshared keys must not appear in frontend logs.
- Task results must redact private keys before persistence.
- Config previews may show private keys for trusted administrators, but logs and
  task errors should still avoid unnecessary secret exposure.
- Any manual config action that writes or reloads WireGuard config requires user
  confirmation. Link42-managed node-to-node links are the exception: the create,
  edit, start, stop, or delete operation is itself the confirmation to apply
  both sides.

For small internal use, a single admin user is acceptable in the first release,
but authentication should still exist from the start.

## 11. Validation Rules

Minimum validation:

- Node names must be unique.
- WireGuard interface names must be valid Linux interface names.
- Interface names must be unique per node.
- Public keys must have valid WireGuard key format.
- Listen ports must be valid UDP ports.
- Endpoint ports must be valid UDP ports.
- Allowed IPs must be valid CIDR values.
- Tunnel IPs must be valid CIDR values.
- MTU must be a valid positive interface MTU.
- `Table = off` means wg-quick should not automatically create routes.
- A managed WireGuard config must have at most one peer.
- A deployable WireGuard config must have exactly one peer.
- Imported configs with multiple peers should be flagged as observation-only
  until the user splits or simplifies them.
- Duplicate interface addresses should produce a warning or error.

Some topology conflicts should start as warnings rather than hard errors,
because imported environments may already contain unusual but working configs.

## 12. First Release Milestones

### Milestone 1: Skeleton

- Create app structure.
- Add FastAPI backend.
- Add SQLite database setup.
- Add first Alembic migration.
- Add basic frontend shell.
- Add Python agent skeleton.

### Milestone 2: Nodes

- Add node CRUD.
- Generate agent token.
- Add agent registration.
- Add heartbeat.
- Show online/offline status in UI.

### Milestone 3: WireGuard Model

- Add WireGuard link config and single-peer data model.
- Add API endpoints for configs and their one remote peer.
- Add validation.
- Add deterministic config renderer.

### Milestone 4: Change Plans

- Generate config preview and diff.
- Show affected nodes and configs.
- Require user confirmation.
- Create agent deployment tasks only after confirmation.

### Milestone 5: Agent Deployment

- Implement `wireguard.apply_config`.
- Write backup before replacing an existing config.
- Apply config using `wg-quick`.
- Report task result to API.

### Milestone 6: Import Existing wg-quick

- Agent scans `/etc/wireguard/*.conf`.
- Parser extracts interface and peer data.
- API stores import candidates.
- Frontend shows candidates and warnings.
- User imports selected configs as unmanaged.
- User can explicitly take over management.

## 13. Design Decisions To Preserve

- Keep deployment lightweight.
- Prefer readable Python over clever abstraction.
- Use SQLite by default.
- Do not introduce Redis or a queue system in the first release.
- Keep Agent polling simple.
- Require frontend confirmation before config deployment.
- Treat imported configs carefully and never overwrite without backup.
- Model each WireGuard config as one point-to-point virtual cable.
- Allow one node to own many WireGuard configs.
- Do not support multiple managed peers inside one WireGuard config in the first release.
- Preserve unknown imported fields where possible.

## 14. Code Documentation Rules

代码需要方便运维人员和项目维护者直接审阅。所有实现代码必须遵守以下注释规范：

- 每个函数必须包含中文 docstring，或在函数旁提供中文注释说明职责。
- 每个模块级常量必须包含中文注释，说明它的用途。
- 注释应解释设计意图、安全边界和运行行为。
- 避免只重复语法本身的无意义注释。
- Agent 认证、私钥处理、配置导入、配置备份、配置部署等安全敏感路径，
  必须用注释说明对应的安全决策。
- 代码标识符可以继续使用英文，以保持工程一致性；但注释和 docstring
  应使用中文。

## 13. 当前开发交接说明（2026-07-02）

本轮开发集中在首页拓扑图、节点展示字段和交互修复，目的是让后续协作者清楚当前做到哪里、为什么这样做。

### 已完成的拓扑相关能力

- 后端 `nodes` 表新增：
  - `region`：节点地域，用于拓扑节点卡片展示。
  - `topology_endpoint`：拓扑图展示地址，由用户在节点设置中选择或输入。
  - `topology_x` / `topology_y` / `topology_locked`：保存用户拖动后的拓扑位置。
- 后端新增/调整接口：
  - `GET /api/topology`：返回拓扑节点和受管链路。
  - `PATCH /api/nodes/{node_id}/topology-position`：保存节点拖动坐标。
  - `POST /api/topology/layout/reset`：清空所有自定义坐标，恢复自动布局。
- 前端首页新增拓扑面板：
  - 根据节点和受管 WireGuard 双向链路自动渲染。
  - 节点卡片仅显示节点名称、节点地域和拓扑展示地址。
  - 链路标签仅显示当前延迟和丢包率；稳定度通过线条颜色表达。
  - 节点可以拖动并保存位置。
  - 提供“还原拓扑”按钮，清空自定义位置。
  - 隐藏 React Flow 迷你地图、控制按钮和 attribution，避免右下角空白/干扰。
- 点击拓扑节点会展开对应节点卡片并滚动到节点位置。
- 点击拓扑链路会展开本端节点并滚动到对应 WireGuard 配置行。

### 拓扑实现取舍

曾尝试根据节点相对方位动态计算上下左右连接点，并用直角线连接；实测视觉效果较差，且容易因 React Flow handle 细节导致连线消失。因此当前实现恢复为 React Flow 默认曲线边，只保留链路状态颜色、动画和标签。

后续如果继续优化连线，应优先用 React Flow 官方自定义 edge/node 组件实现，并配合真实浏览器截图验证，避免只靠 TypeScript 构建通过。

### 当前已知状态

- 拓扑图仍属于第一版可用状态，不是最终视觉设计。
- 节点位置保存依赖前端本地草稿 + 后端坐标持久化：拖动中使用草稿坐标预览，保存成功后由 `/api/topology` 返回的坐标接管。
- 右上角刷新按钮会刷新：节点、拓扑、当前展开节点配置、当前配置 peer/受管连接详情、打开中的链路监测弹窗。
- 节点拓扑展示地址使用统一 `EndpointSelect` 组件，选项主文本应显示真实地址，来源标签显示“节点地址 / 当前配置 / 原始 Endpoint”。

### 最近验证命令

本轮变更完成后已执行：

```bash
npm run build --prefix apps/web
.venv/bin/pytest -q tests/test_point_to_point_rules.py
.venv/bin/pytest -q
git diff --check
```

测试结果：`126 passed`，仅有既有 DeprecationWarning。

### 当前开发主控验收方式

可用临时演示库 `/tmp/link42-topology-demo.db` 启动开发主控：

```bash
PYTHONPATH=apps/api:apps/agent:packages \
LINK42_DATABASE_URL=sqlite:////tmp/link42-topology-demo.db \
LINK42_WEB_DIST_DIR=/root/repo/link42/apps/web/dist \
LINK42_AGENT_OFFLINE_AFTER_SECONDS=3600 \
.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000 --no-access-log
```

当前演示登录信息：

```text
用户名：pmman
密码：pmman-demo
```
