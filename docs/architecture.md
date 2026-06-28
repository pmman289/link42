# Link42 Architecture Outline

## 1. Project Goal

Link42 is a lightweight internal network panel for managing nodes and WireGuard
connections between them.

The first release only covers:

- Adding and managing nodes.
- Managing point-to-point WireGuard link configs.
- Deploying WireGuard configuration through node agents after user confirmation.
- Importing existing `wg-quick` configurations into Link42 as managed links.

The first release does not cover:

- GRE/IPIP/VXLAN management.
- Complex monitoring, alerting, or SLA scoring.
- Redis, message queues, Prometheus, or distributed schedulers.
- Multi-tenant enterprise permission models.
- Kubernetes deployment.

The system is designed for small private or internal environments where simple
deployment, readable code, and controlled network changes matter more than large
scale automation.

Product concept clarification:

- Link42 treats one WireGuard config as one virtual cable.
- One virtual cable connects exactly two endpoints.
- One node can own many virtual cables, so the node detail page should show many
  WireGuard configs.
- A managed WireGuard config should contain exactly one `[Peer]`.
- Multi-peer WireGuard configs may be imported for observation, but they are not
  the first-release management target.

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
status
agent_token_hash
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
wireguard.start_interface
wireguard.stop_interface
wireguard.reload_interface
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
  -> Creates config/interface name, address, listen port
  -> Adds exactly one remote peer
  -> API validates state
  -> API generates change plan
  -> Frontend shows config preview and diff
  -> User confirms
  -> API creates agent task
  -> Agent applies config
  -> Agent reports result
```

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
POST   /api/nodes/{node_id}/rotate-agent-token

GET    /api/nodes/{node_id}/wireguard/configs
POST   /api/nodes/{node_id}/wireguard/configs
GET    /api/wireguard/configs/{config_id}
PATCH  /api/wireguard/configs/{config_id}
DELETE /api/wireguard/configs/{config_id}

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
  "capabilities": ["wireguard", "wg_quick_import"]
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

## 10. Security Rules

First release security requirements:

- Agent tokens must be random and stored hashed on the API side.
- Agent endpoints must require node identity plus token authentication.
- Private keys and preshared keys must not appear in frontend logs.
- Task results must redact private keys before persistence.
- Config previews may show public keys and allowed IPs.
- Any action that writes or reloads WireGuard config requires user confirmation.

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
