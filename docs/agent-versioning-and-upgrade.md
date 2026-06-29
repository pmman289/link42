# Agent 版本与升级设计

Link42 后续会加入连接中间层、udp2raw 插件安装等节点侧能力。主控和 Agent 必须先建立明确的版本与能力协商机制，避免主控下发 Agent 不认识的任务。

## 设计目标

- Agent 版本可展示、可比较、可用于任务门禁。
- 主控按节点能力下发任务，而不是只按节点在线状态下发。
- 新任务类型必须声明最低 Agent 版本和所需能力。
- Agent 能通过受控任务升级自身。
- 插件资产安装和 Agent 升级分离，避免插件更新被误认为 Agent 运行时更新。
- 升级失败不应破坏正在运行的 WireGuard 连接。

## 版本号规则

Agent 使用独立版本号，建议遵循 SemVer：

```text
MAJOR.MINOR.PATCH
```

示例：

```text
0.1.0
0.2.0
0.2.1
```

规则：

- `PATCH`：修 bug，不改变任务协议。
- `MINOR`：新增向后兼容能力，例如新增 `middleware.udp2raw`。
- `MAJOR`：任务协议或安装布局不兼容。

主控版本和 Agent 版本可以暂时同号发布，但协议上必须视为两个独立字段：

```text
controller_version
agent_version
```

## Agent 上报信息

Agent 注册、心跳、任务轮询都应上报版本和能力。

建议请求字段：

```json
{
  "node_id": 1,
  "token": "l42agent_xxx",
  "hostname": "node-a",
  "agent_version": "0.2.0",
  "protocol_version": 1,
  "capabilities": [
    "wireguard",
    "wg_quick_import",
    "service:systemd",
    "middleware",
    "middleware.udp2raw",
    "middleware.install",
    "agent.self_upgrade"
  ],
  "platform": {
    "os": "linux",
    "arch": "x86_64",
    "service_manager": "systemd",
    "glibc": "2.31"
  }
}
```

主控需要保存到 `nodes`：

```text
agent_version
agent_protocol_version
agent_capabilities       # JSON array
agent_platform           # JSON object
agent_update_status
agent_last_error
last_seen_at
```

SQLite 迁移正式化前，可继续用启动时补列；后续应迁到 Alembic。

## 能力命名

能力是主控下发任务的硬门禁。

基础能力：

```text
wireguard
wg_quick_import
service:systemd
service:openwrt
service:openrc
agent.self_upgrade
```

连接中间层能力：

```text
middleware
middleware.install
middleware.udp2raw
middleware.udp2raw.systemd
middleware.udp2raw.openwrt
```

能力名只表示 Agent 知道如何执行，不表示插件已经安装。插件安装状态另行上报：

```json
{
  "installed_plugins": {
    "udp2raw": {
      "installed": true,
      "version": "20200818.0",
      "backend": "systemd",
      "binary": "/usr/local/bin/udp2raw"
    }
  }
}
```

## 任务门禁

每种任务类型声明最低 Agent 版本和能力。

示例：

```python
TASK_REQUIREMENTS = {
    "wireguard.apply_config": {
        "min_agent_version": "0.1.0",
        "capabilities": ["wireguard"],
    },
    "middleware.install": {
        "min_agent_version": "0.2.0",
        "capabilities": ["middleware.install"],
    },
    "middleware.udp2raw.apply": {
        "min_agent_version": "0.2.0",
        "capabilities": ["middleware.udp2raw"],
    },
    "agent.self_upgrade": {
        "min_agent_version": "0.2.0",
        "capabilities": ["agent.self_upgrade"],
    },
}
```

主控创建任务前必须检查：

- 节点在线。
- Agent 版本满足最低要求。
- Agent 能力满足任务要求。
- 插件任务还要检查插件安装状态。

不满足时不要创建任务，应在 UI 显示：

```text
节点 Agent 版本过旧，需要升级到 0.2.0 才能使用 udp2raw 中间层。
```

## Agent 升级方案

Agent 升级分两层：

- **手动安装脚本升级**：兼容所有历史 Agent，适合首次把旧节点升到支持自升级的版本。
- **主控下发自升级任务**：要求当前 Agent 已支持 `agent.self_upgrade` 能力，适合后续常规升级。

第一版必须同时保留这两条路径。旧 Agent 不认识 `agent.self_upgrade`，主控不能指望它们自动升级，只能在 UI 给出重新执行安装脚本的命令。

### 升级兼容矩阵

| 当前 Agent | 上报能力 | 推荐升级方式 | 说明 |
| --- | --- | --- | --- |
| 无版本 / 0.1.x | 无 `agent.self_upgrade` | 安装脚本覆盖安装 | 主控展示升级命令，用户在节点执行。 |
| 0.2.x | 有 `agent.self_upgrade` | 主控一键升级 | 主控下发 `agent.self_upgrade` 任务。 |
| 协议版本不兼容 | 可能无法可靠轮询 | 安装脚本覆盖安装 | UI 标记为需要手动升级。 |

主控判断顺序：

1. 节点离线：不能升级，只能展示安装命令。
2. 节点在线但无 `agent.self_upgrade`：展示手动升级命令。
3. 节点在线且有 `agent.self_upgrade`：允许点击“一键升级”。
4. 目标版本低于或等于当前版本：默认不升级，除非用户选择“强制重装”。

### 升级来源

主控提供 Agent 发布资产，节点不直接依赖 GitHub：

```text
GET /api/agent/releases
GET /api/agent/releases/{version}/download?platform=linux-x64
GET /api/agent/releases/{version}/sha256?platform=linux-x64
```

主控 Docker 镜像内建议预置：

```text
/opt/link42/releases/agent/
- link42-agent-linux-x64
- link42-agent-linux-x64.sha256
- manifest.json
```

`manifest.json` 示例：

```json
{
  "latest": "0.2.0",
  "releases": {
    "0.2.0": {
      "linux-x64": {
        "path": "link42-agent-linux-x64",
        "sha256": "..."
      }
    }
  }
}
```

Manifest 需要包含更多元信息，方便主控选择资产：

```json
{
  "latest": "0.2.0",
  "minimum_supported": "0.1.0",
  "releases": {
    "0.2.0": {
      "released_at": "2026-06-30T00:00:00Z",
      "protocol_version": 1,
      "notes": "新增 udp2raw 中间层和 Agent 自升级能力",
      "assets": {
        "linux-x64-glibc2.31": {
          "path": "link42-agent-linux-x64-glibc2.31-0.2.0",
          "sha256": "...",
          "size": 29500000
        }
      }
    }
  }
}
```

平台命名建议：

```text
linux-x64-glibc2.31
linux-arm64-glibc2.31
linux-mips24kc-musl
openwrt-mips24kc-musl
```

主控根据 `agent_platform.os`、`agent_platform.arch`、`agent_platform.glibc`、`agent_platform.service_manager` 选择最匹配资产。没有精确匹配时不要猜测升级，UI 显示“无匹配 Agent 资产”。

### 升级任务

任务类型：

```text
agent.self_upgrade
```

payload：

```json
{
  "target_version": "0.2.0",
  "download_url": "https://controller/api/agent/releases/0.2.0/download?platform=linux-x64",
  "sha256": "...",
  "size": 29500000,
  "binary_args": ["--version"],
  "service_name": "link42-agent",
  "install_path": "/usr/local/bin/link42-agent",
  "rollback": true
}
```

任务门禁：

```python
"agent.self_upgrade": {
    "min_agent_version": "0.2.0",
    "capabilities": ["agent.self_upgrade"],
}
```

主控创建任务前还要检查：

- 目标版本存在。
- 当前平台有匹配资产。
- 该节点没有未完成的 `agent.self_upgrade` 任务。
- 节点没有正在运行的高风险任务，例如 `wireguard.apply_config`、`middleware.udp2raw.apply`。

执行流程：

1. 下载新二进制到临时文件。
2. 校验 SHA256。
3. 执行 `--version` 或 `version` 自检。
4. 备份当前二进制为 `.bak`。
5. 原子替换 Agent 二进制。
6. 上报 `upgrade_staged`。
7. 重启 Agent 服务。
8. 新 Agent 启动后注册并上报新版本。

如果新 Agent 启动失败，systemd 可以通过 wrapper 或升级脚本回滚 `.bak`。第一版可以先要求用户手动回滚，但任务结果必须保留备份路径。

### 自升级状态机

节点侧状态写入 `/var/lib/link42/agent/upgrade-state.json`，主控侧同步到 `nodes.agent_update_status` 和 `nodes.agent_last_error`。

状态建议：

```text
idle
queued
downloading
verified
staged
restarting
healthy
failed
rolled_back
```

Agent 任务结果分两次上报：

1. 旧 Agent 在替换前上报 `staged`，表示下载校验完成，升级脚本已安排。
2. 新 Agent 启动后，在注册或心跳中上报新版本，主控把状态改为 `healthy`。

如果主控在超时时间内没有看到新版本心跳：

- 状态改为 `failed`。
- 如果节点随后上报旧版本且 `upgrade-state.json` 显示回滚，状态改为 `rolled_back`。
- UI 显示失败原因和手动修复命令。

### systemd 自升级脚本

Agent 不能在自己的进程里直接阻塞式重启自己。推荐做法：

- Agent 下载新二进制到 `/var/lib/link42/agent/link42-agent.new`。
- Agent 写入升级脚本到 `/var/lib/link42/agent/upgrade.sh`。
- Agent 上报任务结果 `staged`。
- Agent 使用 `systemd-run --on-active=1 /var/lib/link42/agent/upgrade.sh` 让 systemd 托管替换动作。

脚本流程：

```sh
#!/bin/sh
set -eu

SERVICE_NAME="${SERVICE_NAME:-link42-agent}"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/link42-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/link42/agent}"
NEW_BIN="$STATE_DIR/link42-agent.new"
BACKUP_BIN="$STATE_DIR/link42-agent.bak"
STATE_FILE="$STATE_DIR/upgrade-state.json"

write_state() {
  printf '%s\n' "$1" > "$STATE_FILE"
}

write_state '{"status":"restarting"}'
systemctl stop "$SERVICE_NAME"

cp "$INSTALL_PATH" "$BACKUP_BIN"
install -m 0755 "$NEW_BIN" "$INSTALL_PATH"

if systemctl start "$SERVICE_NAME"; then
  sleep 5
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    write_state '{"status":"healthy"}'
    exit 0
  fi
fi

install -m 0755 "$BACKUP_BIN" "$INSTALL_PATH"
systemctl start "$SERVICE_NAME" || true
write_state '{"status":"rolled_back"}'
exit 1
```

第一版只实现 systemd。OpenRC/OpenWrt 后续按同一状态机补 backend：

```text
service:openrc      -> rc-service link42-agent stop/start
service:openwrt-uci -> /etc/init.d/link42-agent stop/start
```

### 安装脚本覆盖升级

旧 Agent 或不支持自升级的节点，使用安装脚本完成覆盖安装。安装脚本必须做到幂等：

1. 停止已有服务。
2. 下载指定版本 Agent。
3. 校验 SHA256。
4. 写入 `/etc/link42/agent.env`，保留已有 `LINK42_SERVER_URL`、`LINK42_NODE_ID`、`LINK42_AGENT_TOKEN`，除非命令显式覆盖。
5. 安装/更新 service unit。
6. 启动服务。
7. 输出当前安装版本。

命令示例：

```sh
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env LINK42_AGENT_VERSION=0.2.0 sh
```

如果是新节点或需要重写配置，则带完整环境变量：

```sh
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env \
  LINK42_AGENT_VERSION=0.2.0 \
  LINK42_SERVER_URL=http://controller:8000 \
  LINK42_NODE_ID=1 \
  LINK42_AGENT_TOKEN=l42agent_xxx \
  sh
```

### 主控 API 设计

Web 用户侧 API：

```text
GET  /api/agent/releases
GET  /api/nodes/{node_id}/agent/upgrade-plan
POST /api/nodes/{node_id}/agent/upgrade
POST /api/nodes/{node_id}/agent/upgrade/manual-command
```

`upgrade-plan` 返回：

```json
{
  "current_version": "0.1.0",
  "target_version": "0.2.0",
  "upgrade_mode": "manual",
  "reason": "当前 Agent 不支持自升级",
  "matched_asset": null,
  "manual_command": "curl -fsSL ... | sudo env LINK42_AGENT_VERSION=0.2.0 sh"
}
```

支持自升级时：

```json
{
  "current_version": "0.2.0",
  "target_version": "0.2.1",
  "upgrade_mode": "self_upgrade",
  "reason": null,
  "matched_asset": {
    "platform": "linux-x64-glibc2.31",
    "sha256": "...",
    "size": 29500000
  }
}
```

Agent 侧资产 API：

```text
GET /api/agent/releases
GET /api/agent/releases/{version}/download?platform=linux-x64-glibc2.31
GET /api/agent/releases/{version}/sha256?platform=linux-x64-glibc2.31
```

这些接口走 Agent token 白名单，不走 Web session token。

### 前端交互

节点详情展示：

- 当前 Agent 版本。
- 最新可用版本。
- 协议版本。
- 平台和服务管理器。
- 能力列表。
- 升级状态。

按钮规则：

- `Agent 离线`：按钮禁用，显示手动命令。
- `无匹配资产`：按钮禁用，提示需要构建该平台 Agent。
- `不支持自升级`：显示“复制手动升级命令”。
- `支持自升级`：显示“一键升级到 x.y.z”。
- `升级中`：禁用重复点击，显示任务状态。

升级失败时显示：

```text
升级失败：SHA256 校验失败 / 新 Agent 未在 60 秒内恢复心跳 / systemd 启动失败
```

并提供手动命令。

### 发布流程

每次发布 Agent：

1. 更新 `packages/link42_common/version.py` 的 `AGENT_VERSION`。
2. 构建各平台 Agent 二进制。
3. 生成 SHA256。
4. 生成 `manifest.json`。
5. 将资产复制进主控镜像：

```text
/opt/link42/releases/agent/manifest.json
/opt/link42/releases/agent/link42-agent-linux-x64-glibc2.31-0.2.0
/opt/link42/releases/agent/link42-agent-linux-x64-glibc2.31-0.2.0.sha256
```

6. Docker 镜像构建并推送。
7. 主控启动后读取 manifest，前端即可看到可升级版本。

### 安全约束

- 只允许从主控下载 Agent 资产，不允许任务传入任意外部 URL。
- download URL 可以由主控生成，但 Agent 端仍应校验它属于当前 `LINK42_SERVER_URL`。
- 必须校验 SHA256。
- 新二进制必须能执行 `--version`，输出版本必须等于目标版本。
- 替换路径必须限制在安装路径，禁止 payload 任意写文件。
- 升级任务 payload 不允许携带任意 shell 命令。
- 升级时不修改 `/etc/wireguard`。

### 第一版开发拆分

后续开发可以按这个顺序落地：

1. 构建脚本输出版本化 Agent 二进制和 `manifest.json`。
2. 主控读取 manifest，提供 releases API。
3. 主控提供 `upgrade-plan`，前端展示升级入口和手动命令。
4. 安装脚本支持 `LINK42_AGENT_VERSION` 并保留已有 env。
5. Agent 增加 `agent.self_upgrade` 能力和任务处理器。
6. systemd 自升级脚本、SHA256 校验、回滚状态文件。
7. 主控创建 `agent.self_upgrade` 任务并跟踪状态。
8. 测试覆盖：旧 Agent 手动升级提示、新 Agent 一键升级任务、无匹配资产、校验失败、回滚状态。

## 一键安装脚本与版本

安装脚本应支持版本参数：

```sh
LINK42_AGENT_VERSION=0.2.0 sh link42-agent.sh
```

默认安装主控推荐版本：

```text
GET /api/agent/releases/latest
```

前端生成安装命令时可以固定版本，也可以用 `latest`：

```sh
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env LINK42_AGENT_VERSION=0.2.0 LINK42_SERVER_URL=... LINK42_NODE_ID=... LINK42_AGENT_TOKEN=... sh
```

## udp2raw 插件与 Agent 版本关系

udp2raw 中间层至少要求：

```text
min_agent_version = 0.2.0
capabilities = [
  "middleware",
  "middleware.install",
  "middleware.udp2raw",
  "service:systemd"
]
```

使用流程：

1. 用户在受管连接中启用 udp2raw。
2. 主控检查双方 Agent 版本和能力。
3. 若能力不足，提示升级 Agent。
4. 若 Agent 可执行但插件未安装，下发 `middleware.install`。
5. 插件安装成功后，下发 `middleware.udp2raw.apply/start`。
6. 最后下发 WireGuard 配置。

插件资产版本独立于 Agent：

```text
agent_version = 0.2.0
udp2raw_asset_version = 20200818.0-link42.1
```

## UI 展示

节点详情应显示：

```text
Agent 版本：0.2.0
协议版本：1
服务管理器：systemd
能力：wireguard, wg_quick_import, middleware.udp2raw
更新状态：最新 / 可升级 / 升级中 / 失败
```

当用户启用某功能时，如果节点不满足要求，按钮禁用并给出明确提示。

## 第一阶段实现清单

1. Agent 从包版本读取 `agent_version`，不要硬编码。
2. Agent 注册、心跳、轮询都上报版本、协议版本、能力、平台。
3. 主控保存节点的 Agent 版本和能力。
4. 主控创建任务前校验任务要求。
5. 前端节点列表展示 Agent 版本。
6. Agent 增加 `--version` 输出。
7. 构建脚本产出带版本号的二进制副本：
   - `link42-agent-linux-x64`
   - `link42-agent-linux-x64-0.2.0`
8. 主控提供升级计划和手动升级命令。

## 第二阶段实现清单

1. 主控镜像内置 Agent release manifest 和二进制资产。
2. 主控提供 Agent release 下载 API。
3. 安装脚本支持版本化覆盖升级。
4. Agent 实现 `agent.self_upgrade` 任务。
5. systemd 节点支持自动替换、重启、失败回滚。
6. 前端节点详情提供一键升级入口。

## 非目标

第一阶段不做：

- 自动灰度升级。
- 多版本 Agent 并存调度。
- Windows Agent。
- 第三方插件动态执行权限模型。
- 不经主控校验的任意脚本执行。
