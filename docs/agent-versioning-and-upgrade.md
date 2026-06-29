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

## Agent 升级模型

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
  "service_name": "link42-agent",
  "rollback": true
}
```

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

### systemd 注意事项

Agent 不能在自己的进程里直接阻塞式重启自己。推荐做法：

- Agent 写入升级脚本到 `/var/lib/link42/agent/upgrade.sh`。
- Agent 上报任务结果。
- Agent 使用 `systemd-run --on-active=1 /var/lib/link42/agent/upgrade.sh` 或 `nohup sh upgrade.sh &` 让子进程替换并重启服务。

升级脚本执行：

```sh
systemctl stop link42-agent
install -m 0755 new-binary /usr/local/bin/link42-agent
systemctl start link42-agent
```

OpenWrt/OpenRC 后续单独实现。

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
8. 后续再实现 `agent.self_upgrade`。

## 非目标

第一阶段不做：

- 自动灰度升级。
- 多版本 Agent 并存调度。
- Windows Agent。
- 第三方插件动态执行权限模型。
- 不经主控校验的任意脚本执行。
