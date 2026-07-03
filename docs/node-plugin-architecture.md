# 节点插件架构与开发规范

本文定义 Link42 的“节点插件”机制，用于承载 Bird 配置编辑、FRR 工具、系统路由查看、防火墙规则辅助等节点侧能力。它和现有“连接中间层插件”不同：连接中间层插件绑定一条受管链路，节点插件绑定一个节点，作为主控面板的可选扩展工具存在。

## 目标

- 不把 Bird、FRR、iptables/nftables 等功能塞进核心 WireGuard 主流程。
- 插件只在节点详情页或插件工作区出现，不干扰节点、链路、拓扑这些主功能。
- 插件复用现有 Agent 轮询任务模型，不要求主控 SSH 到节点。
- 插件必须显式声明能力、权限、文件路径、任务类型和 UI 入口。
- 修改类插件必须支持预览、备份、审计和回滚入口，避免误写节点配置。

## 插件分类

### 连接中间层插件

已存在的类型，例如 `udp2raw`、`mimic`。它们属于某条受管 WireGuard 连接，会接管连接字段并生成额外 Agent 任务。

命名空间建议继续使用：

```text
middleware.<plugin>.<action>
```

### 节点功能插件

新增类型，例如 `bird-config`。它们属于某个节点，提供节点内配置查看、编辑、校验、应用、服务重载等能力。

命名空间建议使用：

```text
node_plugin.<plugin>.<action>
```

例如：

```text
node_plugin.bird.read
node_plugin.bird.validate
node_plugin.bird.plan_apply
node_plugin.bird.apply
node_plugin.bird.reload
node_plugin.bird.status
node_plugin.bird.rollback
```

## 数据模型

第一版可以复用 `agent_tasks` 执行一次性任务，但需要新增插件状态和审计记录。建议表：

```text
node_plugins
- id
- node_id
- plugin_type              # bird
- enabled
- status                   # unknown / ready / unsupported / failed
- config                   # 插件级 JSON，例如 bird 配置路径、service 名称
- last_error
- created_at
- updated_at
```

```text
node_plugin_revisions
- id
- node_id
- plugin_type
- resource_key             # bird.conf / conf.d/peer-a.conf
- content_sha256
- content_preview          # 可选，截断后的摘要，不保存敏感内容时为空
- backup_ref               # Agent 节点本地备份路径或备份 id
- action                   # read / apply / rollback
- task_id
- created_at
```

```text
node_plugin_resources
- id
- node_id
- plugin_type
- resource_key             # 插件内资源名
- display_name
- kind                     # file / service / command
- metadata                 # JSON，路径、大小、mtime、readonly 等
- updated_at
```

不建议第一版把完整 Bird 配置长期明文存进数据库。主控可以保存最近一次摘要、hash、diff 和任务结果；完整内容按需读取，提交时由用户确认。

## 插件描述文件

每个插件必须有服务端描述。第一版可以内置在 Python 注册表里，后续再支持外部目录加载。

```json
{
  "type": "bird",
  "display_name": "BIRD",
  "description": "查看、校验并编辑节点上的 BIRD 配置",
  "scope": "node",
  "min_agent_version": "0.6.0",
  "capabilities": ["node_plugin.bird"],
  "actions": ["read", "validate", "plan_apply", "apply", "reload", "status", "rollback"],
  "resources": [
    {
      "key": "bird.conf",
      "kind": "file",
      "default_path": "/etc/bird/bird.conf",
      "editable": true,
      "sensitive": false
    }
  ],
  "platforms": {
    "service_managers": ["systemd", "openrc"],
    "commands": ["bird", "birdc"]
  }
}
```

字段说明：

- `type`：稳定插件 id，只允许小写字母、数字和短横线。
- `scope`：第一版为 `node`。
- `capabilities`：Agent 必须上报这些能力，主控才展示可用入口。
- `actions`：插件暴露给前端和 API 的动作。
- `resources`：插件可访问的文件或服务。插件不能越过这里声明的资源。
- `platforms`：用于主控判断是否可安装、可运行或仅隐藏入口。

## 插件包结构

第一阶段采用“内置插件包”，插件代码随 Link42 发布，不支持用户在运行时上传任意代码。这样可以先把插件接口、权限和 UI 体验做稳。后续如果要开放第三方插件，再把相同结构迁移到外部目录。

推荐结构：

```text
apps/api/link42_api/node_plugins/
  __init__.py
  base.py                  # 后端插件 SDK
  registry.py              # NODE_PLUGINS 注册表
  bird.py                  # Bird 后端插件

apps/agent/link42_agent/plugins/
  __init__.py
  base.py                  # Agent 插件 SDK
  registry.py              # AGENT_NODE_PLUGINS 注册表
  bird.py                  # Bird 节点执行插件

apps/web/src/nodePlugins/
  registry.tsx             # 前端插件注册表
  types.ts                 # 前端插件 SDK 类型
  bird/
    BirdPluginPanel.tsx
```

一个完整节点插件由三部分组成：

```text
后端插件：描述插件、校验请求、构造任务、归档结果。
Agent 插件：检测本机能力、读取/校验/写入节点资源、执行固定动作。
前端插件：渲染用户界面、调用宿主 API、展示任务状态和 diff。
```

三部分必须共享同一个 `plugin_type` 和 action 命名，但不能互相信任：

- 前端只负责体验和基础校验。
- 后端负责可信校验和权限边界。
- Agent 负责节点本地安全执行和最后一道路径/命令限制。

## 宿主提供的能力

Link42 作为插件宿主，应提供稳定的 Host API/SDK。插件只使用这些能力，不直接访问主控内部状态或任意节点命令。

### 主控后端能力

后端宿主提供：

- 节点查询：读取节点基础信息、Agent 版本、能力、平台信息、在线状态。
- 能力门禁：通过 `TASK_REQUIREMENTS` 和 Agent capabilities 判断 action 是否可执行。
- 任务队列：创建 `agent_tasks`，跟踪 pending/running/succeeded/failed。
- 任务结果归档：把 Agent result 转成插件状态、资源状态、revision 记录。
- 资源白名单：插件声明可访问的文件、服务、命令，后端只接受资源 key，不接受任意路径。
- 审计记录：记录谁在什么时候对哪个节点执行了哪个插件动作。
- diff 工具：为文本资源生成 unified diff，前端应用前展示。
- 结果裁剪：统一限制 stdout/stderr/content preview 最大长度。
- 版本兼容：旧 Agent 显示需要升级，而不是让请求静默失败。

后端宿主不提供：

- 任意 shell 执行。
- 任意文件路径透传。
- 插件绕过鉴权直接暴露 API。
- 插件直接修改数据库表结构的能力。

### Agent 宿主能力

Agent 宿主提供：

- 固定任务分发：只执行注册过的 `node_plugin.<plugin>.<action>`。
- 平台检测：OS、发行版、service manager、可执行文件路径、权限检测。
- 安全文件操作：
  - 读取白名单文件。
  - 写临时文件。
  - sha256 计算。
  - base hash 冲突检查。
  - 原子替换。
  - 写入前备份。
- 命令执行封装：
  - 只允许插件调用自己声明的固定命令。
  - 参数数组执行，不拼 shell 字符串。
  - timeout、stdout/stderr 上限、返回码检查。
- 服务控制封装：
  - systemd/openrc/procd 的 status/reload/restart 抽象。
- dry-run 支持：测试环境不落盘、不 reload。
- 结果脱敏：按插件声明裁剪或隐藏敏感字段。

Agent 宿主不提供：

- 交互式命令。
- shell 管道。
- 后台长期进程管理，除非插件声明为 service 类型并走宿主 service manager。
- 任意目录遍历。

### 前端宿主能力

前端宿主提供：

- 节点上下文：当前节点、在线状态、Agent 能力、平台信息。
- 插件 API client：封装 `/api/nodes/{node_id}/plugins/...`。
- 任务轮询：根据 `task_id` 刷新状态。
- 通知系统：成功、失败、警告 toast。
- 确认弹窗：危险动作统一确认。
- diff 视图：文本修改统一展示。
- 表单组件：Field、必填标记、错误展示。
- 代码编辑器容器：第一版可以用 textarea，后续接 Monaco/CodeMirror。

前端宿主不提供：

- 插件远程 JS 加载。
- 插件绕过统一 API 访问主控。
- 插件直接读取 auth token 之外的敏感状态。

## 插件可以做什么

节点插件适合做“节点局部、可选、运维辅助”的事情：

- 读取和编辑某个服务的配置文件，例如 Bird、FRR、dnsmasq。
- 校验配置，例如 `bird -p -c <file>` 或 `birdc configure check`。
- 触发服务 reload/restart/status。
- 查询固定命令输出，例如路由表摘要、Bird peer 状态、BGP session 状态。
- 对白名单文件做备份和回滚。
- 将操作结果转成结构化状态供面板展示。

节点插件不应该做：

- 替代核心 WireGuard 连接模型。
- 维护全局拓扑状态。
- 在节点上安装未知来源软件，除非另有“安装插件”规范和能力门禁。
- 管理长期 daemon，除非通过宿主 service manager 并有明确生命周期。
- 执行用户输入的任意命令。
- 读取未声明的敏感文件，如 WireGuard private key、SSH key、token。

## 插件生命周期

节点插件建议遵循以下生命周期：

```text
describe -> detect -> enable/configure -> read/status -> validate -> plan -> apply -> verify -> rollback
```

- `describe`：主控展示插件基本信息和资源声明。
- `detect`：Agent 检测本机是否支持插件。
- `enable/configure`：管理员选择资源路径、service 名称等插件配置。
- `read/status`：读取当前资源内容或服务状态。
- `validate`：对用户提交内容做只读校验。
- `plan`：生成 diff 和影响说明。
- `apply`：带 base hash 写入、备份、reload。
- `verify`：读取服务状态或二次校验。
- `rollback`：使用 backup_ref 恢复。

第一阶段可以不做显式安装/启用表单，Bird 插件可根据 Agent detect 自动显示为可用；但架构上保留 `node_plugins.config`，方便以后允许用户自定义 Bird 配置路径。

## 权限模型

第一版 Link42 是单用户系统，但插件仍应按权限等级设计，避免未来补权限时重构。

建议 action 风险等级：

```text
read       # 只读，读取配置或状态
validate   # 只读，校验用户提交内容
operate    # 对服务做 reload/status 这类操作
write      # 修改节点文件
danger     # rollback/restart/delete 等高风险动作
```

插件描述中应声明：

```json
{
  "actions": {
    "read": {"risk": "read"},
    "validate": {"risk": "validate"},
    "apply": {"risk": "write", "requires_confirm": true},
    "rollback": {"risk": "danger", "requires_confirm": true}
  }
}
```

宿主规则：

- `write` 和 `danger` 必须有确认弹窗。
- `write` 必须有 diff 或影响说明。
- `write` 必须带 `base_sha256`，防止覆盖并发修改。
- `danger` 必须要求用户输入资源名或节点名二次确认，视具体插件而定。

## 后端插件接口

后端插件负责可信校验、任务构造、结果归档和权限边界。

建议接口：

```python
class NodePlugin:
    type: str
    display_name: str
    min_agent_version: str
    capabilities: list[str]
    resources: dict[str, NodePluginResource]
    actions: dict[str, NodePluginAction]

    def describe(self, node) -> dict:
        ...

    def available(self, node) -> tuple[bool, str | None]:
        ...

    def validate_action(self, action: str, payload: dict, node) -> dict:
        ...

    def build_task(self, action: str, payload: dict, node) -> tuple[str, dict]:
        ...

    def handle_result(self, action: str, task, result: dict, db) -> None:
        ...
```

后端 SDK 应提供上下文对象，而不是让插件随意访问 FastAPI 全局变量：

```python
@dataclass
class NodePluginContext:
    node: models.Node
    db: Session
    actor: str
    controller_url: str
```

更完整的接口建议：

```python
class NodePlugin:
    def describe(self, context: NodePluginContext) -> NodePluginDescription:
        ...

    def detect_status(self, context: NodePluginContext) -> NodePluginStatus:
        ...

    def validate_payload(self, action: str, payload: dict, context: NodePluginContext) -> dict:
        ...

    def build_task(self, action: str, payload: dict, context: NodePluginContext) -> AgentTaskSpec:
        ...

    def summarize_result(self, action: str, result: dict, context: NodePluginContext) -> dict:
        ...
```

`AgentTaskSpec`：

```python
@dataclass
class AgentTaskSpec:
    task_type: str
    payload: dict
    dedupe_key: str | None = None
```

后端插件必须做到：

- action 不存在时返回 404 或 400。
- 资源 key 不存在时拒绝。
- path 只能由后端根据资源 key/config 决定，不能直接信任前端 path。
- payload 写入任务前必须裁剪无关字段。
- 任务 result 归档前必须裁剪超长输出。

注册表：

```python
NODE_PLUGINS = {
    "bird": BirdNodePlugin(),
}
```

插件任务创建流程：

1. API 根据 `{node_id, plugin_type, action}` 找插件。
2. 校验节点存在、在线状态和 Agent capability。
3. 调用 `validate_action()` 清洗 payload。
4. 调用 `build_task()` 得到任务类型和 payload。
5. 写入 `agent_tasks`，必要时写入 `node_plugin_revisions` 草稿记录。
6. Agent 完成任务后，`handle_result()` 归档结果、hash、备份引用和错误信息。

## API 设计

插件列表：

```http
GET /api/node-plugins
```

返回主控内置的插件描述。

节点可用插件：

```http
GET /api/nodes/{node_id}/plugins
```

返回该节点上可用、不可用、需要升级 Agent 的插件状态。

执行插件动作：

```http
POST /api/nodes/{node_id}/plugins/{plugin_type}/{action}
Content-Type: application/json
```

请求示例：

```json
{
  "resource_key": "bird.conf",
  "content": "...",
  "message": "update peer route filter",
  "dry_run": true
}
```

响应示例：

```json
{
  "task_id": 123,
  "status": "queued",
  "action": "validate"
}
```

读取最近任务或资源：

```http
GET /api/nodes/{node_id}/plugins/{plugin_type}/resources
GET /api/nodes/{node_id}/plugins/{plugin_type}/tasks/{task_id}
GET /api/nodes/{node_id}/plugins/{plugin_type}/revisions
```

约定：

- API 不直接执行节点命令，只入队 Agent 任务。
- 修改动作必须返回 `task_id`，前端轮询任务状态。
- 读文件这类动作也走任务，避免主控假设节点可达。

统一响应结构建议：

```json
{
  "task_id": 123,
  "plugin_type": "bird",
  "action": "apply",
  "status": "queued",
  "resource_key": "bird.conf"
}
```

任务结果结构建议：

```json
{
  "task_id": 123,
  "plugin_type": "bird",
  "action": "apply",
  "status": "succeeded",
  "result": {
    "summary": "配置已应用并 reload",
    "resource": {
      "key": "bird.conf",
      "sha256": "..."
    },
    "backup_ref": "...",
    "stdout": "",
    "stderr": ""
  }
}
```

错误结构建议：

```json
{
  "detail": {
    "code": "plugin_resource_conflict",
    "message": "节点上的配置已被其它进程修改，请重新读取后再应用",
    "plugin_type": "bird",
    "action": "apply",
    "resource_key": "bird.conf"
  }
}
```

错误码建议：

```text
plugin_not_found
plugin_action_not_found
plugin_not_supported
plugin_agent_upgrade_required
plugin_resource_not_found
plugin_resource_too_large
plugin_resource_conflict
plugin_validation_failed
plugin_command_failed
plugin_permission_denied
```

## Agent 插件接口

Agent 插件负责节点本地实际操作。第一版以内置 Python 模块注册，避免动态执行第三方代码。

建议目录：

```text
apps/agent/link42_agent/plugins/
  __init__.py
  bird.py
```

接口：

```python
class AgentNodePlugin:
    type: str
    capabilities: list[str]
    actions: set[str]

    def detect(self) -> dict:
        ...

    def execute(self, action: str, payload: dict, config: AgentConfig) -> dict:
        ...
```

更完整的 Agent SDK 建议：

```python
@dataclass
class AgentPluginContext:
    config: AgentConfig
    dry_run: bool
    platform: dict[str, Any]
    helpers: AgentPluginHelpers


class AgentPluginHelpers:
    def read_text_resource(self, resource: ResourceSpec, max_bytes: int) -> FileSnapshot:
        ...

    def write_text_resource(
        self,
        resource: ResourceSpec,
        content: str,
        base_sha256: str,
        backup: bool = True,
    ) -> FileSnapshot:
        ...

    def run_command(
        self,
        argv: list[str],
        timeout_seconds: int = 10,
        max_output_bytes: int = 65536,
    ) -> CommandResult:
        ...

    def service_status(self, service_name: str) -> dict:
        ...

    def service_reload(self, service_name: str) -> dict:
        ...
```

Agent 插件示例：

```python
class BirdAgentPlugin(AgentNodePlugin):
    type = "bird"
    actions = {"detect", "read", "validate", "apply", "status", "rollback"}

    def detect(self, context: AgentPluginContext) -> dict:
        return {
            "has_bird": bool(shutil.which("bird")),
            "has_birdc": bool(shutil.which("birdc")),
            "default_config_path": "/etc/bird/bird.conf",
        }

    def execute(self, action: str, payload: dict, context: AgentPluginContext) -> dict:
        if action == "read":
            return self.read(payload, context)
        if action == "validate":
            return self.validate(payload, context)
        if action == "apply":
            return self.apply(payload, context)
        raise ValueError(f"unsupported bird action: {action}")
```

Agent 插件必须做到：

- 不使用 `shell=True`。
- 不拼接用户输入成 shell 字符串。
- 所有文件访问都通过 resource spec。
- 所有写入都先写临时文件、校验、备份、原子替换。
- 所有输出都限制大小。
- dry-run 时不写文件、不 reload 服务，但要返回将执行的计划。

Agent 任务分发：

```python
TASK_HANDLERS["node_plugin.bird.read"] = ...
TASK_HANDLERS["node_plugin.bird.validate"] = ...
TASK_HANDLERS["node_plugin.bird.apply"] = ...
```

能力上报：

```text
node_plugin
node_plugin.bird
node_plugin.bird.read
node_plugin.bird.validate
node_plugin.bird.apply
```

能力应基于本机检测结果生成。例如只有存在 `bird`/`birdc` 命令且配置路径可读时才上报 `node_plugin.bird.read`；只有配置路径可写时才上报 `node_plugin.bird.apply`。

## 前端插件接口

前端插件是 UI 扩展，不拥有执行能力。它只能通过宿主传入的 `api`、`notify`、`confirm`、`pollTask` 等能力操作。

推荐类型：

```ts
export type NodePluginPanelProps = {
  node: NodeItem;
  plugin: NodePluginStatus;
  host: NodePluginHost;
};

export type NodePluginHost = {
  api<T>(path: string, init?: RequestInit): Promise<T>;
  runAction<T>(fn: () => Promise<T>, key?: string): Promise<T | undefined>;
  notify(type: "success" | "error" | "info", text: string): void;
  confirm(options: ConfirmOptions): Promise<boolean>;
  pollTask(taskId: number): Promise<NodePluginTaskResult>;
  showDiff(options: DiffOptions): Promise<boolean>;
};

export type NodePluginFrontend = {
  type: string;
  displayName: string;
  description: string;
  icon: React.ReactNode;
  renderPanel(props: NodePluginPanelProps): React.ReactNode;
};
```

前端插件只能做：

- 渲染插件自己的面板。
- 调宿主 API 创建任务。
- 展示任务状态、结果、diff。
- 根据插件描述禁用不可用 action。

前端插件不能做：

- 自己保存认证 token。
- 直接访问未封装的全局状态。
- 动态加载远程脚本。
- 绕过确认弹窗执行危险动作。

Bird 前端插件流程：

```text
打开 Bird 插件
  -> GET resources/status
  -> 点击读取
  -> POST read，轮询 task
  -> 编辑内容
  -> POST validate，轮询 task
  -> 展示 diff
  -> 用户确认
  -> POST apply，轮询 task
  -> 展示 reload 结果和新 sha256
```

## Bird 插件动作设计

### read

读取 Bird 配置文件。

任务类型：

```text
node_plugin.bird.read
```

payload：

```json
{
  "resource_key": "bird.conf",
  "path": "/etc/bird/bird.conf",
  "max_bytes": 262144
}
```

result：

```json
{
  "resource_key": "bird.conf",
  "path": "/etc/bird/bird.conf",
  "content": "...",
  "sha256": "...",
  "mtime": "2026-07-03T12:00:00Z"
}
```

### validate

校验用户编辑后的配置，但不落盘。优先使用 Bird 自身配置校验能力；如果系统命令不支持 dry-run，应写入安全临时文件再执行校验命令。

任务类型：

```text
node_plugin.bird.validate
```

payload：

```json
{
  "resource_key": "bird.conf",
  "content": "...",
  "base_sha256": "..."
}
```

result：

```json
{
  "valid": true,
  "stdout": "",
  "stderr": "",
  "warnings": []
}
```

### plan_apply

主控侧生成 diff，Agent 侧可选做二次校验。第一版也可以由 `validate` + 前端 diff 替代。

### apply

写入配置并可选 reload。必须做备份。

任务类型：

```text
node_plugin.bird.apply
```

payload：

```json
{
  "resource_key": "bird.conf",
  "path": "/etc/bird/bird.conf",
  "content": "...",
  "base_sha256": "...",
  "backup": true,
  "reload": true
}
```

Agent 行为：

1. 读取当前文件并计算 sha256。
2. 如果当前 sha256 与 `base_sha256` 不一致，拒绝写入，返回冲突。
3. 写入备份，例如 `/var/lib/link42/backups/bird/bird.conf.<timestamp>`.
4. 写临时文件并校验。
5. 原子替换目标文件。
6. 执行 `birdc configure` 或服务 reload。
7. 返回新 sha256、备份路径和 reload 结果。

result：

```json
{
  "applied": true,
  "sha256": "...",
  "backup_ref": "/var/lib/link42/backups/bird/bird.conf.20260703120000",
  "reload": {
    "ok": true,
    "stdout": "...",
    "stderr": ""
  }
}
```

### rollback

根据 `backup_ref` 恢复文件并 reload。

### status

返回 `birdc show status`、服务状态和配置文件 hash。注意输出可能很长，要限制大小。

## 前端开发规范

节点详情页增加“插件”入口，不放进首页主流程。

推荐 UI：

- 节点卡片或节点详情中显示插件 tab。
- 插件列表显示状态：可用、不可用、需要升级 Agent、缺少命令、只读。
- 点击 Bird 插件后打开编辑器页或右侧抽屉。
- 编辑器提供：读取、格式化或校验、查看 diff、应用、reload、回滚。
- 应用前必须显示 diff 和确认弹窗。
- 配置内容过大时提示只读或下载，不直接塞满主页面。

前端插件注册建议：

```ts
type NodePluginFrontend = {
  type: string;
  displayName: string;
  icon: React.ReactNode;
  renderPanel: (props: NodePluginPanelProps) => React.ReactNode;
};
```

第一版不建议做远程加载前端插件。所有前端插件随主控构建发布，避免引入第三方脚本执行风险。

## 插件开发流程

开发一个新节点插件时，按以下顺序：

1. 写插件说明：确定 `plugin_type`、资源、动作、风险等级、需要的本机命令。
2. 写后端插件：
   - 描述插件。
   - 定义资源白名单。
   - 校验 payload。
   - 构造 Agent task。
   - 归档 result。
3. 写 Agent 插件：
   - detect 本机能力。
   - 实现固定 action。
   - 使用宿主 helper 做文件和命令操作。
   - 返回结构化 result。
4. 写前端插件：
   - 注册插件入口。
   - 渲染表单/编辑器。
   - 调用宿主 API。
   - 展示 diff、确认、任务结果。
5. 补 `TASK_REQUIREMENTS`：
   - 每个任务声明最小 Agent 版本和 capability。
6. 补测试：
   - 后端 payload 校验。
   - Agent detect/action。
   - 文件路径白名单。
   - base hash 冲突。
   - 输出裁剪。
   - 前端关键交互。

插件作者不需要关心：

- Agent 轮询协议细节。
- 登录鉴权。
- 节点在线状态计算。
- 任务状态机。
- toast、modal、diff 基础组件。
- service manager 底层差异，除非插件自己需要特殊行为。

插件作者必须关心：

- 自己插件声明了哪些资源。
- 哪些 action 会写节点。
- 如何校验用户输入。
- 如何从命令输出转成结构化 result。
- 如何处理命令不存在、权限不足、配置冲突。

## 插件 Manifest 规范

后续支持外部插件时，可以把描述抽为 manifest。内置插件也应尽量按同一结构编写。

```json
{
  "api_version": "node-plugin/v1",
  "type": "bird",
  "display_name": "BIRD",
  "scope": "node",
  "entrypoints": {
    "api": "link42_api.node_plugins.bird:BirdNodePlugin",
    "agent": "link42_agent.plugins.bird:BirdAgentPlugin",
    "web": "nodePlugins/bird"
  },
  "min_controller_version": "0.6.0",
  "min_agent_version": "0.6.0",
  "capabilities": ["node_plugin.bird"],
  "resources": [
    {
      "key": "bird.conf",
      "kind": "file",
      "path_config_key": "config_path",
      "default_path": "/etc/bird/bird.conf",
      "editable": true,
      "max_bytes": 262144
    }
  ],
  "actions": {
    "read": {"risk": "read", "task": "node_plugin.bird.read"},
    "validate": {"risk": "validate", "task": "node_plugin.bird.validate"},
    "apply": {"risk": "write", "task": "node_plugin.bird.apply", "requires_confirm": true},
    "rollback": {"risk": "danger", "task": "node_plugin.bird.rollback", "requires_confirm": true}
  }
}
```

Manifest 校验规则：

- `api_version` 必须匹配宿主支持版本。
- `type` 全局唯一。
- action task 必须以 `node_plugin.<type>.` 开头。
- resource key 只能包含字母、数字、点、短横线和下划线。
- 外部插件如果未来开放，必须有签名或固定安装来源；第一版不做。

## 安全边界

- 节点插件不允许任意命令执行；每个 action 必须映射到固定 Agent 函数。
- 文件路径必须来自插件资源白名单，不能信任前端传入任意 path。
- 默认不读取私钥、token、证书等敏感文件。
- 修改文件必须校验 base hash，防止覆盖节点上的并发修改。
- 修改前必须本地备份，且备份目录在 `/var/lib/link42/backups/<plugin>/`。
- Agent result 需要限制 stdout/stderr 长度，避免日志爆炸或泄露大量文件内容。
- 前端应用前必须显示 diff；危险动作必须二次确认。
- 插件能力按 Agent 实际检测上报，主控只展示节点支持的动作。

## 版本兼容

在 `packages/link42_common/connection_types.py` 的 `TASK_REQUIREMENTS` 增加节点插件任务：

```python
TASK_REQUIREMENTS.update({
    "node_plugin.bird.read": {
        "min_agent_version": "0.6.0",
        "capabilities": ["node_plugin.bird.read"],
    },
    "node_plugin.bird.validate": {
        "min_agent_version": "0.6.0",
        "capabilities": ["node_plugin.bird.validate"],
    },
    "node_plugin.bird.apply": {
        "min_agent_version": "0.6.0",
        "capabilities": ["node_plugin.bird.apply"],
    },
})
```

旧 Agent 不上报 `node_plugin.*`，主控应显示“需要升级 Agent”，而不是隐藏所有信息。

## 第一阶段落地建议

1. 先实现内置 Bird 节点插件，不做外部插件市场。
2. 新增后端 `NodePlugin` 注册表和 `/api/nodes/{node_id}/plugins/...` API。
3. Agent 新增 `plugins/bird.py`，支持 detect/read/validate/apply/status。
4. 前端节点详情增加插件 tab，Bird 插件使用代码编辑器、diff 和确认弹窗。
5. 为 Bird 插件增加单元测试：路径白名单、hash 冲突、校验失败、apply 备份、任务能力门禁。

这样可以把“节点工具扩展”跑通，同时不牺牲主功能的简洁性。
