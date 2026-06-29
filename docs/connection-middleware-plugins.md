# 连接中间层插件规范

本文定义 Link42 “连接中间层插件”的规范和注册流程。连接中间层位于受管 WireGuard 连接和真实网络入口之间，用于接管部分连接字段，并由插件自己的配置生成真实转发或伪装通道。

第一版目标插件是 `udp2raw`，但规范应允许后续增加 `gost`、`socat`、`ssh-tunnel` 等协议。

## 设计目标

- 插件绑定到受管连接，而不是单独绑定到节点。
- 插件可以声明自己接管哪些受管连接字段。
- 被接管字段在原表单位置保留展示，但变成只读，并标记“由插件接管”。
- 插件真实使用的地址、端口、密码、模式等配置放在插件自己的表单区域。
- 后端根据插件输出的覆盖值生成 WireGuard 配置。
- Agent 根据插件类型执行对应的 apply/start/stop/status/delete 任务。

## 核心概念

### 连接中间层实例

一个连接中间层实例属于一条受管连接。它负责描述“这条连接是否启用中间层、使用什么协议、双方如何运行”。

建议字段：

```text
connection_middlewares
- id
- managed_link_id 或 local_interface_id
- plugin_type              # udp2raw
- enabled
- status
- config                   # 插件级 JSON 配置
- created_at
- updated_at
```

### 连接中间层端点

端点表示插件在某个节点上的运行配置。一条双端受管连接通常有两个端点。

建议字段：

```text
connection_middleware_endpoints
- id
- middleware_id
- node_id
- interface_id
- side                     # local / peer
- role                     # client / server / symmetric
- listen_host
- listen_port
- connect_host
- connect_port
- status
- config                   # 端点级 JSON 配置
- created_at
- updated_at
```

第一版可以先用一张表和 JSON 保存，但代码层面仍应按“插件实例 + 双端端点”组织。

## 字段接管模型

插件不能随意修改受管连接字段。插件必须显式声明它接管的字段。

字段接管声明示例：

```json
{
  "claimed_fields": [
    "local_endpoint_host",
    "local_endpoint_port",
    "peer_endpoint_host",
    "peer_endpoint_port"
  ]
}
```

覆盖值示例：

```json
{
  "overrides": {
    "local_endpoint_host": "127.0.0.1",
    "local_endpoint_port": 41001,
    "peer_endpoint_host": "127.0.0.1",
    "peer_endpoint_port": 41002
  }
}
```

前端规则：

- 未启用插件时，原字段正常可编辑。
- 启用插件后，被接管字段只读。
- 被接管字段显示插件给出的实际值。
- 被接管字段旁显示“由 udp2raw 接管”。
- 插件关闭后，字段恢复可编辑。

后端规则：

- 保存受管连接时，最终入库和渲染 WireGuard 配置的值必须以插件覆盖值为准。
- 插件未声明接管的字段不能被覆盖。
- 插件覆盖值必须通过后端校验，不能只信任前端计算。

## 插件描述文件

插件应提供一份描述信息，供前端渲染和后端校验使用。

示例：

```json
{
  "type": "udp2raw",
  "display_name": "udp2raw",
  "description": "使用 udp2raw 包装 WireGuard UDP 流量",
  "claimed_fields": [
    "local_endpoint_host",
    "local_endpoint_port",
    "peer_endpoint_host",
    "peer_endpoint_port"
  ],
  "config_schema": {
    "raw_mode": {
      "type": "enum",
      "options": ["faketcp", "udp", "icmp"],
      "default": "faketcp"
    },
    "password": {
      "type": "secret",
      "required": true,
      "default": "auto"
    },
    "local_real_host": {
      "type": "string",
      "required": true
    },
    "local_real_port": {
      "type": "port",
      "required": true
    },
    "peer_real_host": {
      "type": "string",
      "required": true
    },
    "peer_real_port": {
      "type": "port",
      "required": true
    },
    "local_wg_proxy_port": {
      "type": "port",
      "required": true
    },
    "peer_wg_proxy_port": {
      "type": "port",
      "required": true
    }
  }
}
```

## 后端插件接口

后端插件可以先做内置注册表，不需要第一版就做外部动态加载。

建议接口：

```python
class ConnectionMiddlewarePlugin:
    type: str
    display_name: str
    claimed_fields: list[str]

    def default_config(self, context) -> dict:
        ...

    def validate_config(self, config: dict, context) -> dict:
        ...

    def build_overrides(self, config: dict, context) -> dict:
        ...

    def build_agent_payloads(self, config: dict, context) -> list[dict]:
        ...
```

注册表：

```python
CONNECTION_MIDDLEWARE_PLUGINS = {
    "udp2raw": Udp2RawPlugin(),
}
```

后端保存受管连接时的顺序：

1. 根据 `plugin_type` 查找插件。
2. 调用 `validate_config()` 清洗配置。
3. 调用 `build_overrides()` 生成字段覆盖值。
4. 校验覆盖字段都在 `claimed_fields` 内。
5. 用覆盖值参与 WireGuard 配置生成。
6. 保存插件实例和双端端点配置。
7. 创建插件相关 Agent 任务。

## 前端注册流程

前端也使用内置注册表。它只负责展示和基础校验，不负责最终可信计算。

建议接口：

```ts
type ConnectionMiddlewarePlugin = {
  type: string;
  displayName: string;
  claimedFields: string[];
  renderConfigForm: (...) => React.ReactNode;
  previewOverrides: (...) => Record<string, string | number | null>;
};
```

注册表：

```ts
const connectionMiddlewarePlugins = {
  udp2raw: udp2rawPlugin,
};
```

前端渲染流程：

1. 用户启用“连接中间层”。
2. 用户选择插件类型。
3. 插件表单区域出现。
4. 原受管连接表单中被接管字段切换为只读。
5. 只读字段显示插件预览覆盖值。
6. 提交时发送原受管连接字段和插件配置；后端最终决定覆盖结果。

## Agent 任务规范

连接中间层任务不要混入 WireGuard 任务，应使用独立任务类型。

插件任务必须经过 Agent 版本和能力门禁。详细规则见
`docs/agent-versioning-and-upgrade.md`。

建议任务类型：

```text
middleware.install
middleware.apply
middleware.start
middleware.stop
middleware.status
middleware.delete
```

任务 payload 示例：

```json
{
  "middleware_id": 1,
  "type": "udp2raw",
  "side": "local",
  "service_name": "link42-udp2raw-1-local",
  "config": {
    "raw_mode": "faketcp",
    "listen_host": "0.0.0.0",
    "listen_port": 40001,
    "connect_host": "peer.example.com",
    "connect_port": 40002,
    "password": "secret"
  }
}
```

Agent 处理流程：

- `middleware.install`：安装插件二进制、服务模板和运行目录。
- `middleware.apply`：写入插件配置和服务文件。
- `middleware.start`：启动插件服务。
- `middleware.stop`：停止插件服务。
- `middleware.status`：返回插件服务状态。
- `middleware.delete`：删除插件配置和服务文件。

## 受管连接生命周期

创建或更新受管连接：

1. 保存插件配置。
2. 下发 `middleware.apply`。
3. 下发 `middleware.start`。
4. 生成被插件覆盖后的 WireGuard 配置。
5. 下发 `wireguard.apply_config`。
6. 启动 WireGuard。
7. 查询中间层和 WireGuard 状态。

停止受管连接：

1. 停止 WireGuard。
2. 停止连接中间层。

删除受管连接：

1. 停止 WireGuard。
2. 删除 WireGuard 配置。
3. 停止连接中间层。
4. 删除连接中间层配置。

## udp2raw 第一版约定

第一版 `udp2raw` 插件建议只支持：

- Linux systemd。
- 内置插件注册，不做外部动态插件。
- `raw_mode` 默认 `faketcp`。
- 密码自动生成，允许手动覆盖。
- 每条受管连接一组双端 udp2raw 配置。
- udp2raw 是 client -> server 的单向封装：client 监听本机 UDP，封装为 raw TCP/faketcp/icmp 发往 server IP:port；server 再转回 UDP 发往本机 WireGuard ListenPort。
- WireGuard Endpoint 指向 client 本机 `127.0.0.1:<client_listen_port>`。
- 只有 udp2raw server 侧要求 WireGuard ListenPort，client 侧 WireGuard 可以不写 ListenPort。
- 插件真实连接地址填写在 udp2raw 表单区域。
- udp2raw 的 IP 参数必须是 IPv4/IPv6 字面量，不能填写域名。
- 通过 Agent 的 `middleware.install` 安装 udp2raw，不在节点上执行交互式脚本。

udp2raw 至少要求：

```text
min_agent_version = 0.2.0
capabilities = middleware, middleware.install, middleware.udp2raw, service:systemd
```

插件资产由主控提供，Agent 下载并校验后安装：

```text
/usr/local/bin/udp2raw
/usr/local/libexec/link42-udp2raw-systemd
/etc/systemd/system/link42-udp2raw-server@.service
/etc/systemd/system/link42-udp2raw-client@.service
/etc/link42/middleware/udp2raw/
```

字段接管：

```text
local_endpoint_host
local_endpoint_port
peer_endpoint_host
peer_endpoint_port
```

真实连接配置：

```text
server_side
server_listen_host
server_connect_host
server_listen_port
client_listen_host
client_listen_port
raw_mode
cipher_mode
password
```

## 导入场景

如果导入配置中的 Endpoint 是 `127.0.0.1` 或其它本机地址，前端应提示：

```text
检测到本地 Endpoint，可能由连接中间层提供。
转为受管连接时可选择连接中间层插件接管。
```

启用插件后：

- 原 WireGuard Endpoint 字段显示为只读。
- 插件表单要求填写真实连接地址。
- 后端用插件覆盖值生成新的 WireGuard 配置。

## 非目标

第一版不做：

- 第三方插件包动态安装。
- 插件脚本上传。
- 多租户插件权限模型。
- 自动解析系统中已有 udp2raw 配置。
- 多层插件链式叠加。

这些能力可以在内置注册表稳定后再扩展。
