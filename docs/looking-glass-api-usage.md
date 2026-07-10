# Looking Glass API 调用文档

本文面向独立 Looking Glass 服务开发者，说明如何调用 Link42 暴露的第三方 API。

接口根路径：

```text
/third-party-api/looking-glass/v1
```

管理端 Token 由 Link42 管理员在主控面板的“系统设置 -> Looking Glass API Token”中生成。Looking Glass 服务只保存生成出的 Token，并通过 Bearer Token 调用第三方 API。

## 1. 鉴权

所有第三方 API 请求都需要携带：

```http
Authorization: Bearer <API_TOKEN>
```

示例：

```bash
curl -H "Authorization: Bearer l42lg_xxx_xxx" \
  https://link42.example.com/third-party-api/looking-glass/v1/nodes
```

Token 无效、过期、禁用或已吊销时返回：

```json
{
  "error": {
    "code": "invalid_api_key",
    "message": "API Token 无效或已过期"
  }
}
```

## 2. 获取节点列表

```http
GET /third-party-api/looking-glass/v1/nodes
```

权限要求：

```text
looking_glass.nodes.read
```

查询参数：

```text
region    可选，按节点地域精确过滤
online    可选，true 或 false
limit     可选，默认 100，最大 500
cursor    可选，上一页返回的 next_cursor
```

请求示例：

```bash
curl -H "Authorization: Bearer l42lg_xxx_xxx" \
  "https://link42.example.com/third-party-api/looking-glass/v1/nodes?online=true&limit=100"
```

响应示例：

```json
{
  "items": [
    {
      "node_ref": "node_8",
      "name": "tencguangzhou",
      "region": "华南",
      "online": true,
      "last_seen_at": "2026-07-10T09:30:00Z",
      "ips": {
        "management_ip": "10.1.0.6",
        "public_ip": "1.14.226.49",
        "endpoint_ips": ["1.14.226.49", "10.1.0.6"]
      },
      "capabilities": {
        "bird": true,
        "bird_route_lookup": true
      }
    }
  ],
  "next_cursor": null
}
```

字段说明：

- `node_ref`：Looking Glass 后续调用使用的节点引用。
- `name`：节点名称。
- `region`：节点地域。
- `online`：节点 Agent 是否在线。
- `last_seen_at`：节点最后心跳时间。
- `ips.management_ip`：管理地址。
- `ips.public_ip`：公网地址。
- `ips.endpoint_ips`：节点入口地址列表。
- `capabilities.bird_route_lookup`：该节点是否支持 BIRD 路由查询。

## 3. 获取节点详情

```http
GET /third-party-api/looking-glass/v1/nodes/{node_ref}
```

权限要求：

```text
looking_glass.nodes.read
```

请求示例：

```bash
curl -H "Authorization: Bearer l42lg_xxx_xxx" \
  https://link42.example.com/third-party-api/looking-glass/v1/nodes/node_8
```

响应结构与节点列表中的单个 `item` 相同。

## 4. 提交 BIRD 路由查询

```http
POST /third-party-api/looking-glass/v1/nodes/{node_ref}/bird/routes:lookup
```

权限要求：

```text
looking_glass.bird.route
```

请求体：

```json
{
  "ip": "1.1.1.1"
}
```

`ip` 必须是合法 IPv4 或 IPv6 字面量。

请求示例：

```bash
curl -i \
  -H "Authorization: Bearer l42lg_xxx_xxx" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.1.1.1"}' \
  https://link42.example.com/third-party-api/looking-glass/v1/nodes/node_8/bird/routes:lookup
```

成功时返回 `202 Accepted`：

```http
HTTP/1.1 202 Accepted
Location: /third-party-api/looking-glass/v1/queries/lgq_xxx
Retry-After: 1
```

```json
{
  "query_id": "lgq_xxx",
  "status": "queued",
  "node_ref": "node_8",
  "operation": "bird.route_lookup",
  "request": {
    "ip": "1.1.1.1",
    "normalized_ip": "1.1.1.1"
  },
  "created_at": "2026-07-10T09:30:00Z",
  "started_at": null,
  "finished_at": null,
  "deadline_at": "2026-07-10T09:30:15Z",
  "expires_at": "2026-07-10T09:40:00Z",
  "result": null,
  "error": null
}
```

调用方应保存 `query_id`，随后轮询查询结果。

## 5. 读取查询状态和结果

```http
GET /third-party-api/looking-glass/v1/queries/{query_id}
```

权限要求：

```text
looking_glass.bird.route
```

请求示例：

```bash
curl -H "Authorization: Bearer l42lg_xxx_xxx" \
  https://link42.example.com/third-party-api/looking-glass/v1/queries/lgq_xxx
```

处理中响应：

```json
{
  "query_id": "lgq_xxx",
  "status": "running",
  "node_ref": "node_8",
  "operation": "bird.route_lookup",
  "request": {
    "ip": "1.1.1.1",
    "normalized_ip": "1.1.1.1"
  },
  "created_at": "2026-07-10T09:30:00Z",
  "started_at": "2026-07-10T09:30:01Z",
  "finished_at": null,
  "deadline_at": "2026-07-10T09:30:15Z",
  "expires_at": "2026-07-10T09:40:00Z",
  "result": null,
  "error": null
}
```

成功响应：

```json
{
  "query_id": "lgq_xxx",
  "status": "succeeded",
  "node_ref": "node_8",
  "operation": "bird.route_lookup",
  "request": {
    "ip": "1.1.1.1",
    "normalized_ip": "1.1.1.1"
  },
  "created_at": "2026-07-10T09:30:00Z",
  "started_at": "2026-07-10T09:30:01Z",
  "finished_at": "2026-07-10T09:30:02Z",
  "deadline_at": "2026-07-10T09:30:15Z",
  "expires_at": "2026-07-10T09:40:00Z",
  "result": {
    "command": "birdc show route for 1.1.1.1 all",
    "exit_code": 0,
    "stdout": "BIRD 2.0.12 ready.\nTable master4:\n...",
    "stderr": "",
    "truncated": false,
    "duration_ms": 83
  },
  "error": null
}
```

失败响应示例：

```json
{
  "query_id": "lgq_xxx",
  "status": "failed",
  "node_ref": "node_8",
  "operation": "bird.route_lookup",
  "request": {
    "ip": "1.1.1.1",
    "normalized_ip": "1.1.1.1"
  },
  "created_at": "2026-07-10T09:30:00Z",
  "started_at": "2026-07-10T09:30:01Z",
  "finished_at": "2026-07-10T09:30:02Z",
  "deadline_at": "2026-07-10T09:30:15Z",
  "expires_at": "2026-07-10T09:40:00Z",
  "result": {
    "command": "birdc show route for 1.1.1.1 all",
    "exit_code": 1,
    "stdout": "",
    "stderr": "bird: No such table",
    "truncated": false,
    "duration_ms": 40,
    "error_code": "command_failed",
    "error": "BIRD 查询执行失败"
  },
  "error": {
    "code": "command_failed",
    "message": "BIRD 查询执行失败"
  }
}
```

注意：即使 `status=failed`，`result.stdout` 和 `result.stderr` 仍可能包含原始输出，Looking Glass 可以按需要展示或解析。

## 6. 查询状态

```text
queued       已入队，等待节点 Agent 拉取
running      节点 Agent 正在执行
succeeded    执行完成
failed       执行失败
expired      查询结果已过期
cancelled    查询被取消
```

建议轮询策略：

```text
第一次等待 500ms
之后按 1s、2s 间隔退避
响应头有 Retry-After 时优先使用 Retry-After
超过 deadline_at 后停止等待并提示超时
```

结果默认保留 10 分钟。过期后读取查询结果会返回 `410 result_expired`。

## 7. 常见错误

```text
400 invalid_request          请求格式错误或 IP 非法
401 invalid_api_key          API Token 不存在、禁用、吊销或过期
403 permission_denied        Token 缺少所需权限
404 node_not_found           节点不存在或不在 Token 白名单中
404 query_not_found          查询不存在或不属于当前 Token
409 node_offline             节点离线
409 capability_missing       节点不支持 BIRD 路由查询
410 result_expired           查询结果已过期
429 query_queue_full         节点查询队列已满
```

错误响应格式：

```json
{
  "error": {
    "code": "node_offline",
    "message": "节点当前离线，无法执行查询"
  }
}
```

## 8. 完整调用流程

```bash
# 1. 读取节点
curl -H "Authorization: Bearer l42lg_xxx_xxx" \
  https://link42.example.com/third-party-api/looking-glass/v1/nodes

# 2. 对指定节点提交 BIRD 查询
curl -i \
  -H "Authorization: Bearer l42lg_xxx_xxx" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.1.1.1"}' \
  https://link42.example.com/third-party-api/looking-glass/v1/nodes/node_8/bird/routes:lookup

# 3. 使用返回的 query_id 轮询结果
curl -H "Authorization: Bearer l42lg_xxx_xxx" \
  https://link42.example.com/third-party-api/looking-glass/v1/queries/lgq_xxx
```
