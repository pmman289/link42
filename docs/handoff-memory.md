# Link42 当前交接记忆

本文用于在长对话、上下文压缩、或切换协作者后快速恢复现场。

## 当前产品状态

- Link42 是轻量级内网 WireGuard 节点和点对点链路管理面板。
- 当前架构为中心 FastAPI + SQLite、React/Vite 前端、Python 节点 Agent。
- 产品核心规则：一个 WireGuard 配置等同一根点对点虚拟网线；每个受管配置在部署前必须只有一个对端。
- 前端主流程已经调整为层级结构：先看节点列表，点击在线节点后展开该节点的 WireGuard 配置列表，点击具体配置后打开配置和 peer 操作窗口。

## 当前本机测试环境

- 工作目录：`/root/repo/link42`
- 前端地址：`http://192.168.123.20:5173/`
- API 地址：`http://192.168.123.20:8000`
- API 健康检查：`http://192.168.123.20:8000/api/health`
- 测试节点：
  - `node_id=2`
  - 节点名：`nodetest`
  - Agent token：`l42agent_YGhpdQRV5yBGkWhOo9Rxs9UzCmEqFW8x822OR7ETgsI`
- Agent 当前按实机模式运行：
  - `LINK42_SERVER_URL=http://192.168.123.20:8000`
  - `LINK42_NODE_ID=2`
  - `LINK42_AGENT_TOKEN=l42agent_YGhpdQRV5yBGkWhOo9Rxs9UzCmEqFW8x822OR7ETgsI`
  - `LINK42_WIREGUARD_DIR=/etc/wireguard`
  - `LINK42_AGENT_DRY_RUN=0`
  - `LINK42_POLL_INTERVAL=2`

## 最近完成的关键功能

- 节点创建时只需要填写主控地址和节点名称，并返回 Agent 安装 token。
- 新节点默认离线；Agent 注册或心跳后变为在线；心跳超时后变为离线。
- 离线节点不可点选和操作；若窗口已打开但提交时 Agent 离线，后端会返回离线错误。
- WireGuard 配置支持创建和修改，接口为 `PATCH /api/wireguard/configs/{id}`。
- peer 使用单对象语义，前端使用 `PUT/GET/DELETE /api/wireguard/configs/{id}/peer`。
- `wg_interfaces` 增加 `runtime_status` 和 `deployed_config`。
- 生成部署计划时使用 `deployed_config` 作为 diff 基线，避免部署成功后仍然出现同样 diff。
- 没有 diff 时不能下发任务，前端禁用确认按钮，后端也拒绝空 diff 计划。
- 部署成功后记录 `deployed_config`，并将运行状态标记为 `running`。
- Agent 支持任务：
  - `wireguard.apply_config`
  - `wireguard.read_config`
  - `wireguard.status`
  - `wireguard.start_interface`
  - `wireguard.stop_interface`
  - `wireguard.delete_config`
- 启动、断开、删除 WireGuard 配置已经加入幂等处理：
  - API 避免相同配置上重复创建同类 pending/running 任务。
  - start/stop 根据 `runtime_status` 做幂等返回。
  - Agent 使用 `wg show <iface>` 判断是否需要重复 `wg-quick up/down`。
- 删除配置前要求配置已停止且没有忙碌任务；删除 DB 记录后下发 `wireguard.delete_config`。
- 前端增加 toast 通知，不再把所有反馈堆在主页绿色条里。
- 前端增加基础输入校验，包括 CIDR、端口、WireGuard key 形状。
- 后端 schema 增加端口和 CIDR 形状校验。
- UI 已从三列并列展示改为节点列表、配置列表、配置窗口的层级交互。

## 当前验证结果

- `.venv/bin/python -m pytest -q` 已通过，最近结果为 `13 passed`。
- `.venv/bin/python -m compileall apps/api apps/agent packages tests` 已通过。
- `npm run build` 已通过。

## 常用命令

停止当前服务：

```bash
pkill -f 'uvicorn link42_api.main:app|npm run preview|vite.*5173|python -m link42_agent.main'
```

启动 API：

```bash
.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000
```

启动前端预览：

```bash
npm run preview -- --host 0.0.0.0 --port 5173
```

启动 node 2 Agent：

```bash
cd /root/repo/link42
setsid env LINK42_SERVER_URL=http://192.168.123.20:8000 LINK42_NODE_ID=2 LINK42_AGENT_TOKEN=l42agent_YGhpdQRV5yBGkWhOo9Rxs9UzCmEqFW8x822OR7ETgsI LINK42_WIREGUARD_DIR=/etc/wireguard LINK42_AGENT_DRY_RUN=0 LINK42_POLL_INTERVAL=2 .venv/bin/python -m link42_agent.main > /tmp/link42-agent-node2.log 2>&1 < /dev/null &
```

## 注意事项

- 用户正在实机测试，不要主动清空数据库，除非用户明确要求。
- Agent 是真实模式，不是 dry-run，会写 `/etc/wireguard` 并执行 `wg-quick`。
- 不要把 Agent 以前台命令启动，它会作为轮询进程阻塞当前交互。
- 当前 `.git` 目录在工作区里不可作为普通 Git 仓库使用，`git status` 可能失败。
- FastAPI `TestClient` 在当前环境曾经挂起，测试更偏向 service/DB 层。
- 手工编辑文件使用 `apply_patch`。
- Python 注释和 docstring 约定使用中文。

## 近期上下文

用户最近完成了基本功能测试，开始聚焦 UI 优化。最新一轮 UI 诉求包括：

- 错误提示不能显示成绿色条，应使用通知或弹窗形式。
- 成功提示也应使用通知形式，避免全部显示在主页。
- 弹窗关闭按钮应固定在窗口右上角，不随内容滚动消失。
- 无 diff 时不允许下发任务。
- 输入需要校验。
- 页面风格需要更美观，可以引用现成 CSS 库并增加优雅动画。

上述大部分已经实现，但仍需要继续接受用户实测反馈并迭代。
