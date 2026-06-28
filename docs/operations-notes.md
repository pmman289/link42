# Link42 运行约定与踩坑记录

## 当前本地实机访问方式

- API 监听：`0.0.0.0:8000`
- 前端监听：`0.0.0.0:5173`
- 局域网前端地址：`http://192.168.123.20:5173/`
- 局域网 API 健康检查：`http://192.168.123.20:8000/api/health`

## 启动约定

- API 可前台启动：
  - `.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000`
- 前端生产预览可前台启动：
  - `npm run preview -- --host 0.0.0.0 --port 5173`
- Agent 不要直接前台执行后阻塞当前工作流。
- Agent 应使用 systemd、独立后台会话、或明确可管理的长期进程方式启动。
- 实机 Agent 环境变量：
  - `LINK42_SERVER_URL=http://192.168.123.20:8000`
  - `LINK42_NODE_ID=<节点 ID>`
  - `LINK42_AGENT_TOKEN=<节点 token>`
  - `LINK42_WIREGUARD_DIR=/etc/wireguard`
  - `LINK42_AGENT_DRY_RUN=0`
  - `LINK42_POLL_INTERVAL=2`
- 当前实测节点：
  - `node_id=2`
  - `name=nodetest`
  - `agent_token=l42agent_YGhpdQRV5yBGkWhOo9Rxs9UzCmEqFW8x822OR7ETgsI`

## 数据库

- 默认数据库文件是项目根目录的 `link42.db`。
- 清空本地测试库时删除 `link42.db`，API 重启后会自动创建新库。
- 删除数据库会让所有旧节点 token 失效。
- 旧 SQLite 数据库不会自动获得 SQLAlchemy 新增的表约束。
- 当前实现已在启动时清理重复 Peer，并补 `uq_wg_peer_interface_id` 唯一索引。
- 第一版没有 Alembic 迁移链，后续正式化部署前应补迁移。

## 生产实机注意事项

- `LINK42_AGENT_DRY_RUN=0` 会真实写入 `/etc/wireguard` 并执行 `wg-quick`。
- 用户确认 Change Plan 后，Agent 才会执行写入和 `wg-quick`。
- 生成 Change Plan 时使用数据库中的 `deployed_config` 作为基线。
- 没有 diff 的 Change Plan 不允许确认部署，前端禁用按钮，后端也拒绝提交。
- 部署成功后会更新 `deployed_config`，并将接口运行状态记录为 `running`。
- 启动和断开 WireGuard 连接通过 Agent 任务执行，并以 `runtime_status` 作为页面状态展示依据。
- 删除 WireGuard 配置前必须先断开连接，且不能存在同配置的忙碌任务。
- 导入扫描只读 `/etc/wireguard/*.conf`，不会写文件。
- 接管导入配置会先生成计划；确认后 Agent 写入前会备份旧配置。
- 多 Peer 导入配置只能观察，不能直接接管。

## 已遇到的坑

- 不能把 Agent 当普通命令直接前台执行；它是轮询进程，会阻塞当前交互。
- Vite 的 `5173` 可能被旧进程占用；需要先清理旧前端进程。
- 前端生产预览不带开发代理，不能依赖 `/api` 同源代理。
- 因此前端已改为自动访问当前主机的 `8000` 端口。
- 从受限工具沙箱里直接 `curl 127.0.0.1` 可能误报连接失败；确认服务状态时要注意网络命名空间。
- FastAPI `TestClient` 在当前环境曾出现挂起，因此部分规则测试使用 DB/service 层测试。
- `sqlite3` 命令行工具当前环境不可用，可用项目 `.venv` 里的 Python 查询 SQLite。
- `.git` 在当前工作区不可作为普通 Git 仓库使用，`git status` 会失败。

## 验证命令

- Python 测试：
  - `.venv/bin/python -m pytest -q`
- Python 编译检查：
  - `.venv/bin/python -m compileall apps/api apps/agent packages tests`
- 前端生产构建：
  - `npm run build`

## 当前验证结果

- Python 测试已通过：`13 passed`。
- Python 编译检查已通过。
- 前端生产构建已通过。
