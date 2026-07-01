# Link42 运行约定与踩坑记录

## 当前本地实机访问方式

- API 监听：`0.0.0.0:8000`
- 前端监听：`0.0.0.0:5173`
- 局域网前端地址：`http://192.0.2.10:5173/`
- 局域网 API 健康检查：`http://192.0.2.10:8000/api/health`

## 启动约定

- API 可前台启动：
  - `.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000`
- 前端生产预览可前台启动：
  - `npm run preview -- --host 0.0.0.0 --port 5173`
- Agent 不要直接前台执行后阻塞当前工作流。
- Agent 应使用 systemd、独立后台会话、或明确可管理的长期进程方式启动。
- 实机 Agent 环境变量：
  - `LINK42_SERVER_URL=http://192.0.2.10:8000`
  - `LINK42_NODE_ID=<节点 ID>`
  - `LINK42_AGENT_TOKEN=<节点 token>`
  - `LINK42_WIREGUARD_DIR=/etc/wireguard`
  - `LINK42_AGENT_DRY_RUN=0`
  - `LINK42_POLL_INTERVAL=2`
- 当前实测节点：
  - `node_id=2`
  - `name=nodetest`
  - `agent_token=l42agent_xxx`
- 清库后旧 token 全部失效；最近一轮双节点测试曾使用：
  - `node1=l42agent_xxx`
  - `node2=l42agent_xxx`
- 单机可以模拟两个 Agent，但要避免接口名冲突；真实 `/etc/wireguard` 模式下两个 Agent 会操作同一台机器的同一套 WireGuard 环境。

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
- 受管节点间连接不走手动 Change Plan 确认；创建、编辑、启动、停止、删除会按双端整体操作。
- 受管节点间连接创建后应直接下发双方配置、启动双方连接并 enable 开机自启。
- 删除受管节点间连接前必须先停止双方连接。
- `Table = off` 的产品含义是不让 `wg-quick` 自动生成路由。
- MTU 默认值为 `1420`。
- 高级自定义配置会插入到 `[Interface]` 或 `[Peer]` 后；受管连接需要区分双方四段自定义文本。

## Agent 安装与发布

- x64 Agent 二进制构建：
  - `scripts/agent/build-x64.sh`
- Agent 默认通过 `python:3.11-slim-bullseye` Docker 容器构建，避免在新 glibc 主机上打出的 PyInstaller 产物无法在旧 Debian 上运行。
- 如果目标机器报 `GLIBC_2.38 not found`，说明二进制是在过新的 glibc 环境构建的，需要重新用默认 Docker 构建脚本打包并发布。
- 产物路径：
  - `dist/agent/link42-agent-linux-x64`
- 一键安装脚本：
  - `deploy/sh/link42-agent.sh`
- 预期安装脚本 URL：
  - `https://get.pmman.tech/sh/link42-agent.sh`
- 预期二进制资源 URL：
  - `https://get.pmman.tech/res/link42/link42-agent-linux-x64`
- 前端展示命令形如：
  - `curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo env LINK42_SERVER_URL='http://controller:8000' LINK42_NODE_ID='1' LINK42_AGENT_TOKEN='token' sh`
- 一键卸载命令：
  - `curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo sh -s -- uninstall`
- 安装脚本会尝试安装 `wireguard-tools`，下载 Agent 二进制，并按 systemd 或 OpenRC 注册服务。
- 卸载脚本会删除 Agent 服务、二进制和 `/etc/link42/agent.env`，不会删除 `/etc/wireguard` 下的配置。
- OpenWrt/OpenRC 支持仍要谨慎测试；真实家庭路由器环境不能破坏现有网络。

## 主控 Docker 镜像

- 主控镜像 Dockerfile：
  - `Dockerfile.controller`
- 构建脚本：
  - `scripts/controller/build-image.sh`
- 构建并推送 DockerHub：
  - `scripts/controller/push-image.sh tagname`
- 镜像导出脚本：
  - `scripts/controller/export-image.sh`
- 默认镜像名：
  - `pmman/link42:latest`
- 容器端口：
  - `8000/tcp`
- 容器内运行目录统一放在一个母目录下，方便整体映射：
  - `/link42/data`：SQLite 数据库和运行数据，默认 `LINK42_DATABASE_URL=sqlite:////link42/data/link42.db`。
  - `/link42/config`：预留配置文件目录，供用户 bind mount。
- 前端构建产物目录：
  - `/opt/link42/web`
- FastAPI 通过 `LINK42_WEB_DIST_DIR=/opt/link42/web` 托管 React build 后的静态文件。
- Docker Compose 文件：
  - `deploy/docker-compose.yml`
- Compose 默认使用名为 `link42-runtime` 的 volume 映射到 `/link42`。
- 复制到其它机器运行时可先导出镜像：
  - `scripts/controller/export-image.sh`
- 目标机器拉取并运行：
  - `docker pull pmman/link42:tagname`
  - `docker run -d --name link42-controller -p 8000:8000 -v /opt/link42:/link42 pmman/link42:tagname`
- 或导入 tar 后运行：
  - `docker load -i link42-controller-latest.tar`
  - `docker run -d --name link42-controller -p 8000:8000 -v /opt/link42:/link42 pmman/link42:latest`

## 已遇到的坑

- 不能把 Agent 当普通命令直接前台执行；它是轮询进程，会阻塞当前交互。
- Vite 的 `5173` 可能被旧进程占用；需要先清理旧前端进程。
- 前端生产预览不带开发代理，不能依赖 `/api` 同源代理。
- 因此前端已改为自动访问当前主机的 `8000` 端口。
- 从受限工具沙箱里直接 `curl 127.0.0.1` 可能误报连接失败；确认服务状态时要注意网络命名空间。
- FastAPI `TestClient` 在当前环境曾出现挂起，因此部分规则测试使用 DB/service 层测试。
- `sqlite3` 命令行工具当前环境不可用，可用项目 `.venv` 里的 Python 查询 SQLite。
- 当前工作树曾出现几乎所有文件从 `100644` 变为 `100755` 的模式变化，`git diff --stat` 显示 0 行变更；不要把这类权限漂移当作业务改动提交。
- Git 操作、push、Docker build、联网安装依赖通常需要沙箱提升权限。

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
