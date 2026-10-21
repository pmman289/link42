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
  - `agent_token=<REDACTED_AGENT_TOKEN>`
- 清库后旧 token 全部失效；最近一轮双节点测试曾使用：
  - `node1=<REDACTED_AGENT_TOKEN>`
  - `node2=<REDACTED_AGENT_TOKEN>`
- 单机可以模拟两个 Agent，但要避免接口名冲突；真实 `/etc/wireguard` 模式下两个 Agent 会操作同一台机器的同一套 WireGuard 环境。

## 数据库

- 默认数据库文件是项目根目录的 `link42.db`。
- 清空本地测试库时删除 `link42.db`，API 重启后会自动创建新库。
- 删除数据库会让所有旧节点 token 失效。
- 旧 SQLite 数据库不会自动获得 SQLAlchemy 新增的表约束。
- 当前实现已在启动时清理重复 Peer，并补 `uq_wg_peer_interface_id` 唯一索引。
- 第一版没有 Alembic 迁移链，后续正式化部署前应补迁移。

## 地址管理功能移除

- 地址池、占用台账、空闲地址推荐、外部预留及 `/api/ipam` 接口已移除；节点与链路地址改为手工填写，不再执行全局地址分配或冲突检查。
- 已登记的节点固定 IPv4、WireGuard/GRE 隧道地址和已部署配置保留，现有 Agent 无需重装。
- 升级不会删除旧地址池表，但主控不再读取或更新这些表。节点地址继续使用原有存储表，避免丢失历史登记。

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

- 安装脚本问题核实、修复和兼容说明见 [安装脚本审查记录](installer-audit.md)。

- x64 Agent 二进制构建：
  - `scripts/agent/build-x64.sh`
- Agent 默认通过 `python:3.11-slim-bullseye` Docker 容器构建，避免在新 glibc 主机上打出的 PyInstaller 产物无法在旧 Debian 上运行。
- 如果目标机器报 `GLIBC_2.38 not found`，说明二进制是在过新的 glibc 环境构建的，需要重新用默认 Docker 构建脚本打包并发布。
- 产物路径：
  - `dist/agent/link42-agent-linux-x64`
- 一键安装脚本：
  - `deploy/sh/link42-agent.sh`
- 预期安装脚本 URL：
  - `http://controller:8000/sh/link42-agent.sh`
- 预期二进制资源 URL：
  - `http://controller:8000/res/link42/link42-agent-linux-x64`
- 前端展示命令形如：
  - `curl -fsSL http://controller:8000/sh/link42-agent.sh | sudo env LINK42_SERVER_URL='http://controller:8000' LINK42_NODE_ID='1' LINK42_AGENT_TOKEN='token' sh`
- 一键卸载命令：
  - `curl -fsSL http://controller:8000/sh/link42-agent.sh | sudo sh -s -- uninstall`
- 安装脚本会尝试安装 `wireguard-tools`，下载 Agent 二进制，并按 systemd 或 OpenRC 注册服务。
- 卸载脚本会删除 Agent 服务、二进制和 `/etc/link42/agent.env`，不会删除 `/etc/wireguard` 下的配置。
- OpenWrt/OpenRC 支持仍要谨慎测试；用户提供过 `ssh mrouter` 的家庭路由器环境，但不能破坏上面的现有网络。

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

## 静态页面请求后主控卡死（0.6.25 修复）

症状是日志已记录“主控启动完成”，随后一个 CPU 核心持续满载，面板和 `/api/health` 都超时。生产环境 Starlette 1.8.0 的 `FileResponse` 在 ASGI 2.3 下会等待 `http.disconnect`；请求体限制中间件若在回放完请求体后反复返回空 `http.request`，会形成不让出事件循环的忙循环。

`0.6.25` 修改为只回放一次完整请求体，后续调用转发底层 `receive()`，等待真实连接事件。请求体大小限制保持不变。回归检查同时覆盖断开事件转发，以及有子进程超时保护的 ASGI 2.3 静态文件响应；还需使用实际生产依赖验证“读取面板后健康检查仍正常”。仅有 JSON 接口测试或启动完成日志无法覆盖此问题。

生产排查先查看容器健康状态、CPU 和 Python 调用栈，避免把事件循环卡死误判为数据库迁移失败。修改前备份数据库和原代码；应把修复写入镜像，避免仅修改容器可写层后在重建时丢失。紧急恢复可保留停止状态的旧容器，但旧、新主控不得同时连接同一运行目录。

## 全新安装挂载空目录后容器退出（0.6.26 修复）

公网 `0.6.25` 镜像按 README 将空宿主机目录挂载到 `/link42` 时，可复现启动失败并以退出码 `3` 停止，日志包含 `sqlite3.OperationalError: unable to open database file`。绑定挂载会遮住镜像中预建的 `/link42/data`，而 SQLite 不会自动创建数据库父目录；已使用的数据目录和自动填充的新 Docker 命名卷可能掩盖此问题。

`0.6.26` 在 `init_db()` 连接 SQLite 之前按实际数据库路径创建父目录，同时覆盖默认路径和自定义多级路径。发布验证使用 `volume-nocopy` 保证挂载目录为空，并在读取面板后再次检查健康接口。

较早镜像可先补建实际挂载目录中的子目录，再启动原容器。README 默认路径示例：

```bash
sudo mkdir -p /opt/link42/data /opt/link42/config
docker start link42
```

这只补建目录，不需要删除数据库或重新创建运行卷。权限、磁盘空间或其它退出原因仍应依据具体启动日志排查。

## 安装资源统一由主控提供（0.6.27）

主控和 Web 版本提升至 `0.6.27`，Agent 保持 `0.6.23`，通信协议仍为 `1`。安装脚本、Agent latest/固定版本及摘要、UDP2RAW 独立安装资源均由自己的主控提供，发布流程不再上传独立资源站点。

部署前确认系统设置中的主控地址能被节点访问，反向代理同时转发 `/api/`、`/sh/` 和 `/res/`。旧的脚本和资源 URL 覆盖配置已停用；旧节点继续运行，无需轮换凭据，但之前保存的安装命令、脚本和 UDP2RAW 独立菜单需要重新获取。系统软件源和 mimic 官方下载保留。

完整迁移及下载验证方法见 [主控资源部署](agent-public-deployment.md)。本次通过后端 686 项测试、前端 46 项测试和前端构建，并验证真实镜像在空数据卷上的启动、匿名下载与摘要、登录、设置及升级命令。

## Agent 安装无输出退出及 systemd 启动失败

已在 Debian 13 测试节点复现两处安装脚本问题：安装操作跳过卸载路径探测时，裸 `return` 继承失败的条件比较结果，在 `set -e` 下以退出码 `1` 无输出结束；绕过这一步后，生成的 `EnvironmentFile="/path/agent.env"` 又被 systemd 当作非绝对路径忽略，导致 Agent 缺少 `LINK42_SERVER_URL` 并反复退出。

修复为跳过探测时显式返回 `0`；`EnvironmentFile=` 使用不包裹引号的绝对路径，并保留 `%` 转义和卸载时的路径恢复。安装路径禁止控制字符，systemd 启动后检查服务状态，失败时给出 journalctl 命令，不再报告安装成功。

新增完整入口、真实 systemd 配置解析及启动失败回归测试。全量 698 项测试通过；实机使用独立目录、独立 systemd 服务和临时主控验证首次安装、Agent 上线、恢复已有配置覆盖安装和卸载。测试期间已有 Agent 进程未重启，未修改已有软件包状态，临时服务和资源均已清理。修复需要随主控安装脚本发布，用户再从更新后的主控获取脚本执行覆盖安装；无需轮换现有节点凭据。

## 安装可靠性修复与地址池移除（0.6.28）

主控和 Web 版本提升至 `0.6.28`，Agent 保持 `0.6.23`，通信协议保持 `1`。本版包含上述安装静默退出和 systemd 环境文件修复，并为安装失败增加程序、配置、服务状态的恢复；补齐下载限制、UDP2RAW 摘要验证、菜单参数校验和安全环境文件解析。逐项结论与兼容说明见 [安装脚本审查记录](installer-audit.md)。

移除地址池、地址占用台账、空闲地址推荐及相关 API，保留节点已有内网地址与 WireGuard/GRE 配置；旧地址池表保留但不再使用。延迟任务仍校验配置身份，并兼容旧任务中的身份字段，避免误改重建后的接口。

CI 增加后端测试、前端测试及构建、Shell 语法检查；发布工具不再要求固定的虚拟环境路径，并校验 Agent 平台标签与实际 glibc 需求。

现有节点无需重新安装或轮换凭据。新版独立 UDP2RAW 脚本需要本版主控提供的摘要接口；旧主控缺少接口时安装会终止并保留旧程序。现有环境文件若使用命令或变量展开，需改为对应键的实际字面值。

验证通过后端 721 项测试、前端 44 项测试及生产构建，另完成真实主控镜像空卷启动、全部下载与摘要校验，以及 hyhk02 隔离服务的新装、覆盖安装、强制失败恢复和卸载。本次仅提交并推送代码，镜像发布与生产部署另行执行。

## 依赖安全更新（0.6.29）

主控和 Web 版本提升至 `0.6.29`，Agent 提升至 `0.6.24`，协议保持 `1`。本版将构建和 CI 的 Node.js 基础版本从 20/22 统一到受支持的 Node.js 24 LTS；Vite 更新至 `8.3.5`，Vitest 更新至 `4.1.12`，修复 npm audit 报告的 Vite `launch-editor` 高危问题及 Vitest mock 路径穿越问题。完整前端依赖审计结果为 0 个漏洞。

Python 依赖显式要求 `certifi>=2026.10.19`，修复 `PYSEC-2026-4320`；pip-audit 当前环境无已知漏洞。项目不包含 PHP 或 Composer 依赖，因此 PHP 运行时漏洞不在本项目技术栈内。

本次只更新依赖、构建基线和审计流程，不改变数据库结构或 Agent 协议；现有节点可继续运行，需发布新版主控及 Agent 资源后才能使用 Agent `0.6.24` 的更新代码。
