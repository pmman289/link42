# Link42

> [!WARNING]
> 本项目100%由天才程序员(GPT)生成，含人量约等于0，请谨慎使用，如有BUG敬请反馈

Link42 是一个轻量的 WireGuard 节点和点对点链路管理面板，偏向 DN42、家庭网络和小型内网场景。主控使用 Docker 部署，节点侧运行 Agent，由主控下发 WireGuard 配置、启停任务和连接中间层任务。

## 功能概览

- 管理多台受管节点，查看 Agent 在线状态、版本和能力。
- 创建普通 WireGuard 点对点配置，生成部署计划后下发。
- 创建受管双向链路，自动生成双方密钥、Peer 和配置。
- 导入现有 `wg-quick` 配置，支持接管或转为受管连接。
- 支持 Linux systemd/OpenRC 和 OpenWrt UCI/procd Agent 后端。
- 支持 udp2raw 连接中间层，适合需要封装 WireGuard UDP 的链路。
- 单用户登录鉴权，首次启动自动生成密码并输出到 Docker 日志。
- 支持删除 Link42 记录但保留节点上的 WireGuard 配置，便于之后重新导入。

## 快速部署主控 Docker

推荐把运行数据和配置都放在一个母目录下，例如 `/opt/link42`：

```bash
sudo mkdir -p /opt/link42/data /opt/link42/config
```

启动主控：

```bash
docker run -d \
  --name link42 \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /opt/link42:/link42 \
  pmman/link42:latest
```

访问：

```text
http://<主控IP>:8000
```

查看首次启动密码：

```bash
docker logs link42
```

容器内目录：

```text
/link42/data    SQLite 数据库和运行数据，默认数据库为 /link42/data/link42.db
/link42/config  预留配置目录，方便后续挂载配置文件
```

映射说明：

- 端口 `8000/tcp`：Web 面板和 API 共用端口。
- 宿主机 `/opt/link42/data`：必须持久化，保存数据库。
- 宿主机 `/opt/link42/config`：预留给运行配置，建议一起备份。

升级主控镜像：

```bash
docker pull pmman/link42:latest
docker stop link42
docker rm link42
docker run -d \
  --name link42 \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /opt/link42:/link42 \
  pmman/link42:latest
```

## 离线迁移镜像

导出镜像：

```bash
docker pull pmman/link42:latest
docker save pmman/link42:latest | gzip > link42-latest.tar.gz
```

目标机器导入：

```bash
gunzip -c link42-latest.tar.gz | docker load
docker run -d \
  --name link42 \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /opt/link42:/link42 \
  pmman/link42:latest
```

## 首次使用流程

1. 启动主控容器。
2. 用 `docker logs link42` 查看首次生成的登录密码。
3. 打开 `http://<主控IP>:8000` 登录。
4. 进入设置页，设置主控访问地址，例如：

```text
http://192.0.2.10:8000
```

5. 添加节点，填写节点名称和可被其它节点访问的入口地址。
6. 在节点设置里复制部署命令，到节点机器上执行。
7. Agent 上线后创建 WireGuard 配置或受管连接。

主控访问地址会影响前端生成的 Agent 部署命令。修改后，节点设置里的部署命令会使用新的地址。

## 安装节点 Agent

在 Web 面板里添加节点后，复制节点设置中的命令。命令形态类似：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo env \
  LINK42_SERVER_URL='http://主控地址:8000' \
  LINK42_NODE_ID='1' \
  LINK42_AGENT_TOKEN='l42agent_xxx' \
  sh
```

Agent 安装脚本会：

- 安装必要依赖，例如 `wireguard-tools`、`curl`、OpenWrt 上的 `python3`。
- 下载匹配平台的 Agent。
- 写入 `/etc/link42/agent.env`。
- 创建并启动系统服务。

支持后端：

```text
Linux systemd      wg-quick + systemd
Linux OpenRC       wg-quick + OpenRC
OpenWrt UCI/procd  UCI network + procd
```

卸载 Agent：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo sh -s -- uninstall
```

卸载只移除 Agent 程序、环境文件和 Agent 服务，不会删除已有 WireGuard 配置。

## OpenWrt 说明

OpenWrt 节点使用源码包安装，Agent 通过 UCI 写入 WireGuard 配置，不依赖 `/etc/wireguard/*.conf` 或 `wg-quick`。

注意：

- OpenWrt 节点不支持 `wg-quick` 文件导入扫描。
- OpenWrt 作为 udp2raw server 时，Link42 不自动修改 firewall zone；需要用户手动在实际入口区域放行 udp2raw server 监听端口。
- udp2raw IP 参数必须是 IPv4/IPv6 字面量，不能填域名。

## WireGuard 删除策略

删除配置时，面板会弹出确认窗口：

- 默认只删除 Link42 主控记录，保留节点上的 WireGuard 配置文件和服务。
- 勾选“同时删除节点上的 WireGuard 配置文件和服务”后，才会下发节点清理任务。
- 未接管的导入观察记录始终只删除面板记录，不修改节点原始文件。

这个设计方便误删后重新扫描导入，也避免默认破坏节点上的现有网络。

## udp2raw 连接中间层

受管连接可以启用 udp2raw：

```text
WireGuard UDP -> udp2raw client 本地 UDP 监听端口
udp2raw client -> faketcp/udp/icmp -> udp2raw server IP:port
udp2raw server -> UDP -> server_forward_host:server_forward_port
```

关键约束：

- udp2raw 是单向 client -> server 封装。
- 只有 udp2raw server 所在一侧必须填写 WireGuard `ListenPort`。
- `server_forward_port` 可留空，主控会回退到 server 侧 WireGuard `ListenPort`。
- 启用连接中间层时，面板会把 MTU 默认调整到 `1300`，用户仍可手动修改。

## 常用环境变量

主控容器常用变量：

```text
LINK42_DATABASE_URL=sqlite:////link42/data/link42.db
LINK42_CONFIG_DIR=/link42/config
LINK42_WEB_DIST_DIR=/opt/link42/web
LINK42_AGENT_OFFLINE_AFTER_SECONDS=15
```

Agent 常用变量：

```text
LINK42_SERVER_URL=http://主控地址:8000
LINK42_NODE_ID=节点ID
LINK42_AGENT_TOKEN=节点Token
LINK42_WIREGUARD_DIR=/etc/wireguard
LINK42_AGENT_DRY_RUN=0
LINK42_POLL_INTERVAL=2
LINK42_AGENT_VERSION=latest
```

## 构建与发布

安装开发依赖：

```bash
python3 -m pip install -e ".[dev]"
npm install --prefix apps/web
```

运行测试和前端构建：

```bash
.venv/bin/pytest -q
npm run build --prefix apps/web
git diff --check
```

构建主控镜像：

```bash
scripts/controller/build-image.sh
```

构建并推送到 DockerHub：

```bash
scripts/controller/push-image.sh tagname
```

导出镜像：

```bash
scripts/controller/export-image.sh tagname
```

完整发布流程见：

```text
docs/release-build-and-push.md
```

## 项目结构

```text
apps/api/        FastAPI 主控后端
apps/web/        React Web 面板
apps/agent/      节点 Agent
packages/        共享包和 WireGuard 解析/渲染逻辑
deploy/          Docker Compose、systemd、安装脚本
scripts/         构建、发布和测试脚本
docs/            架构、测试、发布和交接文档
udp2raw_sh/      udp2raw 资产和参考脚本
```

更完整的目录说明见：

```text
docs/project-structure.md
```

## 安全提示

- Link42 是可信内网管理面板，主控可以下发真实网络配置。
- 请不要把主控端口直接暴露到不可信公网。
- Agent 非 dry-run 模式会真实写入系统 WireGuard 配置并执行启停命令。
- OpenWrt/家庭路由器测试要谨慎，避免破坏现有网络。
