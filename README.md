# Link42

Link42 是一个用来管理多节点 WireGuard 点对点链路的 Web 面板。

它适合 DN42、家庭网络、实验室网络、小型多机房内网这类场景：你有几台 Linux/OpenWrt 节点，希望少手写配置，能看清链路关系，并且可以安全地导入、接管和下发 WireGuard 配置。

## 主要功能

- 多节点管理：查看节点在线状态、Agent 版本、系统能力和地域分组。
- 受管连接：自动生成双方 WireGuard 密钥、Peer、Endpoint 和配置，下发到两端节点。
- 现有配置导入：扫描节点上的 `wg-quick` 配置，先作为观察记录导入，再决定是否接管。
- 拓扑视图：按受管连接生成拓扑图，支持拖拽保存位置和全屏查看编辑。
- 链路监测：对配置添加连通性监测，查看延迟和近期状态。
- 中间层支持：受管连接可启用 `udp2raw` 或 `mimic`。
- OpenWrt 支持：OpenWrt 节点通过 UCI/procd 管理 WireGuard。
- 数据保护：删除默认只删面板记录，不会直接删除节点上的 WireGuard 配置；版本升级时会保留上一个数据库备份。

## 快速开始

准备一个主控目录：

```bash
sudo mkdir -p /opt/link42
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

打开面板：

```text
http://<主控IP>:8000
```

首次启动会自动生成登录密码，在容器日志里查看：

```bash
docker logs link42
```

登录后建议先进入“设置”，确认主控访问地址，例如：

```text
http://192.168.1.10:8000
```

这个地址会写进节点 Agent 的安装命令里，节点必须能访问它。

## 接入第一台节点

1. 在面板里添加节点，填写名称、地域和入口地址。
2. 打开节点设置，复制 Agent 安装命令。
3. 到节点机器上执行安装命令。
4. 等节点变为 online 后，就可以创建或导入 WireGuard 配置。

安装命令大致长这样，实际请以面板生成的为准：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo env \
  LINK42_SERVER_URL='http://主控地址:8000' \
  LINK42_NODE_ID='1' \
  LINK42_AGENT_TOKEN='l42agent_xxx' \
  sh
```

Agent 会安装依赖、写入 `/etc/link42/agent.env`，并注册为系统服务。卸载 Agent：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo sh -s -- uninstall
```

卸载 Agent 不会删除已有 WireGuard 配置。

## 常见使用流程

### 创建两台受管节点之间的连接

1. 两台节点都安装 Agent，并处于 online。
2. 在其中一台节点下点击“创建受管连接”。
3. 选择对端节点，填写双方接口名、隧道地址、入口地址和 AllowedIPs。
4. 保存后 Link42 会生成双方配置，并下发启动任务。

受管连接适合 Link42 完整管理两端配置的场景。创建、修改、启动、停止、删除都会按双端整体处理。

### 导入已有 WireGuard 配置

1. 在节点页面点击“扫描现有 wg-quick”。
2. 对扫描到的配置点击“导入”。
3. 导入后它只是观察记录，不会修改节点文件。
4. 需要交给 Link42 管理时，再选择“接管导入配置”或“导入为受管连接”。

接管前会生成部署计划。只有确认计划后，Agent 才会写入节点配置。

### 删除配置

删除时默认只删除 Link42 面板记录，保留节点上的 WireGuard 配置文件和服务。

只有勾选“同时删除节点上的 WireGuard 配置文件和服务”时，Link42 才会下发节点清理任务。未接管的导入观察记录始终只删除面板记录。

## 数据目录

推荐把整个 `/link42` 持久化到宿主机目录：

```text
/link42/data    SQLite 数据库和运行数据
/link42/config  站点配置、上传 logo 等配置文件
```

如果使用上面的 `docker run`，宿主机目录就是：

```text
/opt/link42/data
/opt/link42/config
```

升级前建议备份 `/opt/link42`。主控启动时也会为数据库保留上一版本备份，但只保留一个备份，避免长期运行后占用过多空间。

## 升级

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

如果你用 Compose，也可以参考 [deploy/docker-compose.yml](deploy/docker-compose.yml)。

## OpenWrt 节点

OpenWrt 节点通过 UCI/procd 管理 WireGuard，不依赖 `/etc/wireguard/*.conf` 或 `wg-quick`。

需要注意：

- OpenWrt 节点不支持 `wg-quick` 文件导入扫描。
- OpenWrt 作为 udp2raw server 时，Link42 不会自动修改 firewall zone，需要手动放行 udp2raw server 监听端口。
- OpenWrt 上的中间层能力取决于 Agent 上报的能力和平台支持情况。

## udp2raw 和 mimic

受管连接可以启用连接中间层。

`udp2raw` 适合把 WireGuard UDP 封装成 faketcp/udp/icmp 的场景。它是 client -> server 的单向封装，server 侧必须能被 client 访问。udp2raw 的地址参数必须填写 IP 字面量，不能填域名。

`mimic` 用于 Linux 网卡层透明处理 WireGuard 流量。启用 mimic 时，双方都必须填写真实 Endpoint 和 WireGuard ListenPort；mimic filter 也要求 IP 字面量。mimic 目前不支持 OpenWrt，需要非 OpenWrt Linux、systemd、kernel > 6.1，并完成 mimic 安装检测。

## 离线迁移镜像

导出镜像：

```bash
docker pull pmman/link42:latest
docker save pmman/link42:latest | gzip > link42-latest.tar.gz
```

目标机器导入并运行：

```bash
gunzip -c link42-latest.tar.gz | docker load
docker run -d \
  --name link42 \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /opt/link42:/link42 \
  pmman/link42:latest
```

## 常用环境变量

主控容器：

```text
LINK42_DATABASE_URL=sqlite:////link42/data/link42.db
LINK42_CONFIG_DIR=/link42/config
LINK42_WEB_DIST_DIR=/opt/link42/web
LINK42_AGENT_OFFLINE_AFTER_SECONDS=15
```

Agent：

```text
LINK42_SERVER_URL=http://主控地址:8000
LINK42_NODE_ID=节点ID
LINK42_AGENT_TOKEN=节点Token
LINK42_WIREGUARD_DIR=/etc/wireguard
LINK42_AGENT_DRY_RUN=0
LINK42_POLL_INTERVAL=2
LINK42_AGENT_VERSION=latest
```

## 开发

安装依赖：

```bash
python3 -m pip install -e ".[dev]"
npm install --prefix apps/web
```

常用检查：

```bash
.venv/bin/python -m pytest -q
npm run build --prefix apps/web
git diff --check
```

构建主控镜像：

```bash
scripts/controller/build-image.sh
```

构建和发布说明见 [docs/release-build-and-push.md](docs/release-build-and-push.md)。

## 目录结构

```text
apps/api/        主控后端
apps/web/        Web 面板
apps/agent/      节点 Agent
packages/        共享代码和 WireGuard 解析/渲染逻辑
deploy/          Docker Compose、systemd、安装脚本
scripts/         构建、发布和测试脚本
docs/            架构、测试、发布和交接文档
```
