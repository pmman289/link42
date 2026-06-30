# Agent x64 二进制构建

当前只支持在 Linux x86_64 主机上构建 x64 Agent 单文件二进制。

Linux 单文件二进制仍会受 glibc 版本影响。不要在过新的发行版上直接用本机
Python 构建后发给旧系统运行，否则可能出现类似下面的错误：

```text
Failed to load Python shared library ... GLIBC_2.38 not found
```

默认构建脚本会使用 `python:3.11-slim-bullseye` 容器构建，让产物依赖更老的
glibc，适合 Debian 11/12 等常见服务器。

## 准备

```bash
docker version
```

## 构建

```bash
scripts/agent/build-x64.sh
```

产物：

```bash
dist/agent/link42-agent-linux-x64
```

如果明确只想使用本机 Python 构建，可以执行：

```bash
LINK42_AGENT_BUILD_MODE=local scripts/agent/build-x64.sh
```

本机构建需要先安装 PyInstaller：

```bash
.venv/bin/python -m pip install pyinstaller
```

## 运行

```bash
LINK42_SERVER_URL=http://主控地址:8000 \
LINK42_NODE_ID=节点ID \
LINK42_AGENT_TOKEN=节点Token \
LINK42_WIREGUARD_DIR=/etc/wireguard \
LINK42_AGENT_DRY_RUN=0 \
LINK42_POLL_INTERVAL=2 \
./dist/agent/link42-agent-linux-x64
```

这个二进制仍会调用宿主机上的 `wg`、`wg-quick`、`systemctl`、`rc-service`、`uci`、`ifup` 等系统命令；它只是不再要求目标机器预装 Python 包。

## 一键安装脚本

发布脚本路径：

```bash
deploy/sh/link42-agent.sh
```

预期发布 URL：

```bash
https://get.pmman.tech/sh/link42-agent.sh
```

脚本默认从下面的资源目录下载 x64 Agent 二进制：

```bash
https://get.pmman.tech/res/link42/link42-agent-linux-x64
```

前端展示的安装命令形如：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo env LINK42_SERVER_URL='http://controller:8000' LINK42_NODE_ID='1' LINK42_AGENT_TOKEN='token' sh
```

一键卸载：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo sh -s -- uninstall
```

卸载会停止并删除 Agent 服务、二进制和 `/etc/link42/agent.env`，不会删除
`/etc/wireguard` 下的 WireGuard 配置。

## OpenWrt ARM

OpenWrt ARM/aarch64 第一阶段不使用 glibc PyInstaller 二进制。安装脚本会在检测到
OpenWrt UCI/procd 后下载源码包：

```text
https://get.pmman.tech/res/link42/link42-agent-source.tar.gz
```

源码包由下面命令生成：

```bash
scripts/agent/build-source.sh
```

目标机要求：

- `python3`
- `curl` 或 `wget`
- `wireguard-tools`
- `uci`
- `ifup`
- `/etc/rc.common`

安装后会写入：

```text
/opt/link42-agent/src
/usr/local/bin/link42-agent
/etc/init.d/link42-agent
/etc/link42/agent.env
```

OpenWrt Agent 使用 UCI 写入 WireGuard 配置，不依赖 `/etc/wireguard/*.conf` 或
`wg-quick`。目前 OpenWrt 节点只上报基础 WireGuard/UCI 能力，不上报
`agent.self_upgrade` 和 systemd 版 udp2raw 中间层能力。
