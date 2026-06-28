# Agent x64 二进制构建

当前只支持在 Linux x86_64 主机上构建 x64 Agent 单文件二进制。

## 准备

```bash
.venv/bin/python -m pip install pyinstaller
```

## 构建

```bash
scripts/build-agent-x64.sh
```

产物：

```bash
dist/agent/link42-agent-linux-x64
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
