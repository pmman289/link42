# Agent 静态发布与节点部署方案

本文给构建发布人员使用，目标是把 Link42 Agent 安装脚本和二进制发布到
`https://get.pmman.tech`，让节点机器可以通过一条命令安装、覆盖升级或卸载 Agent。

静态站点服务器：

```text
ssh aligz
/opt/1panel/www/sites/get.pmman.tech/index
```

公开访问路径：

```text
https://get.pmman.tech/sh/link42-agent.sh
https://get.pmman.tech/res/link42/link42-agent-linux-x64
```

## 总体设计

Agent 发布分两条线：

1. **静态站点发布**：用于新节点安装和旧 Agent 手动覆盖升级。
2. **主控镜像内置 release**：用于支持 `agent.self_upgrade` 的新 Agent 由主控下发自升级任务。

两条线使用同一批 `dist/agent` 产物。构建人员每次发布 Agent 时，应同时更新静态站点和主控镜像内置的
`dist/controller-agent-releases`。

## 目录规范

服务器目录保持如下结构：

```text
/opt/1panel/www/sites/get.pmman.tech/index/
  sh/
    link42-agent.sh
  res/
    link42/
      manifest.json
      link42-agent-linux-x64
      link42-agent-linux-x64.sha256
      link42-agent-source.tar.gz
      link42-agent-source.tar.gz.sha256
      0.2.0/
        manifest.json
        link42-agent-linux-x64
        link42-agent-linux-x64.sha256
        link42-agent-source.tar.gz
        link42-agent-source.tar.gz.sha256
        link42-agent-linux-x64-0.2.0
        link42-agent-linux-x64-0.2.0.sha256
        link42-agent-linux-x64-glibc2.31-0.2.0
        link42-agent-linux-x64-glibc2.31-0.2.0.sha256
```

说明：

- `res/link42/link42-agent-linux-x64` 是 latest 安装入口使用的稳定文件名。
- `res/link42/link42-agent-source.tar.gz` 是 OpenWrt ARM/aarch64 源码安装入口使用的稳定文件名。
- `res/link42/<version>/link42-agent-linux-x64` 是固定版本安装入口使用的稳定文件名。
- 版本化文件保留在版本目录内，便于排查和人工下载。
- `.sha256` 必须和对应二进制同步发布。
- `manifest.json` 用于人工检查和后续扩展；当前安装脚本主要依赖固定文件名和 sha256。

## 构建 Agent

在仓库根目录执行：

```bash
git status --short --branch
scripts/agent/build-x64.sh
scripts/agent/build-source.sh
```

默认脚本使用 `python:3.11-slim-bullseye` 容器构建，避免在过新的系统上构建出依赖
`GLIBC_2.38` 的 PyInstaller 二进制。

检查产物：

```bash
dist/agent/link42-agent-linux-x64 --version
sha256sum -c dist/agent/link42-agent-linux-x64.sha256
cat dist/agent/manifest.json
```

产物示例：

```text
dist/agent/link42-agent-linux-x64
dist/agent/link42-agent-linux-x64.sha256
dist/agent/link42-agent-linux-x64-0.2.0
dist/agent/link42-agent-linux-x64-0.2.0.sha256
dist/agent/link42-agent-linux-x64-glibc2.31-0.2.0
dist/agent/link42-agent-linux-x64-glibc2.31-0.2.0.sha256
dist/agent/manifest.json
```

## 发布到 get.pmman.tech

先取版本号：

```bash
AGENT_VERSION="$(dist/agent/link42-agent-linux-x64 --version | awk '{print $NF}')"
echo "$AGENT_VERSION"
```

如果 `--version` 输出格式变化，也可以从共享版本文件读取：

```bash
AGENT_VERSION="$(python3 - <<'PY'
from pathlib import Path
import re
text = Path("packages/link42_common/version.py").read_text(encoding="utf-8")
print(re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text).group(1))
PY
)"
```

创建远端目录：

```bash
ssh aligz "mkdir -p /opt/1panel/www/sites/get.pmman.tech/index/sh /opt/1panel/www/sites/get.pmman.tech/index/res/link42/$AGENT_VERSION"
```

上传安装脚本：

```bash
scp deploy/sh/link42-agent.sh \
  aligz:/opt/1panel/www/sites/get.pmman.tech/index/sh/link42-agent.sh

ssh aligz "chmod 0755 /opt/1panel/www/sites/get.pmman.tech/index/sh/link42-agent.sh"
```

上传 latest 产物：

```bash
scp dist/agent/link42-agent-linux-x64 \
  dist/agent/link42-agent-linux-x64.sha256 \
  dist/agent/link42-agent-source.tar.gz \
  dist/agent/link42-agent-source.tar.gz.sha256 \
  dist/agent/manifest.json \
  aligz:/opt/1panel/www/sites/get.pmman.tech/index/res/link42/
```

上传固定版本产物：

```bash
scp dist/agent/link42-agent-linux-x64* \
  dist/agent/link42-agent-source.tar.gz \
  dist/agent/link42-agent-source.tar.gz.sha256 \
  dist/agent/manifest.json \
  aligz:/opt/1panel/www/sites/get.pmman.tech/index/res/link42/$AGENT_VERSION/
```

修正权限：

```bash
ssh aligz "chmod 0755 /opt/1panel/www/sites/get.pmman.tech/index/res/link42/link42-agent-linux-x64 /opt/1panel/www/sites/get.pmman.tech/index/res/link42/$AGENT_VERSION/link42-agent-linux-x64* && chmod 0644 /opt/1panel/www/sites/get.pmman.tech/index/res/link42/link42-agent-source.tar.gz /opt/1panel/www/sites/get.pmman.tech/index/res/link42/$AGENT_VERSION/link42-agent-source.tar.gz /opt/1panel/www/sites/get.pmman.tech/index/res/link42/*.sha256 /opt/1panel/www/sites/get.pmman.tech/index/res/link42/$AGENT_VERSION/*.sha256 /opt/1panel/www/sites/get.pmman.tech/index/res/link42/manifest.json /opt/1panel/www/sites/get.pmman.tech/index/res/link42/$AGENT_VERSION/manifest.json"
```

## 发布后验证

从公网检查脚本和二进制：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | head
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | grep -E 'stop_service|reload_service|status_service'
curl -fsSLO https://get.pmman.tech/res/link42/link42-agent-linux-x64
curl -fsSLO https://get.pmman.tech/res/link42/link42-agent-linux-x64.sha256
curl -fsSLO https://get.pmman.tech/res/link42/link42-agent-source.tar.gz
curl -fsSLO https://get.pmman.tech/res/link42/link42-agent-source.tar.gz.sha256
sha256sum -c link42-agent-linux-x64.sha256
sha256sum -c link42-agent-source.tar.gz.sha256
chmod +x link42-agent-linux-x64
./link42-agent-linux-x64 --version
rm -f link42-agent-linux-x64 link42-agent-linux-x64.sha256 link42-agent-source.tar.gz link42-agent-source.tar.gz.sha256
```

检查固定版本：

```bash
curl -fsS "https://get.pmman.tech/res/link42/$AGENT_VERSION/link42-agent-linux-x64.sha256"
curl -fsS "https://get.pmman.tech/res/link42/$AGENT_VERSION/link42-agent-source.tar.gz.sha256"
curl -fsS "https://get.pmman.tech/res/link42/$AGENT_VERSION/manifest.json"
```

如果某台旧系统之前报过 `GLIBC_2.38 not found`，发布后应在该系统上执行：

```bash
curl -fsSLO https://get.pmman.tech/res/link42/link42-agent-linux-x64
chmod +x link42-agent-linux-x64
./link42-agent-linux-x64 --version
```

能正常输出版本才算兼容。

## 节点安装命令

新节点安装需要主控里创建节点后拿到 `node_id` 和 `agent_token`：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env \
  LINK42_SERVER_URL='http://主控地址:8000' \
  LINK42_NODE_ID='节点ID' \
  LINK42_AGENT_TOKEN='节点Token' \
  sh
```

固定版本安装：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env \
  LINK42_AGENT_VERSION='0.2.0' \
  LINK42_SERVER_URL='http://主控地址:8000' \
  LINK42_NODE_ID='节点ID' \
  LINK42_AGENT_TOKEN='节点Token' \
  sh
```

覆盖升级已有节点时，如果 `/etc/link42/agent.env` 已存在，可以只指定版本：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env LINK42_AGENT_VERSION='0.2.0' sh
```

安装脚本会保留已有：

```text
LINK42_SERVER_URL
LINK42_NODE_ID
LINK42_AGENT_TOKEN
```

除非命令行环境变量显式覆盖它们。

## 节点卸载命令

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo sh -s -- uninstall
```

卸载会删除：

```text
/usr/local/bin/link42-agent
/etc/link42/agent.env
/opt/link42-agent
link42-agent systemd/OpenRC 服务
Link42 管理的 udp2raw 中间层服务、配置和资产
```

卸载不会删除：

```text
/etc/wireguard
```

如需保留 Link42 管理的 udp2raw 中间层资产，可显式设置：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env LINK42_KEEP_MIDDLEWARE=1 sh -s -- uninstall
```

## systemd 节点检查命令

```bash
link42-agent --version
systemctl status link42-agent --no-pager
journalctl -u link42-agent --no-pager -n 80
```

常见成功日志应包含注册、心跳或轮询任务；如果主控地址、节点 ID、token 错误，日志会显示认证失败或连接失败。

## 回滚方案

静态站点回滚分两种：

1. **latest 回滚**：把 `res/link42/link42-agent-linux-x64` 和 `.sha256` 覆盖回上一版。
2. **节点回滚**：在节点上执行固定旧版本安装命令。

示例：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh |
sudo env LINK42_AGENT_VERSION='0.1.0' sh
```

建议构建人员不要删除旧版本目录，至少保留最近 3 个版本：

```text
res/link42/0.1.0
res/link42/0.2.0
res/link42/0.2.1
```

## 与主控镜像发布的关系

静态站点发布完成后，还需要准备主控镜像内置 Agent release：

```bash
scripts/agent/prepare-release-assets.sh
find dist/controller-agent-releases -maxdepth 1 -type f -print
```

然后按 `docs/release-build-and-push.md` 构建并推送主控镜像：

```bash
IMAGE_TAG="$AGENT_VERSION" IMAGE_REPO="pmman/link42" scripts/controller/push-image.sh
```

这样：

- 新节点可以使用 `get.pmman.tech` 的安装脚本。
- 旧 Agent 可以用安装脚本手动覆盖升级。
- 新 Agent 可以通过主控内置 release 走 `agent.self_upgrade`。

## 构建人员发布清单

每次发布 Agent 至少确认：

- `scripts/agent/build-x64.sh` 已成功。
- `dist/agent/link42-agent-linux-x64 --version` 输出正确版本。
- `sha256sum -c dist/agent/link42-agent-linux-x64.sha256` 通过。
- `deploy/sh/link42-agent.sh` 已上传到 `get.pmman.tech/sh/`。
- latest 二进制和 sha256 已上传到 `get.pmman.tech/res/link42/`。
- 固定版本目录已上传到 `get.pmman.tech/res/link42/<version>/`。
- 公网 `curl` 下载、sha256 校验、`--version` 验证通过。
- 主控镜像已包含同版本 Agent release manifest。
