# Agent 主控分发

Agent 安装脚本和版本资源由 Link42 主控统一提供。构建主控镜像时会把 Agent 产物
放入镜像，节点通过主控 API 下载，不需要单独维护静态资源站点或资源服务器。

## 主控资源目录

镜像内默认目录为 `/opt/link42/releases/agent`：

```text
/opt/link42/releases/agent/manifest.json
/opt/link42/releases/agent/<version>/...
```

构建前准备资源：

```bash
scripts/agent/prepare-release-assets.sh
```

`scripts/controller/build-image.sh` 和 `scripts/controller/publish-dockerhub.sh` 会自动执行资源准备。
通常不需要把 `/opt/link42/releases/agent` 映射到宿主机；如果显式设置
`LINK42_AGENT_RELEASE_DIR`，目录必须已经包含 `manifest.json` 和对应资源，不能使用空目录覆盖镜像内置资源。

## 节点安装

```bash
curl -fsSL https://your-link42-controller.example.com/api/agent/install.sh | \
  sudo env LINK42_SERVER_URL=https://your-link42-controller.example.com \
  LINK42_NODE_ID=1 LINK42_AGENT_TOKEN=token sh
```

安装脚本会调用主控的 release manifest，根据系统选择 Linux x64 二进制或 OpenWrt/musl 源码包，并校验 SHA256。

卸载：

```bash
curl -fsSL https://your-link42-controller.example.com/api/agent/install.sh | sudo sh -s -- uninstall
```

## API

- `GET /api/agent/install.sh`
- `GET /api/agent/releases`
- `GET /api/agent/releases/{version}/download?platform=...`
- `GET /api/agent/releases/{version}/sha256?platform=...`

脚本支持 `LINK42_AGENT_VERSION` 固定版本。旧版 `LINK42_RES_BASE_URL` 仅作为显式离线部署覆盖项保留，正常部署不需要设置。
