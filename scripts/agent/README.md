# Agent 构建与发布

Agent 资源由 Link42 主控统一分发，不再依赖独立的静态资源站点。

## 构建

```bash
scripts/agent/build-x64.sh
scripts/agent/build-source.sh
scripts/agent/prepare-release-assets.sh
```

主控镜像默认将 `manifest.json` 和各版本资源放在
`/opt/link42/releases/agent`。构建主控镜像时会自动生成这些资源，不需要上传到独立资源服务器。
只有在需要使用外部构建产物时，才通过 `LINK42_AGENT_RELEASE_DIR` 指向一个已准备好的本地目录；不要把空目录挂载到默认路径，否则会覆盖镜像内置资源。

## 新节点安装

在主控节点管理页面复制安装命令，或使用下面的形式：

```bash
curl -fsSL https://your-link42-controller.example.com/api/agent/install.sh | \
  sudo env LINK42_SERVER_URL=https://your-link42-controller.example.com \
  LINK42_NODE_ID=1 LINK42_AGENT_TOKEN=token sh
```

安装脚本从主控的 `/api/agent/releases` 接口选择平台资源，并通过版本化下载和
SHA256 接口校验文件。OpenWrt 和 musl 系统会选择 `openwrt-source` 源码包。

## 准备主控镜像资源

```bash
scripts/agent/prepare-release-assets.sh
```

主控镜像构建和发布脚本会自动执行该步骤。准备完成后，使用
`scripts/controller/publish-dockerhub.sh` 构建并推送包含这些资源的主控镜像。
