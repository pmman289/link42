# Link42 构建发布脚本

本目录放构建发布入口。发布人员优先使用下面三个脚本：

```bash
scripts/agent/publish-public-assets.sh
scripts/controller/publish-dockerhub.sh
scripts/release-all.sh
```

## 发布环境配置

复制示例配置后按环境修改：

```bash
cp scripts/release.env.example scripts/release.env
```

可配置资源服务器和镜像仓库：

```bash
LINK42_PUBLIC_HOST=aligz
LINK42_PUBLIC_ROOT=/opt/1panel/www/sites/get.pmman.tech/index
LINK42_PUBLIC_BASE_URL=https://get.pmman.tech
IMAGE_REPO=pmman/link42
```

脚本会自动读取 `scripts/release.env`。命令行环境变量优先级更高：

```bash
LINK42_PUBLIC_HOST=other-host scripts/agent/publish-public-assets.sh
```

所有脚本都会自动切换到仓库根目录执行，因此可以从任意当前目录调用。

## 一键全量发布

构建并发布 Agent 静态资源，然后构建并推送主控 Docker 镜像：

```bash
scripts/release-all.sh
```

常用参数：

```bash
IMAGE_TAG=20260630-120000 scripts/release-all.sh
IMAGE_REPO=pmman/link42 scripts/release-all.sh
SKIP_AGENT_PUBLIC=1 scripts/release-all.sh
SKIP_CONTROLLER=1 scripts/release-all.sh
```

一键发布会先发布资源服务器上的 Agent 产物，再构建主控镜像。主控镜像内置的 Agent release 会复用刚生成的 `dist/agent` 产物。

## 分步发布

只发布 Agent 安装脚本、x64 二进制和 OpenWrt source 包：

```bash
scripts/agent/publish-public-assets.sh
```

只构建并推送主控 Docker 镜像：

```bash
scripts/controller/publish-dockerhub.sh
```

服务器限速时，脚本会在上传步骤停留较久，等待即可。

主控发布脚本会检查 `dist/agent` 是否落后于当前 Agent 源码；如果落后，会自动重建内置 Agent release，避免镜像里嵌入旧二进制或旧 OpenWrt 源码包。
