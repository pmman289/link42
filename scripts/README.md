# Link42 构建发布脚本

本目录放构建发布入口。发布人员优先使用下面三个脚本：

```bash
scripts/controller/publish-dockerhub.sh
scripts/release-all.sh
scripts/controller/export-image.sh
```

## 发布环境配置

复制示例配置后按环境修改：

```bash
cp scripts/release.env.example scripts/release.env
```

可配置镜像仓库：

```bash
IMAGE_REPO=pmman/link42
```

脚本会自动读取 `scripts/release.env`。命令行环境变量优先级更高：

```bash
IMAGE_REPO=pmman/link42 scripts/controller/publish-dockerhub.sh
```

所有脚本都会自动切换到仓库根目录执行，因此可以从任意当前目录调用。

## 一键全量发布

生成内置 Agent 资源，然后构建并推送主控 Docker 镜像：

```bash
scripts/release-all.sh
```

常用参数：

```bash
IMAGE_TAG=20260630-120000 scripts/release-all.sh
IMAGE_REPO=pmman/link42 scripts/release-all.sh
```

一键发布会先生成主控镜像需要的 Agent release 资产，再构建并推送主控镜像。Agent 安装脚本、二进制、OpenWrt 源码包、udp2raw 和 UDPspeeder 都由主控 API 提供。

## 分步发布

构建并推送主控 Docker 镜像：

```bash
scripts/controller/publish-dockerhub.sh
```

主控发布脚本会检查 `dist/agent` 是否落后于当前 Agent 源码；如果落后，会自动重建内置 Agent release，避免镜像里嵌入旧二进制或旧 OpenWrt 源码包。
