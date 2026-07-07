# 主控 Docker 构建发布

## 构建镜像

只构建本地镜像：

```bash
IMAGE_TAG=20260630-120000 scripts/controller/build-image.sh
```

默认镜像仓库：

```text
pmman/link42
```

## 构建并推送 DockerHub

推荐使用完整发布脚本：

```bash
scripts/controller/publish-dockerhub.sh
```

它会执行：

```text
pytest
compileall
npm run build
git diff --check
prepare-release-assets
docker build
本地容器验证
docker push <tag>
docker tag/push latest
远端 digest 校验
```

常用参数：

```bash
IMAGE_TAG=20260630-120000 scripts/controller/publish-dockerhub.sh
IMAGE_REPO=pmman/link42 scripts/controller/publish-dockerhub.sh
SKIP_VERIFY=1 scripts/controller/publish-dockerhub.sh
LOCAL_VERIFY=0 scripts/controller/publish-dockerhub.sh
PUSH_LATEST=0 scripts/controller/publish-dockerhub.sh
REBUILD_AGENT_RELEASES=1 scripts/controller/publish-dockerhub.sh
```

`IMAGE_REPO` 也可以写入统一配置：

```bash
cp scripts/release.env.example scripts/release.env
```

也可以传入 tag：

```bash
scripts/controller/publish-dockerhub.sh 20260630-120000
```

本地容器验证会按当前认证流程登录后检查 `/api/agent/releases`，并确认镜像内置的 Agent latest 可读取。日志里的密码、token 和 secret 会自动打码。

`build-image.sh`、`push-image.sh` 和 `export-image.sh` 也会读取 `scripts/release.env`，并从仓库根目录执行；命令行环境变量优先级高于配置文件。

## 导出镜像

```bash
scripts/controller/export-image.sh 20260630-120000
```

默认输出：

```text
dist/controller/link42-controller-<tag>.tar
```
