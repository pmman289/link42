# Link42 全流程构建与 DockerHub 推送

本文面向专门负责构建发布的 Agent。目标是完成：

1. 构建兼容旧系统的 `link42-agent` 二进制。
2. 生成 Agent release manifest 和校验文件。
3. 构建内置 Web、API、udp2raw 资产、Agent release manifest 的主控镜像。
4. 推送到 DockerHub：`pmman/link42:tagname` 和 `pmman/link42:latest`。
5. 必要时导出镜像给其它机器离线运行。

## 前置条件

在仓库根目录执行：

```bash
pwd
git status --short --branch
docker version
docker login
```

要求：

- 当前目录是仓库根目录。
- Docker 可用。
- DockerHub 已登录，可推送 `pmman/link42`。
- 工作区没有不明确的脏改动；如果有，先确认这些改动是否应该进入发布。

## 推荐发布标签

建议使用时间戳 tag：

```bash
export IMAGE_TAG="$(date +%Y%m%d-%H%M%S)"
export IMAGE_REPO="pmman/link42"
```

也可以显式指定：

```bash
export IMAGE_TAG="20260630-041512"
export IMAGE_REPO="pmman/link42"
```

## 1. 运行基础验证

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall apps/api apps/agent packages tests
npm run build --prefix apps/web
git diff --check
```

全部通过后再继续。

## 2. 构建 Agent x64 二进制

默认构建脚本使用 `python:3.11-slim-bullseye` 容器，避免在过新的 glibc 环境构建出无法在旧 Debian 上运行的 PyInstaller 产物。

```bash
scripts/agent/build-x64.sh
```

产物位于：

```text
dist/agent/link42-agent-linux-x64
dist/agent/link42-agent-linux-x64.sha256
dist/agent/link42-agent-linux-x64-<agent_version>
dist/agent/link42-agent-linux-x64-<agent_version>.sha256
dist/agent/link42-agent-linux-x64-glibc2.31-<agent_version>
dist/agent/link42-agent-linux-x64-glibc2.31-<agent_version>.sha256
dist/agent/manifest.json
```

检查版本：

```bash
dist/agent/link42-agent-linux-x64 --version
cat dist/agent/manifest.json
```

如果目标机器曾报过类似错误：

```text
GLIBC_2.38 not found
```

必须使用默认 Docker 构建模式重新打包，不要用本机新系统直接构建。

## 3. 准备主控镜像内置 Agent release 资产

主控镜像构建脚本会自动执行：

```bash
scripts/agent/prepare-release-assets.sh
```

也可以手动检查：

```bash
scripts/agent/prepare-release-assets.sh
find dist/controller-agent-releases -maxdepth 1 -type f -print
cat dist/controller-agent-releases/manifest.json
```

如果第 2 步已经构建 Agent，`dist/controller-agent-releases` 会包含二进制、sha256 和 manifest。

如果没有构建 Agent，该目录只会生成空 release manifest。主控仍可构建和运行，但前端升级计划会回退为手动升级命令，不能一键自升级。

## 4. 构建主控 Docker 镜像

```bash
IMAGE_TAG="$IMAGE_TAG" IMAGE_REPO="$IMAGE_REPO" scripts/controller/build-image.sh
```

等价镜像名：

```text
pmman/link42:<IMAGE_TAG>
```

构建脚本会把以下内容打进镜像：

- FastAPI API。
- React Web 构建产物。
- `wireguard-tools`。
- `udp2raw_sh/udp2raw_bin`，用于 Agent 安装 udp2raw 中间层。
- `dist/controller-agent-releases`，用于 Agent 自升级资产。

镜像内重要目录：

```text
/opt/link42/web
/opt/link42/plugins/udp2raw/assets
/opt/link42/releases/agent
/link42/data
/link42/config
```

运行数据统一挂载母目录 `/link42`：

```text
/link42/data    SQLite 数据库和运行数据
/link42/config  预留配置目录
```

## 5. 推送 DockerHub

```bash
docker push "$IMAGE_REPO:$IMAGE_TAG"
docker tag "$IMAGE_REPO:$IMAGE_TAG" "$IMAGE_REPO:latest"
docker push "$IMAGE_REPO:latest"
```

记录 digest：

```bash
docker image inspect "$IMAGE_REPO:$IMAGE_TAG" --format '{{index .RepoDigests 0}}'
```

## 6. 可选：导出镜像到其它机器

导出：

```bash
scripts/controller/export-image.sh "$IMAGE_TAG"
```

或直接：

```bash
docker save "$IMAGE_REPO:$IMAGE_TAG" | gzip > "dist/link42-controller-$IMAGE_TAG.tar.gz"
```

目标机器导入：

```bash
gunzip -c "link42-controller-$IMAGE_TAG.tar.gz" | docker load
```

目标机器运行示例：

```bash
docker run -d \
  --name link42 \
  --restart unless-stopped \
  -p 8000:8000 \
  -v link42-runtime:/link42 \
  "$IMAGE_REPO:$IMAGE_TAG"
```

或使用 compose：

```bash
docker compose -f deploy/docker-compose.yml up -d
```

## 7. 发布 Agent 安装脚本和外部二进制资源

前端节点安装命令默认使用：

```text
https://get.pmman.tech/sh/link42-agent.sh
https://get.pmman.tech/res/link42
```

详细的静态站点发布、验证、节点安装、卸载和回滚流程见：

```text
docs/agent-public-deployment.md
```

需要同步发布：

```text
deploy/sh/link42-agent.sh
dist/agent/link42-agent-linux-x64
dist/agent/link42-agent-linux-x64.sha256
dist/agent/<agent_version>/link42-agent-linux-x64
dist/agent/<agent_version>/link42-agent-linux-x64.sha256
```

当前安装脚本下载规则：

- `LINK42_AGENT_VERSION=latest`：
  - `$LINK42_RES_BASE_URL/link42-agent-linux-x64`
- `LINK42_AGENT_VERSION=0.2.0`：
  - `$LINK42_RES_BASE_URL/0.2.0/link42-agent-linux-x64`

发布到对象存储或静态站点时，目录结构应保持一致：

```text
res/link42/link42-agent-linux-x64
res/link42/link42-agent-linux-x64.sha256
res/link42/0.2.0/link42-agent-linux-x64
res/link42/0.2.0/link42-agent-linux-x64.sha256
sh/link42-agent.sh
```

## 8. 发布后验证

拉取镜像：

```bash
docker pull "$IMAGE_REPO:$IMAGE_TAG"
docker pull "$IMAGE_REPO:latest"
```

启动主控：

```bash
docker rm -f link42-test >/dev/null 2>&1 || true
docker run -d --name link42-test -p 8000:8000 -v link42-test-runtime:/link42 "$IMAGE_REPO:$IMAGE_TAG"
docker logs link42-test --tail=80
```

检查主控健康：

```bash
curl -fsS http://127.0.0.1:8000/api/auth/me || true
curl -fsS http://127.0.0.1:8000/api/agent/releases
```

`/api/auth/me` 未登录时返回 401 属于正常现象。`/api/agent/releases` 应返回 manifest。

清理测试容器：

```bash
docker rm -f link42-test
docker volume rm link42-test-runtime
```

## 9. Git 提交建议

构建产物默认不提交：

```text
dist/
build/
apps/web/dist/
```

通常只提交源码、脚本、文档改动。提交前检查：

```bash
git status --short
git diff --stat
```

如果本次只是构建和推送镜像，源码无变化，可以不提交。

## 10. 常见问题

### Agent 在旧系统提示 GLIBC_xxx not found

原因通常是用新系统本机 Python/PyInstaller 构建。处理：

```bash
scripts/agent/build-x64.sh
```

不要设置 `LINK42_AGENT_BUILD_MODE=local`。

### 主控镜像里没有 Agent 自升级资产

检查：

```bash
cat dist/controller-agent-releases/manifest.json
```

如果 `releases` 是空对象，说明构建主控前没有先构建 Agent 二进制。重新执行：

```bash
scripts/agent/build-x64.sh
IMAGE_TAG="$IMAGE_TAG" scripts/controller/build-image.sh
```

### DockerHub latest 没更新

确认 tag 和 latest digest 是否一致：

```bash
docker buildx imagetools inspect "$IMAGE_REPO:$IMAGE_TAG"
docker buildx imagetools inspect "$IMAGE_REPO:latest"
```

不一致时重新执行：

```bash
docker tag "$IMAGE_REPO:$IMAGE_TAG" "$IMAGE_REPO:latest"
docker push "$IMAGE_REPO:latest"
```

### npm audit 提示漏洞

构建阶段可能出现 npm audit 提示。只要 `npm run build` 成功，不阻断发布。依赖升级应作为单独任务处理，避免发布流程中临时大版本升级。
