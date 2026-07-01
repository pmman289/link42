# Agent 构建发布

## 构建产物

构建 Linux x64 单文件二进制：

```bash
scripts/agent/build-x64.sh
```

构建 OpenWrt 源码包：

```bash
scripts/agent/build-source.sh
```

主要产物：

```text
dist/agent/link42-agent-linux-x64
dist/agent/link42-agent-linux-x64.sha256
dist/agent/link42-agent-linux-x64-<version>
dist/agent/link42-agent-linux-x64-<version>.sha256
dist/agent/link42-agent-linux-x64-glibc2.31-<version>
dist/agent/link42-agent-linux-x64-glibc2.31-<version>.sha256
dist/agent/link42-agent-source.tar.gz
dist/agent/link42-agent-source.tar.gz.sha256
dist/agent/manifest.json
```

## 发布到 get.pmman.tech

完整构建、上传、修权限、公网校验：

```bash
scripts/agent/publish-public-assets.sh
```

如果已经构建好，只上传和验证：

```bash
SKIP_BUILD=1 scripts/agent/publish-public-assets.sh
```

可配置项：

```bash
LINK42_PUBLIC_HOST=aligz
LINK42_PUBLIC_ROOT=/opt/1panel/www/sites/get.pmman.tech/index
LINK42_PUBLIC_BASE_URL=https://get.pmman.tech
```

推荐写入统一配置文件：

```bash
cp scripts/release.env.example scripts/release.env
```

脚本会自动读取 `scripts/release.env`，命令行环境变量仍可临时覆盖。

发布后应能访问：

```text
https://get.pmman.tech/sh/link42-agent.sh
https://get.pmman.tech/res/link42/link42-agent-linux-x64
https://get.pmman.tech/res/link42/link42-agent-source.tar.gz
https://get.pmman.tech/res/link42/<version>/link42-agent-linux-x64
https://get.pmman.tech/res/link42/<version>/link42-agent-source.tar.gz
```

## 主控内置 release

主控镜像构建前会自动准备内置 Agent release，也可以手动执行：

```bash
scripts/agent/prepare-release-assets.sh
```

输出目录：

```text
dist/controller-agent-releases
```
