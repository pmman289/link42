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

## 随主控提供下载

安装脚本、二进制和源码包随主控镜像一起发布，无需单独上传资源服务器。节点使用设置中的主控地址：

```text
http://controller:8000/sh/link42-agent.sh
http://controller:8000/res/link42/link42-agent-linux-x64
http://controller:8000/res/link42/link42-agent-source.tar.gz
http://controller:8000/res/link42/<version>/link42-agent-linux-x64
http://controller:8000/res/link42/<version>/link42-agent-source.tar.gz
```

资源的 `.sha256` 由主控 manifest 提供；缺失或不安全的文件不会返回摘要。旧版本下载只支持当前镜像 manifest 中实际包含的版本。

## 主控内置 release

主控镜像构建前会自动准备内置 Agent release，也可以手动执行：

```bash
scripts/agent/prepare-release-assets.sh
```

输出目录：

```text
dist/controller-agent-releases
```

`prepare-release-assets.sh` 会根据当前源码、`dist/agent/manifest.json` 和产物时间自动判断是否需要重建：

```bash
scripts/agent/prepare-release-assets.sh
REBUILD_AGENT_RELEASES=1 scripts/agent/prepare-release-assets.sh
```

当只发布主控镜像时，这个检查可以避免镜像内置旧 Agent。

准备流程和镜像构建均会校验完整性，也可以单独执行：

```bash
python3 scripts/agent/verify-release-assets.py dist/controller-agent-releases
```
