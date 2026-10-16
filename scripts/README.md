# Link42 构建发布脚本

主控镜像包含 Web、API、安装脚本以及 Agent/UDP2RAW 资源，所有节点下载均使用自己的主控地址。无需独立静态资源服务器、SSH 上传或额外域名。

## 发布配置

```bash
cp scripts/release.env.example scripts/release.env
```

设置 `IMAGE_REPO`，命令行环境变量优先于配置文件。

## 构建与发布

仅构建本地镜像（不推送）：

```bash
IMAGE_NAME=link42:local scripts/controller/build-image.sh
```

构建、验证并推送：

```bash
IMAGE_REPO=your-dockerhub-user/link42 IMAGE_TAG=your-tag scripts/release-all.sh
# 等价的主控发布入口：
scripts/controller/publish-dockerhub.sh
```

构建入口会自动准备 Agent 产物并校验脚本、二进制、源码包、manifest 和摘要。即使设置 `SKIP_PREPARE_AGENT_RELEASES=1`，仍执行完整性校验。发布前的临时空卷容器会验证页面、健康检查和匿名资源下载，随后才推送镜像。

旧的独立静态资源发布入口及 `LINK42_PUBLIC_*`、`SKIP_AGENT_PUBLIC` 配置已移除。

安装和迁移方法见 [主控资源部署](../docs/agent-public-deployment.md)。
