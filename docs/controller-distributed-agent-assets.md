# 主控分发 Agent 与中间层资源

Link42 的安装脚本、Agent release 和 udp2raw/UDPspeeder 资源统一由主控提供，节点不再依赖独立的 `get.pmman.tech` 站点。

## 迁移点

- Agent 安装脚本：`GET /api/agent/install.sh`
- Agent release 清单：`GET /api/agent/releases`
- Agent 二进制/源码：`GET /api/agent/releases/{version}/download?platform=...`
- Agent 校验值：`GET /api/agent/releases/{version}/sha256?platform=...`
- udp2raw 资产：`GET /api/agent/plugins/udp2raw/assets/{asset_name}`
- UDPspeeder 资产：`GET /api/agent/plugins/udpspeeder/assets/{asset_name}`

以上 Agent 资源接口和中间层资产接口属于节点引导链路，按固定白名单免 Web 登录，资产名称由主控白名单限制。

## 部署

构建主控镜像前准备资源：

```bash
scripts/agent/prepare-release-assets.sh
```

`scripts/controller/build-image.sh` 和 `scripts/controller/publish-dockerhub.sh` 会自动执行这一步。
资源随后被复制到主控镜像的 `/opt/link42/releases/agent`，不需要再通过 SSH/SCP 上传到独立资源服务器。

如果要使用单独准备好的本地资源目录，可以在启动主控时显式设置：

```bash
LINK42_AGENT_RELEASE_DIR=/path/to/controller-agent-releases
```

该目录必须已经包含 `manifest.json` 和对应资源；不要用空目录覆盖镜像内置目录。

新节点安装命令应显式设置 `LINK42_SERVER_URL`。安装脚本根据主控 manifest 选择平台资源，完成下载和 SHA256 校验；`LINK42_AGENT_VERSION` 可指定固定版本。

## 兼容覆盖

`LINK42_RES_BASE_URL` 和 `UDP2RAW_BIN_DIR_URL` 仅作为已有离线部署的显式覆盖项保留。未设置时，默认全部走当前主控；新部署不应依赖这些变量。
