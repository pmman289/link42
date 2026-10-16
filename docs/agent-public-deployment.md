# 主控托管安装脚本与资源

Link42 主控从 `0.6.27` 起直接提供 Agent 和 UDP2RAW 的安装脚本与资源，节点不需要访问额外的项目资源站点。系统软件源和 mimic 官方 GitHub 下载仍保留。

## 主控部署

标准 Docker 镜像内置安装脚本、Agent x64 二进制、musl/OpenWrt 源码包及 UDP2RAW 白名单二进制。升级主控镜像即可更新这些资源。

在系统设置中填写**节点能够访问的完整主控地址**，例如 `https://panel.example.com:8443`。仅支持 HTTP/HTTPS，不支持凭据、路径前缀、查询参数或片段。新建节点时可以填写该节点实际使用的主控地址。

Nginx、Caddy 或 CDN 应将 `/sh/`、`/res/`、`/api/` 一并转发到主控；这些资源不可返回前端页面兜底，安装资源应遵循主控的缓存响应头，避免缓存旧版本与摘要。

源码部署时，保留仓库中的 `deploy/sh/link42-agent.sh`、`udp2raw_sh/udp2raw.sh` 和 `udp2raw_sh/udp2raw_bin/`。准备并指定 Agent 发布目录：

```bash
scripts/agent/prepare-release-assets.sh
export LINK42_AGENT_RELEASE_DIR="$PWD/dist/controller-agent-releases"
# 使用仓库源码启动主控，例如激活开发环境后执行：
uvicorn link42_api.main:app --host 0.0.0.0 --port 8000
```

## 下载接口

以下路径均以自己的主控地址为前缀，无需 Web 登录：

| 路径 | 内容 |
| --- | --- |
| `/sh/link42-agent.sh` | Agent 安装、覆盖升级和卸载脚本 |
| `/sh/udp2raw.sh` | UDP2RAW 独立安装与菜单脚本 |
| `/res/link42/link42-agent-linux-x64` | manifest latest 对应的 x64 二进制 |
| `/res/link42/link42-agent-source.tar.gz` | manifest latest 对应的源码包 |
| `/res/link42/<version>/<filename>` | manifest 中指定版本的资源 |
| `/res/link42/<filename>.sha256` | 对应资源的 SHA256；固定版本路径同样支持 |
| `/sh/udp2raw_bin/<filename>` | 固定白名单中的 UDP2RAW 二进制 |

下载仅解析已知文件名与 manifest 资产，目录不会直接公开。不存在的版本、文件以及越界或符号链接路径会报错，不会转向其它站点。`/api/agent/releases` 的 manifest 管理接口仍需登录，原 Agent 自升级下载接口保持兼容；UDP2RAW Agent API 仍需节点凭据。

## 安装、升级与卸载

将以下示例中的 `http://controller:8000` 替换为自己的主控地址，节点 ID 和令牌从面板获取：

```bash
curl -fsSL http://controller:8000/sh/link42-agent.sh | sudo env \
  LINK42_SERVER_URL=http://controller:8000 \
  LINK42_NODE_ID=1 LINK42_AGENT_TOKEN=token sh
```

OpenWrt 以 root 执行，将 `sudo env` 改为 `env`。主控地址同时用于连接 API 和下载资源。

旧节点覆盖安装会从已有 `agent.env` 恢复主控地址和凭据，命令行显式提供的值优先。指定版本示例：

```bash
curl -fsSL http://controller:8000/sh/link42-agent.sh | sudo env \
  LINK42_SERVER_URL=http://controller:8000 LINK42_AGENT_VERSION=0.6.23 sh
```

该版本必须存在于主控 manifest。摘要校验失败会终止安装；资源不存在时应检查主控镜像或挂载的发布目录。

卸载无需给脚本传入主控地址或节点凭据：

```bash
curl -fsSL http://controller:8000/sh/link42-agent.sh | sudo sh -s -- uninstall
```

卸载默认清理 Link42 管理的中间层；需保留时传入 `LINK42_KEEP_MIDDLEWARE=1`。也可执行已保存的本地脚本卸载，无需下载资源。

UDP2RAW 独立安装：

```bash
curl -fsSL http://controller:8000/sh/udp2raw.sh | sudo env \
  LINK42_SERVER_URL=http://controller:8000 sh -s -- install
```

生成的 `udp2raw-menu` 保存安装时的主控地址，后续进入菜单或更新均使用该地址。更换主控后，重新执行安装命令更新菜单入口。

## 从旧配置迁移

- 旧主控配置 `LINK42_AGENT_INSTALL_SCRIPT_URL`、`LINK42_AGENT_RES_BASE_URL` 仍可被读取，但不再用于生成下载地址，可删除。
- 安装脚本不再使用 `LINK42_RES_BASE_URL`；UDP2RAW 不再使用 `UDP2RAW_BASE_URL`、`UDP2RAW_BIN_DIR_URL` 或 `UDP2RAW_SCRIPT_URL`。
- 重新从面板复制命令，或从自己的主控重新下载脚本；之前保存的旧脚本和旧菜单无法被主控远程替换。
- 不需要数据库迁移或轮换现有节点凭据。已运行的 Agent 无需仅为本次 URL 迁移重新安装。

## 验证

```bash
python3 scripts/controller/verify-downloads.py http://controller:8000 0.6.23
```

第二个参数替换为镜像中实际的 Agent latest 版本。检查会下载脚本、latest/固定版本资源和摘要，以及 UDP2RAW 二进制，不会在本机安装服务。
