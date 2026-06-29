# 项目结构

本文记录 Link42 仓库的目录约定，避免脚本和部署文件后续散落。

## 应用代码

- `apps/api/`：中心 FastAPI 主控后端。
- `apps/web/`：React/Vite Web 面板。
- `apps/agent/`：节点 Agent 入口和轮询执行逻辑。
- `packages/link42_common/`：API 与 Agent 共享的通用工具。
- `packages/link42_wireguard/`：WireGuard 配置解析和渲染。
- `tests/`：后端、Agent 和 WireGuard 规则测试。

## 脚本

- `scripts/agent/`：Agent 构建脚本。
  - `build-x64.sh`：构建 Linux x64 单文件 Agent 二进制。
- `scripts/controller/`：主控镜像脚本。
  - `build-image.sh`：构建 `pmman/link42:<tag>` 主控镜像。
  - `push-image.sh`：构建并推送主控镜像到 DockerHub。
  - `export-image.sh`：将主控镜像导出为 tar，供离线机器 `docker load`。

## 部署文件

- `Dockerfile.controller`：主控镜像 Dockerfile，包含 API 和已构建 Web 面板。
- `deploy/docker-compose.yml`：主控容器运行示例。
- `deploy/sh/`：一键安装脚本，目前包含 Agent 安装/卸载脚本。
- `deploy/systemd/`：systemd service 示例。

## 文档和示例

- `docs/`：架构、运维、构建和决策记录。
- `local-demo/`：本地演示配置样例。

## 构建产物

以下目录只作为本机构建输出，不应提交：

- `build/`
- `dist/`
- `.venv/`
- `apps/web/dist/`
- `apps/web/node_modules/`
- `*.db`
- `*.egg-info/`
