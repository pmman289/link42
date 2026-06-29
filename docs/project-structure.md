# 项目结构

Link42 以“应用代码 / 部署脚本 / 文档 / 构建产物”四层来组织。

## 源码

- `apps/api/`：主控 FastAPI 后端。
- `apps/web/`：React + Vite 前端。
- `apps/agent/`：节点 Agent 入口和任务执行逻辑。
- `packages/link42_common/`：后端和 Agent 共享工具。
- `packages/link42_wireguard/`：WireGuard 配置解析和渲染。
- `tests/`：单元测试和规则测试。

## 部署与脚本

- `Dockerfile.controller`：主控镜像 Dockerfile。
- `scripts/controller/`：主控镜像构建、导出、推送脚本。
- `scripts/agent/`：Agent 构建脚本。
- `deploy/docker-compose.yml`：主控容器运行示例。
- `deploy/sh/`：Agent 安装和卸载脚本。
- `deploy/systemd/`：systemd service 示例。

## 文档

- `docs/architecture.md`：设计和架构说明。
- `docs/project-decisions.md`：产品和技术决策。
- `docs/operations-notes.md`：运维、部署和踩坑记录。
- `docs/agent-binary-build.md`：Agent 二进制构建说明。
- `docs/handoff-memory.md`：上下文恢复说明。

## 示例与产物

- `local-demo/`：本地演示配置样例。
- `build/`：PyInstaller 中间产物。
- `dist/`：Agent 二进制和导出镜像等发布物。
- `apps/web/dist/`：前端构建产物。
- `.venv/`：本地 Python 虚拟环境。

## 运行目录

容器内部统一挂载到 `/link42`：

- `/link42/data`：数据库和运行数据。
- `/link42/config`：预留配置目录。
