# Link42

Link42 是一个轻量的内网 WireGuard 节点和链路管理面板。

## 功能

- 管理受管节点。
- 管理点对点 WireGuard 配置。
- 导入现有 `wg-quick` 配置。
- 在确认前预览并下发变更。
- 构建并发布主控 Docker 镜像。

## 项目结构

目录说明见 [docs/project-structure.md](docs/project-structure.md)。

## 开发

安装依赖：

```bash
python3 -m pip install -e ".[dev]"
```

启动 API：

```bash
uvicorn link42_api.main:app --app-dir apps/api --reload
```

启动前端：

```bash
cd apps/web
npm install
npm run dev
```

运行测试：

```bash
pytest
```

## 主控 Docker 镜像

构建镜像：

```bash
scripts/controller/build-image.sh
```

构建并推送到 DockerHub：

```bash
scripts/controller/push-image.sh tagname
```

导出镜像：

```bash
scripts/controller/export-image.sh
```

运行镜像：

```bash
docker run -d --name link42-controller -p 8000:8000 -v /opt/link42:/link42 pmman/link42:tagname
```

也可以通过 Docker Compose 启动：

```bash
docker compose -f deploy/docker-compose.yml up -d
```

## 运行目录

容器内统一使用一个母目录 `/link42`：

- `/link42/data`：SQLite 数据库和运行数据。
- `/link42/config`：预留配置目录，方便宿主机映射。

## 说明

- 主控默认同时托管 API 和 Web 面板。
- 设置页可修改主控访问地址、账号和密码。
- 首次启动时会在容器日志里输出默认登录密码。
