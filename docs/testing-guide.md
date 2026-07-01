# Link42 测试指南

本文给负责测试和 bug 修复的 Agent 使用。目标是说明应该跑哪些测试、如何按问题范围选择测试、哪些实机测试有风险，以及测试失败时如何定位。

## 测试分层

Link42 当前测试分为五层：

```text
Python 后端规则测试
Python Agent 本机执行测试
前端 TypeScript/Vite 构建测试
Docker 镜像构建测试
实机/容器运行验证
```

优先级：

1. 任何代码改动都至少跑相关单测和 `git diff --check`。
2. 后端或 Agent 改动必须跑 Python 测试。
3. 前端改动必须跑 `npm run build --prefix apps/web`。
4. Dockerfile、构建脚本、依赖、静态资源路径改动必须构建镜像。
5. 会写 `/etc/wireguard` 或操作 service 的改动，实机测试必须谨慎。

## 全量本地验证

在仓库根目录执行：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall apps/api apps/agent packages tests
npm run build --prefix apps/web
git diff --check
```

预期：

- `pytest` 全部通过。
- `compileall` 无语法错误。
- `npm run build` 完成 TypeScript 检查和 Vite 构建。
- `git diff --check` 无空白错误。

当前常见 warning：

- FastAPI `on_event` deprecation warning。
- `datetime.utcnow()` deprecation warning。

这些 warning 当前不阻断发布，但不要新增无关 warning。

## 按范围选择测试

### 后端业务规则

涉及这些文件时：

```text
apps/api/link42_api/main.py
apps/api/link42_api/models.py
apps/api/link42_api/schemas.py
apps/api/link42_api/database.py
apps/api/link42_api/wireguard_service.py
packages/link42_wireguard/
```

至少运行：

```bash
.venv/bin/python -m pytest tests/test_point_to_point_rules.py -q
.venv/bin/python -m compileall apps/api packages tests
git diff --check
```

建议补测试的位置：

```text
tests/test_point_to_point_rules.py
```

适合覆盖：

- 节点在线/离线规则。
- 导入扫描和 ImportCandidate 过滤。
- 单 Peer 规则。
- 受管连接双端一致性。
- udp2raw 单向语义。
- AllowedIPs 渲染。
- Agent 版本能力门禁。
- Agent 升级计划和任务创建。

### Agent 本机执行

涉及这些文件时：

```text
apps/agent/link42_agent/main.py
apps/agent/link42_agent/system.py
apps/agent/link42_agent/service_manager.py
apps/agent/link42_agent/middleware.py
apps/agent/link42_agent/upgrade.py
apps/agent/link42_agent/client.py
deploy/sh/link42-agent.sh
```

至少运行：

```bash
.venv/bin/python -m pytest tests/test_agent_system.py -q
.venv/bin/python -m compileall apps/agent packages tests
git diff --check
```

建议补测试的位置：

```text
tests/test_agent_system.py
```

适合覆盖：

- systemd/OpenRC/OpenWrt service manager 分支。
- `wg-quick up/down` 幂等。
- 写入配置前备份。
- Agent 能力上报。
- udp2raw systemd 配置生成。
- Agent 自升级 URL 限制、dry-run、版本校验。

### 前端

涉及这些文件时：

```text
apps/web/src/main.tsx
apps/web/src/styles.css
apps/web/package.json
apps/web/package-lock.json
```

至少运行：

```bash
npm run build --prefix apps/web
git diff --check
```

复杂 UI bug 修复后应做浏览器 E2E 或人工路径验证。仓库提供了一个持久化 Playwright 运行环境，避免每次测试都在 `/tmp` 重新安装 npm 包和下载 Chromium。

首次在本机准备 Playwright：

```bash
scripts/e2e/bootstrap-playwright.sh
```

默认缓存位置：

```text
Playwright npm runtime: ~/.cache/link42/e2e
Chromium browser cache: ~/.cache/ms-playwright
```

之后运行任意 Playwright 脚本：

```bash
scripts/e2e/run-playwright.sh /tmp/link42-e2e/my-ui-test.js
```

脚本里可直接使用：

```js
const { chromium } = require("playwright");
```

建议使用临时 SQLite 和默认前端 API 推断端口，避免污染真实数据：

```bash
LINK42_DATABASE_URL=sqlite:////tmp/link42-e2e-api.db \
  .venv/bin/uvicorn link42_api.main:app --host 127.0.0.1 --port 8000 --no-access-log

npm run dev --prefix apps/web -- --host 127.0.0.1 --port 5173
```

Playwright 脚本建议覆盖：

- 登录过期后是否立刻回登录页。
- 节点设置弹窗是否能查看/轮换 token。
- 导入 wg-quick 后是否不会重复出现可导入项。
- 导入为受管连接时新弹窗是否在最前可操作。
- Endpoint 控件是否支持下拉选择和直接输入。
- udp2raw 开启后是否只要求服务端侧 WireGuard ListenPort。
- udp2raw server 对外地址和监听地址是否拒绝域名，只允许 IP。
- udp2raw 开启后，上方被接管的 Endpoint 参数是否不可编辑。
- 监听端口为空时前端和后端是否都允许。
- 链路监测摘要是否可点击，弹窗是否回显目标 IP，图表是否渲染，窗口切换是否可用。

测试结束后清理临时进程、数据库和脚本输出，不要清理持久 Playwright 缓存：

```bash
rm -rf /tmp/link42-e2e /tmp/link42-e2e-api.db
```

### 跨机器真实 E2E 环境

针对 mimic、udp2raw、Agent 安装/卸载这类必须看真实进程、systemd、`/etc/wireguard` 和数据面的测试，优先使用仓库内沉淀的跨机器脚本：

```bash
scripts/real-e2e/up.sh
scripts/real-e2e/status.sh
scripts/real-e2e/down.sh
```

默认测试拓扑是：

```text
主控：本机
本机 Agent：本机
远端 Agent：ssh remote-test-host
本机入口：192.0.2.10
远端入口：198.51.100.20
```

首次使用先复制配置：

```bash
cp scripts/real-e2e/env.example /tmp/link42-real-e2e.env
```

按实际测试接口补充清理名单，例如：

```bash
LINK42_REAL_LOCAL_WG_IFACES="l42mim0 l42u2r0"
LINK42_REAL_REMOTE_WG_IFACES="l42mim1 l42u2r1"
LINK42_REAL_LOCAL_MIMIC_IFACES="enp3s0"
LINK42_REAL_REMOTE_MIMIC_IFACES="enp1s0"
```

启动：

```bash
npm run build --prefix apps/web
scripts/real-e2e/up.sh
```

脚本会：

- 启动临时 SQLite 主控，数据库和日志位于 `/tmp/link42-real-e2e`。
- 创建本机和远端两个节点。
- 本机直接运行当前源码 Agent。
- 把当前 `apps/agent` 和 `packages` 打包到远端，并用远端 `python3` 启动 Agent。
- 等待两个节点 online。

查看状态：

```bash
scripts/real-e2e/status.sh
```

清理：

```bash
scripts/real-e2e/down.sh
```

如果本轮测试通过主控安装了 mimic 包，并希望恢复到未安装状态：

```bash
LINK42_REAL_PURGE_MIMIC=1 scripts/real-e2e/down.sh
```

注意：

- 清理脚本只删除配置里列出的 WireGuard 测试接口和 mimic bind interface 配置，避免误删现场。
- Link42 udp2raw 测试资产和服务模板会按 Link42 路径清理。
- 不要把生产接口名写进 `LINK42_REAL_*_WG_IFACES`。

### Docker 和发布

涉及这些文件时：

```text
Dockerfile.controller
.dockerignore
scripts/controller/
scripts/agent/
deploy/docker-compose.yml
```

至少运行：

```bash
scripts/agent/prepare-release-assets.sh
IMAGE_TAG=test-local scripts/controller/build-image.sh
docker run --rm -p 8000:8000 pmman/link42:test-local sh -c 'ls -la /opt/link42 && ls -la /opt/link42/releases/agent'
```

若要推送 DockerHub，按：

```text
docs/release-build-and-push.md
```

执行完整流程。

## 实机测试注意事项

用户已授权测试/修复 Agent 在本机搭建真实开发测试环境。测试目标不是只跑 dry-run，而是用最新开发环境启动主控、真实本机 Agent、真实 `/etc/wireguard` 和 `wg-quick` 做冒烟验证；开发主控数据库可以随测随删，但测试脚本必须清理自己制造的脏数据。

### 持久 Docker 双节点环境

为了验证 udp2raw 这类跨节点链路，已创建两个持久化 Docker 节点容器，模拟两台独立机器：

```text
Docker image: link42-node-smoke:latest
Docker network: link42-smoke-net
Subnet: 172.31.42.0/24
Node A container: link42-node-a
Node A IP: 172.31.42.11
Node B container: link42-node-b
Node B IP: 172.31.42.12
Workspace mount in containers: /workspace/link42
```

容器以 `--privileged --cgroupns=host` 运行，内部有 systemd、wireguard-tools、iproute2、tcpdump、curl、Python 依赖，可以真实执行：

```text
wg-quick up/down
systemctl start/stop link42-udp2raw-*.service
tcpdump 抓容器间 udp2raw 流量
python -m link42_agent.main
```

建议主控仍跑宿主机最新开发代码，监听 `0.0.0.0:18046`。容器通过 Docker bridge 网关访问主控：

```text
Controller from host: http://127.0.0.1:18046
Controller from containers: http://172.31.42.1:18046
```

容器管理命令：

```bash
docker ps --filter name=link42-node
docker exec -it link42-node-a bash
docker exec -it link42-node-b bash
docker restart link42-node-a link42-node-b
```

重建环境：

```bash
docker network create --subnet 172.31.42.0/24 link42-smoke-net
docker run -d --name link42-node-a --hostname link42-node-a --privileged --cgroupns=host \
  --network link42-smoke-net --ip 172.31.42.11 \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /root/repo/link42:/workspace/link42 \
  link42-node-smoke:latest
docker run -d --name link42-node-b --hostname link42-node-b --privileged --cgroupns=host \
  --network link42-smoke-net --ip 172.31.42.12 \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /root/repo/link42:/workspace/link42 \
  link42-node-smoke:latest
```

注意：这两个容器是测试资产，默认保留；测试脚本只清理容器内部的测试接口、Agent 进程、udp2raw 服务和临时配置，不要随手 `docker rm`。

约束：

- 可以使用开发环境主控和临时 SQLite 数据库，测试前后清理测试数据。
- 可以直接使用本机 `/etc/wireguard`，但只允许操作测试专用接口名前缀，例如 `l42smoke*`。
- 可以用 `127.0.10.1`、`127.0.10.2` 作为两个本机节点 Agent 的入口地址，避免连接外部节点。
- 不要修改或删除非测试接口和配置；当前机器可能已有真实接口，例如 `wg46747`。
- Agent 长跑必须后台启动并记录 PID/日志，测试结束后清理进程、接口、配置文件和临时数据库。
- 可以把测试得到的新要点写回 `docs/`，方便后续上下文恢复。

固定真实冒烟工作流：

```bash
scripts/smoke-real-local.sh
```

该脚本会启动开发主控到 `127.0.0.1:18042`，创建两个节点和两个本机 Agent，生成两条 `l42smoke*` WireGuard 配置，走真实 apply/start/status/stop/delete 链路，并在退出时清理测试接口和配置。

Agent 真实模式会写系统配置并操作网络：

```text
/etc/wireguard
wg
wg-quick
systemctl
rc-service
uci
ifup / ifdown
iptables
```

不要在用户真实机器上随意执行破坏性测试。

风险较低的实机检查：

```bash
link42-agent --version
systemctl status link42-agent
journalctl -u link42-agent --no-pager -n 80
wg --version
wg-quick --version
ls -la /etc/wireguard
```

风险较高，需要用户明确同意：

```bash
wg-quick up <iface>
wg-quick down <iface>
systemctl restart link42-agent
systemctl restart wg-quick@<iface>
rm /etc/wireguard/<iface>.conf
uci commit network
ifdown <iface>
ifup <iface>
```

OpenWrt/家庭路由器测试尤其谨慎，不要破坏用户现有网络。

OpenWrt udp2raw/faketcp 检查重点：

- Link42 不应插入 `iptables -I INPUT -p tcp --dport <server_listen_port> -j DROP` 这类 direct DROP 规则；这会吞掉 faketcp SYN。
- OpenWrt/procd 后端只应启动 udp2raw，并由 udp2raw 自身 `-a` 处理必要规则。
- OpenWrt 作为 udp2raw server 时，测试前确认用户已在实际入口 zone 手动放行 `server_listen_port` 对应 TCP 端口。
- 若 client 日志持续 `rst==1`，检查是否存在错误的 direct DROP/ACCEPT 顺序、udp2raw 自身自动规则、上游 NAT/端口转发和入口 zone。
- 若 client 无 RST 但无握手，检查 zone 放行、上游 NAT/端口转发、server 监听地址和抓包入站情况。

Linux mimic 检查重点：

- Agent 版本应为 `0.5.2` 或更高；`0.5.0` 生成过错误 mimic 配置，`0.5.1` 安装依赖和配置文件权限处理不完整，均不应用于运行 mimic。
- 未安装 mimic 时只应上报 `middleware.install.mimic`，不应上报 `middleware.mimic`。
- mimic 半安装状态，例如 `dpkg-query` 显示 `iU`、`iF`，或缺少 `mimic` 用户、`mimic@.service`、`modinfo mimic` 失败时，不应上报 `middleware.mimic`。
- 安装任务应使用 GitHub latest release，并能通过节点配置的 GitHub 代理下载。
- 安装任务应预装 `dkms`、`dwarves`、`bubblewrap`，并按顺序尝试 `linux-headers-$(uname -r)`、cloud kernel 对应 headers、发行版通用 headers；精确 headers 不存在时不应提前中断，最终以 mimic runtime health 判断 DKMS/module 是否可用。
- 安装失败后 `agent_platform.has_mimic` 应为 false；如仅有二进制但健康检查不通过，只能看到 `mimic_binary_present=true`。
- `/etc/mimic/<iface>.conf` 不应包含 `ingress_ifname`、`egress_ifname`、`handshake_interval`、`keepalive_interval`。
- mimic filter 应为官方格式，例如 `filter = remote=203.0.113.20:51821`；IPv6 应为 `filter = remote=[2001:db8::20]:51821`。
- 启用 mimic 的受管连接 Endpoint 必须是 IP 字面量；域名应在主控侧 400 拒绝。
- mimic 不应把 WireGuard Endpoint 改成 `127.0.0.1`，应保持真实端点。

## Dry Run

Agent 支持：

```bash
LINK42_AGENT_DRY_RUN=1
```

dry-run 适合验证任务 payload 和控制流，但不能完全代表真实 service manager 行为。

本地运行示例：

```bash
LINK42_SERVER_URL=http://127.0.0.1:8000 \
LINK42_NODE_ID=1 \
LINK42_AGENT_TOKEN=l42agent_xxx \
LINK42_WIREGUARD_DIR=/tmp/link42-wireguard \
LINK42_AGENT_DRY_RUN=1 \
.venv/bin/python -m link42_agent.main
```

不要把 Agent 前台跑在会话里长时间阻塞。需要后台运行时使用 `setsid` 或 systemd。

## 手工 API 验证

未登录状态：

```bash
curl -i http://127.0.0.1:8000/api/auth/me
```

返回 401 是正常的。

Agent release manifest：

```bash
curl -fsS http://127.0.0.1:8000/api/agent/releases
```

健康检查：

```bash
curl -fsS http://127.0.0.1:8000/api/health
```

Web 登录 API 需要真实密码。初次启动密码会输出在 Docker 日志：

```bash
docker logs link42 --tail=120
```

## 测试数据库

默认 SQLite：

```text
link42.db
```

Docker 内默认：

```text
/link42/data/link42.db
```

不要主动删除用户数据库，除非用户明确要求清空重测。

如果需要隔离测试数据库，使用环境变量：

```bash
LINK42_DATABASE_URL=sqlite:////tmp/link42-test.db \
.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000
```

测试完成后再删除 `/tmp/link42-test.db`。

## 前后端本地联调

启动 API：

```bash
.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000 --no-access-log
```

隔离 API smoke test 推荐用随机端口和临时库：

```bash
LINK42_DATABASE_URL=sqlite:////tmp/link42-smoke.db \
.venv/bin/uvicorn link42_api.main:app --host 127.0.0.1 --port 18000 --no-access-log
```

启动前端：

```bash
npm run dev --prefix apps/web -- --host 0.0.0.0 --port 5173
```

或构建后预览：

```bash
npm run build --prefix apps/web
npm run preview --prefix apps/web -- --host 0.0.0.0 --port 5173
```

## 失败定位

### pytest 失败

先看失败测试名和断言。常见定位：

```bash
.venv/bin/python -m pytest tests/test_point_to_point_rules.py::test_name -q -vv
.venv/bin/python -m pytest tests/test_agent_system.py::test_name -q -vv
```

不要为了让测试过而删除关键断言。先判断断言是不是表达了真实业务约束。

### TypeScript/Vite 构建失败

常见原因：

- 新增 type 未定义。
- nullable 字段未处理。
- React state 类型不匹配。
- 表单字段读出来是 `FormDataEntryValue | null`，需要显式转换。

命令：

```bash
npm run build --prefix apps/web
```

### Docker 构建失败

常见原因：

- `.dockerignore` 把需要的目录排除了。
- `dist/controller-agent-releases` 未准备。
- npm/pip 下载失败。
- Dockerfile COPY 路径不存在。

先执行：

```bash
scripts/agent/prepare-release-assets.sh
ls -la dist/controller-agent-releases
IMAGE_TAG=test-local scripts/controller/build-image.sh
```

## 回归测试清单

修复 bug 后，根据影响范围至少勾选相关项：

- 登录、登出、token 过期回登录页。
- 节点创建、编辑、删除、轮换 token。
- Agent 注册、心跳、离线判断。
- 手动 WireGuard 配置创建、保存 Peer、生成部署计划。
- AllowedIPs 渲染存在且正确。
- `Table = off` 默认行为。
- `ListenPort` 空值允许。
- 导入扫描不会重复显示已导入接口。
- 非管理导入配置删除只删观察记录。
- 导入为受管连接时必须选择对端覆盖项。
- 受管连接创建、编辑、启动、停止、删除双端一致。
- udp2raw 只要求 server 侧 WireGuard ListenPort。
- udp2raw client 本地监听 UDP，连接 server IP:port；server 再转回本机 WireGuard UDP。
- udp2raw IP 参数不能填域名。
- Agent 升级计划：旧 Agent 显示手动命令，新 Agent 可创建 self-upgrade 任务。
- Docker 主控启动后 `/api/agent/releases` 可访问。

## 提交前检查

```bash
git status --short
git diff --stat
git diff --check
```

不应提交：

```text
dist/
build/
apps/web/dist/
.pytest_cache/
__pycache__/
link42.db
```

如果只负责测试，不改代码，可以只提交测试文档或测试补充；如果没有文件变化，不需要提交。
