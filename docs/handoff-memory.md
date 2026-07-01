# Link42 当前交接记忆

本文用于在长对话、上下文压缩、或切换协作者后快速恢复现场。

## 当前产品状态

- Link42 是 WireGuard 点对点链路管理面板，当前偏向 DN42、家庭网络和小型内网场景。
- 当前架构为中心 FastAPI + SQLite、React/Vite 前端、Python 节点 Agent。
- 产品核心规则：一个 WireGuard 配置等同一根点对点虚拟网线；每个受管配置在部署前必须只有一个对端。
- 前端主流程已经调整为层级结构：先看节点列表，点击在线节点后展开该节点的 WireGuard 配置列表，点击具体配置后打开配置和 peer 操作窗口。
- 手动连接和受管节点间连接已经拆成两个按钮入口：
  - 手动连接用于连接非 Link42 管理的远端，仍走部署计划和 diff 确认。
  - 受管节点间连接用于两个 Link42 节点之间直接建链，系统自动生成双方密钥并直接下发、启动、enable 双方连接。
- 节点创建和编辑改为弹窗表单，节点保存入口地址列表，后续创建受管节点间连接时从双方入口地址中选择 Endpoint。
- 节点 token 会持久保存在数据库里，节点编辑窗口可再次查看；节点 bar 右侧有编辑按钮，离线节点仍不可点击进入配置列表。

## 当前本机测试环境

- 工作目录：`/root/repo/link42`
- 前端地址通常为：`http://192.168.123.20:5173/`
- API 地址通常为：`http://192.168.123.20:8000`
- API 健康检查：`http://192.168.123.20:8000/api/health`
- 用户已授权测试/修复 Agent 在本机搭建真实开发测试环境：可以启动最新开发主控、使用临时测试数据库、安装/运行本机 Agent，并直接使用真实 `/etc/wireguard` 做测试；必须只操作测试专用接口名前缀如 `l42smoke*`，不能连接外部节点，结束后清理测试接口、配置和数据库。推荐执行 `scripts/smoke-real-local.sh` 做真实冒烟。
- 已创建持久 Docker 双节点测试环境用于 udp2raw/跨节点 E2E：
  - 镜像：`link42-node-smoke:latest`
  - 网络：`link42-smoke-net`，网段 `172.31.42.0/24`
  - 容器：`link42-node-a=172.31.42.11`，`link42-node-b=172.31.42.12`
  - 容器内工作区：`/workspace/link42` 挂载宿主 `/root/repo/link42`
  - 宿主主控建议监听：`0.0.0.0:18046`；容器访问主控用 `http://172.31.42.1:18046`
  - 容器支持 systemd、WireGuard、tcpdump，可真实启动 Agent 和 udp2raw systemd service；默认保留容器，不要随手删除。
- 用户可能会要求清空数据库从头测，此时可以删除 `link42.db` 后重启 API。
- 最近创建过两个本机测试节点，token 如下；如果数据库已清空则这些 token 已失效：
  - `node1=l42agent_dWpxQBthT_4drtsuK_EDWEbtKXVl937RUchLawszIII`
  - `node2=l42agent_hfx1eUJL5Gg8mLHTtOsujqRECLalGL5jrwpe_noWjzM`
- 单机可同时跑两个 Agent 进程模拟两个节点，但必须为每个进程设置不同的 `LINK42_NODE_ID`、`LINK42_AGENT_TOKEN`，并谨慎处理真实 `/etc/wireguard` 接口名冲突。

## 最近完成的关键功能

- 节点创建时只需要填写主控地址和节点名称，并返回 Agent 安装 token。
- 节点现在还保存入口地址列表，可填写多个 IPv4/IPv6/域名，供受管节点间连接选择 Endpoint。
- 新节点默认离线；Agent 注册或心跳后变为在线；心跳超时后变为离线。
- 离线节点不可点选和操作；若窗口已打开但提交时 Agent 离线，后端会返回离线错误。
- 节点支持编辑和删除；删除节点前要求该节点下所有 WireGuard 配置都已删除。
- WireGuard 配置支持创建和修改，接口为 `PATCH /api/wireguard/configs/{id}`。
- peer 使用单对象语义，前端使用 `PUT/GET/DELETE /api/wireguard/configs/{id}/peer`。
- `wg_interfaces` 增加 `runtime_status` 和 `deployed_config`。
- 生成部署计划时使用 `deployed_config` 作为 diff 基线，避免部署成功后仍然出现同样 diff。
- 没有 diff 时不能下发任务，前端禁用确认按钮，后端也拒绝空 diff 计划。
- 部署成功后记录 `deployed_config`，并将运行状态标记为 `running`。
- Agent 支持任务：
  - `wireguard.apply_config`
  - `wireguard.read_config`
  - `wireguard.status`
  - `wireguard.start_interface`
  - `wireguard.stop_interface`
  - `wireguard.delete_config`
  - `wireguard.import_scan`
- 启动、断开、删除 WireGuard 配置已经加入幂等处理：
  - API 避免相同配置上重复创建同类 pending/running 任务。
  - start/stop 根据 `runtime_status` 做幂等返回。
  - Agent 使用 `wg show <iface>` 判断是否需要重复 `wg-quick up/down`。
- 删除配置前要求配置已停止且没有忙碌任务；删除 DB 记录后下发 `wireguard.delete_config`。
- 删除已导入配置后，后端会把对应 ImportCandidate 标记回未导入，避免按钮一直显示已导入而无法再次导入。
- 扫描现有 `wg-quick` 会刷新 import candidates；Agent 返回的不存在候选应被清理或标记不可用，避免 UI 显示旧文件。
- 导入配置时不再把私钥和预共享密钥强制隐藏；面板用户被视为可信用户，可以查看私钥用于排障和跨节点配置。
- 受管节点间连接：
  - 创建时只需要接口名、双方 tunnel IP 列表、双方监听端口、双方 Endpoint 入口地址。
  - 系统自动生成双方私钥、公钥和预共享密钥。
  - 创建后直接下发双方配置、启动连接并设置开机自启，不再生成手动确认的 diff 计划。
  - 编辑、启动、停止、删除都按一对配置整体操作，避免只改一侧造成状态不一致。
  - 删除前要求双方连接都已停止。
- WireGuard 配置支持多个 Address，用于双栈等场景。
- WireGuard 配置支持 MTU，默认 `1420`。
- WireGuard 配置支持 `Table = off`，前端文案为“不自动生成路由”之类的选项语义。
- 手动连接和受管连接都支持高级自定义文本：
  - `[Interface]` 后插入自定义配置。
  - `[Peer]` 后插入自定义配置。
  - 受管连接双方不能共用高级配置，因为 PostUp 等可能每侧不同。
- 前端增加 toast 通知，不再把所有反馈堆在主页绿色条里。
- 前端增加基础输入校验，包括 CIDR、端口、WireGuard key 形状。
- 后端 schema 增加端口和 CIDR 形状校验。
- UI 已从三列并列展示改为节点列表、配置列表、配置窗口的层级交互。
- Agent 服务管理已抽象出 systemd、OpenRC 和 OpenWrt UCI 支持：
  - 常规 Linux 使用 `systemctl` 和 `wg-quick@<iface>`。
  - Alpine/OpenRC 使用 `rc-service`、`rc-update`。
  - OpenWrt 路径偏向 UCI/network 配置、`ifup/ifdown`。
- 已添加 x64 Agent 单文件二进制构建脚本 `scripts/agent/build-x64.sh`。
- 已添加 Agent 一键安装脚本 `deploy/sh/link42-agent.sh`，预期发布到 `https://get.pmman.tech/sh/link42-agent.sh`。
- 前端节点安装命令已经改为使用上述安装脚本，并从 `https://get.pmman.tech/res/link42/` 下载二进制资源。
- Git 仓库已初始化并推送过 first commit；远端为 `git@github.com:pmman289/link42.git`，提交身份为 `pmman <me@pmman.tech>`。

## 当前未完成或刚提出的需求

- 当前刚完成的需求：统一项目描述为“WireGuard 点对点链路管理面板”，并同步 README、页面左上角文案、架构文档和交接记忆。
- 当前主要开发焦点：拓扑图交互细节、前端体验、真实节点兼容性、udp2raw/mimic 中间层稳定性和测试回归。
- 拓扑图已具备节点拖动、坐标保存、还原布局、链路延迟/丢包展示、点击节点/链路跳转等基础能力；当前连线样式已回退为 React Flow 默认曲线，不再使用动态边连接点。
- 后续如果继续优化拓扑视觉，应使用官方自定义 edge/node 组件并做浏览器截图验证。

## 当前验证结果

- `.venv/bin/python -m pytest -q` 已通过，最近结果为 `56 passed`。
- `.venv/bin/python -m compileall apps/api apps/agent packages tests` 已通过。
- `npm run build` 已通过。
- 2026-06-30 做过一次隔离 smoke test：`LINK42_DATABASE_URL=sqlite:////tmp/link42-smoke.db` 启动 API 到 `127.0.0.1:18000`，用临时节点 token 启动 `LINK42_AGENT_DRY_RUN=1` Agent 和 `/tmp/link42-smoke-wg`，验证健康检查、登录、节点创建、Agent 注册/心跳/能力上报、导入扫描任务、手动 WireGuard 配置生成计划和 dry-run apply_config 全链路均通过。
- 2026-06-30 新增并跑通真实本机冒烟脚本 `scripts/smoke-real-local.sh`：开发主控监听 `127.0.0.1:18042`，两个本机 Agent 使用 `127.0.10.1` 和 `127.0.10.2`，真实写入 `/etc/wireguard/l42smokea.conf`、`/etc/wireguard/l42smokeb.conf`，真实执行 `wg-quick up/down`，验证本机双 WireGuard 接口连通后清理配置、接口、进程和临时数据库。

## 常用命令

停止当前服务：

```bash
pkill -f 'uvicorn link42_api.main:app|npm run preview|vite.*5173|python -m link42_agent.main'
```

启动 API：

```bash
.venv/bin/uvicorn link42_api.main:app --host 0.0.0.0 --port 8000
```

启动前端预览：

```bash
npm run preview -- --host 0.0.0.0 --port 5173
```

启动 node 2 Agent：

```bash
cd /root/repo/link42
setsid env LINK42_SERVER_URL=http://192.168.123.20:8000 LINK42_NODE_ID=2 LINK42_AGENT_TOKEN=l42agent_YGhpdQRV5yBGkWhOo9Rxs9UzCmEqFW8x822OR7ETgsI LINK42_WIREGUARD_DIR=/etc/wireguard LINK42_AGENT_DRY_RUN=0 LINK42_POLL_INTERVAL=2 .venv/bin/python -m link42_agent.main > /tmp/link42-agent-node2.log 2>&1 < /dev/null &
```

构建 x64 Agent 二进制：

```bash
scripts/agent/build-x64.sh
```

Agent 安装脚本发布后，前端展示的命令形如：

```bash
curl -fsSL https://get.pmman.tech/sh/link42-agent.sh | sudo env LINK42_SERVER_URL='http://controller:8000' LINK42_NODE_ID='1' LINK42_AGENT_TOKEN='token' sh
```

## 注意事项

- 用户正在实机测试，不要主动清空数据库，除非用户明确要求。
- Agent 是真实模式，不是 dry-run，会写 `/etc/wireguard` 并执行 `wg-quick`。
- 家庭路由器 OpenWrt 测试环境可通过 `ssh mrouter` 访问，但这是用户真实家庭路由器，测试必须只做低风险检查，不要破坏现有网络环境。
- 不要把 Agent 以前台命令启动，它会作为轮询进程阻塞当前交互。
- 当前工作树出现过大量 `100644 -> 100755` 的文件模式变化，`git diff --stat` 为 0 行变更；不要把这些无关权限变化当业务修改提交。
- FastAPI `TestClient` 在当前环境曾经挂起，测试更偏向 service/DB 层。
- 手工编辑文件使用 `apply_patch`。
- Python 注释和 docstring 约定使用中文。
- Git 操作和 push 往往需要沙箱提升权限。
- 网络访问受限；Docker build、npm/pip 下载、git push 等可能需要 `require_escalated`。

## 近期上下文

用户最近要求总结整个项目并更新 docs，准备切换上下文。切换后下一步大概率是继续完成“主控 Docker 镜像 + 打包脚本 + 可映射配置目录”的任务。
