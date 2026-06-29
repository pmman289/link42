# Link42 项目决策记录

## 产品定位

- Link42 是小型内网使用的轻量节点链路管理面板。
- 第一版只实现节点添加、WireGuard 点对点配置管理、现有 `wg-quick` 配置导入。
- 第一版不实现 GRE/IPIP/VXLAN、复杂监控、告警、权限体系、多租户、Redis、队列、Kubernetes 部署。

## 核心模型

- 一个 WireGuard 配置等同于一根点对点虚拟网线。
- 一个 WireGuard 配置只连接一个远端对端。
- 一个节点可以包含多个 WireGuard 配置。
- 节点可以配置多个入口地址，用于节点间受管连接选择 Endpoint；入口地址可以覆盖 IPv4、IPv6、内网地址、公网地址或域名。
- 受管 WireGuard 配置必须最多只有一个 `[Peer]`。
- 可部署 WireGuard 配置必须正好有一个启用的 `[Peer]`。
- 多 Peer 的 `wg-quick` 配置允许导入为观察状态，但不能直接接管管理，必须拆分为多个单对端配置后再接管。
- 数据库中的 `deployed_config` 是已成功部署到节点的配置快照，生成 diff 时以它作为基线，而不是重新读取空白或未同步文件。
- 数据库中的 `runtime_status` 是页面展示和操作禁用的主要运行状态来源，Agent 状态任务会持续修正它。
- 私钥和预共享密钥可以在可信管理面板展示；不要在日志、错误详情和非必要任务结果中泄露。

## 系统架构

- 架构采用中心 API + 全节点 Agent。
- API 不通过 SSH 主动连接节点。
- Agent 主动轮询 API、拉取任务、执行本机操作、上报结果。
- 前端只修改期望状态；真正写入节点前必须生成 Change Plan 并由用户确认。

## 技术选型

- 后端使用 Python + FastAPI + SQLAlchemy。
- Agent 使用 Python，便于审阅。
- 前端使用 React + TypeScript + Vite。
- 默认数据库使用 SQLite。
- 后续可通过 `LINK42_DATABASE_URL` 切换到 MySQL 兼容数据库。
- 第一版不引入 Redis、缓存、消息队列。
- 第一版暂未引入 Alembic；启动时使用 `create_all()` 建表，并用轻量修复补齐旧 SQLite 的唯一约束。

## WireGuard 管理规则

- 配置文件由 `link42_wireguard` 包集中解析和渲染。
- 渲染结果必须稳定，便于生成 diff。
- WireGuard 配置支持多个 Address，用于 IPv4/IPv6 双栈和多地址链路。
- WireGuard 配置支持 MTU，默认值为 `1420`。
- `Table = off` 表示不让 wg-quick 自动生成路由；前端应以选项语义展示，不应让用户理解为普通文本字段。
- 手动配置和受管节点间配置都支持在 `[Interface]` 和 `[Peer]` 后插入自定义文本。
- 受管节点间配置的高级自定义文本必须分成本端 Interface、本端 Peer、对端 Interface、对端 Peer 四份，不能两端共用。
- 部署任务使用 `wireguard.apply_config`。
- 读取当前配置任务使用 `wireguard.read_config`。
- 连接状态任务使用 `wireguard.status`。
- 启动连接任务使用 `wireguard.start_interface`。
- 断开连接任务使用 `wireguard.stop_interface`。
- 删除配置任务使用 `wireguard.delete_config`。
- 导入扫描任务使用 `wireguard.import_scan`。
- Agent 默认扫描和写入 `/etc/wireguard`。
- 测试环境可通过 `LINK42_WIREGUARD_DIR` 指向临时目录。
- 生产实机测试必须使用 `/etc/wireguard` 且 `LINK42_AGENT_DRY_RUN=0`。
- Agent 写入已存在配置前必须创建备份。

## 受管节点间连接规则

- 受管节点间连接是 Link42 完全管理的双端 WireGuard 链路。
- 创建受管连接时用户只填写：
  - 接口名称。
  - 双方 tunnel Address 列表。
  - 双方 ListenPort。
  - 双方使用哪个节点入口地址作为 Endpoint。
  - 可选 MTU、Table 策略和双方独立高级配置。
- 系统自动生成双方密钥对和预共享密钥。
- 创建成功后直接下发双方配置、启动双方连接并设置开机自启，不走手动连接的 diff 确认模型。
- 编辑、启动、停止、删除受管节点间连接时必须同时操作双方配置，避免单边漂移。
- 删除前要求双方连接均已停止。
- 受管节点间连接的 API 应保持幂等，重复点击不能重复创建任务或制造半成功状态。
- 从已有 `wg-quick` 导入为受管连接时，应读取两个导入配置作为表单初始值；如果某侧 Endpoint 不指向另一节点入口地址，需要弹窗提示，但允许用户强制继续。
- 导入为受管连接并确认创建后，原有两个导入配置应被新受管连接替换，旧配置需要停止、备份或删除，具体行为必须让用户明确确认。

## API 约定

- 新语义接口使用 `configs` 命名：
  - `GET /api/nodes/{node_id}/wireguard/configs`
  - `POST /api/nodes/{node_id}/wireguard/configs`
  - `GET /api/wireguard/configs/{config_id}`
  - `PUT /api/wireguard/configs/{config_id}/peer`
  - `GET /api/wireguard/configs/{config_id}/peer`
  - `DELETE /api/wireguard/configs/{config_id}/peer`
  - `POST /api/wireguard/configs/{config_id}/plan-apply`
  - `POST /api/wireguard/configs/{config_id}/take-over`
- 修改配置使用 `PATCH /api/wireguard/configs/{config_id}`。
- 旧 `interfaces` 和 `peers` 路由保留兼容，但前端应使用新 `configs/{id}/peer` 单对象接口。
- 保存对端是“设置/替换唯一对端”，不是追加 Peer。
- 没有 diff 的 Change Plan 必须被后端拒绝，避免无意义重复部署。
- 针对同一配置和同类 WireGuard 操作，API 需要避免重复创建 pending/running 任务。
- start/stop/delete 等操作需要具备幂等语义，重复点击不能造成重复任务或错误状态震荡。

## 前端约定

- 用户首先看到节点列表。
- 离线节点不可点击；在线节点点击后展示该节点下多个 WireGuard 配置。
- 节点 bar 右侧提供编辑按钮，离线节点也能编辑和查看 token，但不能点击进入配置列表。
- 点击具体 WireGuard 配置后打开配置窗口，窗口中展示本地配置、唯一对端、部署计划和连接操作。
- 创建连接入口应是按钮，而不是常驻杂乱表单：
  - 手动创建连接到非管理节点。
  - 创建连接到其它 Link42 节点。
- 用户点击部署前，必须先生成部署计划并查看 diff。
- 用户确认部署计划后才创建 Agent 任务。
- 无 diff 时，确认部署按钮必须禁用。
- 页面通知使用 toast 或弹窗语义，错误和成功需要有不同视觉状态，不能全部显示为主页绿色提示条。
- 输入项需要在前端做基础校验，后端也必须做对应校验。
- 前端生产预览通过当前访问主机自动推断 API 地址：`http://<当前主机>:8000`。
- 后端已允许内网前端跨端口访问 API 的 CORS。

## 部署与发布约定

- Agent x64 单文件二进制由 `scripts/agent/build-x64.sh` 构建。
- Agent 一键安装脚本位于 `deploy/sh/link42-agent.sh`。
- Agent 安装脚本预期发布到 `https://get.pmman.tech/sh/link42-agent.sh`。
- Agent 二进制资源预期发布到 `https://get.pmman.tech/res/link42/link42-agent-linux-x64`。
- 前端展示的 Agent 安装命令应使用安装脚本，并通过环境变量传入主控地址、节点 ID、节点 token。
- Agent 支持 systemd、OpenRC 和 OpenWrt UCI/ifup 模式；OpenWrt/家庭路由器测试必须保持低风险，不能破坏用户现有网络。
- 主控 Docker 镜像是下一步需求：应预留 `/data` 存数据库、`/config` 存配置文件，并提供简单构建脚本。

## 代码规范

- Python 后端和 Agent 代码必须便于人工审阅。
- 注释和 docstring 使用中文。
- 每个函数必须有中文 docstring 或中文注释说明职责。
- 每个模块级常量必须有中文注释说明用途。
- 修改时优先保持现有结构，避免无关重构。
- 手工编辑文件使用 `apply_patch`。
