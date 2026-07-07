import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Check, ChevronDown, ChevronRight, FileText, Folder, GitBranch, LineChart as LineChartIcon, LogOut, Maximize2, Moon, Network, Pencil, Plug, Plus, RefreshCw, Server, Settings, ShieldCheck, Sun, Upload, X } from "lucide-react";
import { Background, Handle, Position, ReactFlow, type Edge as FlowEdge, type EdgeMouseHandler, type Node as FlowNode, type NodeMouseHandler, type OnNodeDrag } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import CodeMirror from "@uiw/react-codemirror";
import { indentWithTab } from "@codemirror/commands";
import { StreamLanguage } from "@codemirror/language";
import { nginx } from "@codemirror/legacy-modes/mode/nginx";
import { EditorView, keymap } from "@codemirror/view";
import { Tree, type NodeRendererProps } from "react-arborist";
import CreatableSelect from "react-select/creatable";
import type { SingleValue, StylesConfig } from "react-select";
import "./styles.css";

type NodeItem = {
  id: number;
  name: string;
  hostname: string | null;
  region: string | null;
  management_ip: string | null;
  public_ip: string | null;
  endpoint_ips: string[];
  topology_endpoint: string | null;
  github_proxy_url: string | null;
  topology_x: number | null;
  topology_y: number | null;
  topology_locked: boolean;
  agent_token_value: string | null;
  agent_version: string | null;
  agent_protocol_version: number | null;
  agent_capabilities: string[];
  agent_platform: Record<string, unknown>;
  agent_update_status: string | null;
  agent_last_error: string | null;
  middleware_install_status: string | null;
  status: string;
  last_seen_at: string | null;
};

type ConfigItem = {
  id: number;
  node_id: number;
  name: string;
  tunnel_ips: string[];
  listen_port: number | null;
  private_key_value: string | null;
  public_key: string | null;
  mtu: number | null;
  source: string;
  managed: boolean;
  enabled: boolean;
  table_name: string | null;
  interface_custom_config: string | null;
  runtime_status: string;
  primary_peer_endpoint_host: string | null;
  primary_peer_endpoint_port: number | null;
  primary_peer_allowed_ips: string[];
  monitor_summary: LinkMonitorSummary | null;
  warnings: string[];
};

type ConnectionEndpointItem = {
  id: number;
  endpoint_ref: string;
  node_id: number;
  node_name: string | null;
  role: "local" | "peer" | string;
  interface_name: string;
  tunnel_ips: string[];
  mtu: number | null;
  routes: string[];
  runtime_status: string;
  protocol_config: Record<string, unknown>;
  monitor_summary: LinkMonitorSummary | null;
};

type ConnectionItem = {
  id: number;
  connection_ref: string;
  protocol_type: "wireguard" | "gre" | string;
  protocol_label: string;
  name: string;
  source: string;
  managed: boolean;
  status: string;
  endpoints: ConnectionEndpointItem[];
  warnings: string[];
};

type LinkMonitorSummary = {
  monitor_id: number;
  target_host: string;
  last_latency_ms: number | null;
  avg_latency_ms: number | null;
  min_latency_ms: number | null;
  max_latency_ms: number | null;
  jitter_ms: number | null;
  packet_loss: number;
  stability_score: number;
  status: "healthy" | "warning" | "critical" | "unknown";
  sample_count: number;
  last_checked_at: string | null;
};

type LinkMonitor = {
  id: number;
  node_id: number;
  interface_id: number | null;
  connection_endpoint_id: number | null;
  name: string;
  target_host: string;
  interval_seconds: number;
  retention_days: number;
  enabled: boolean;
  next_due_at: string | null;
  last_checked_at: string | null;
  summary: LinkMonitorSummary | null;
};

type LinkMonitorSample = {
  checked_at: string;
  success: boolean;
  latency_ms: number | null;
  error: string | null;
};

type LinkMonitorSamplesResponse = {
  monitor: LinkMonitor;
  summary: LinkMonitorSummary | null;
  samples: LinkMonitorSample[];
};

type TopologyNode = {
  id: number;
  name: string;
  status: string;
  hostname: string | null;
  region: string | null;
  endpoint_ips: string[];
  topology_endpoint: string | null;
  agent_version: string | null;
  agent_platform: Record<string, unknown>;
  topology_x: number | null;
  topology_y: number | null;
  topology_locked: boolean;
};

type TopologyEdge = {
  id: string;
  connection_ref: string | null;
  protocol_type: "wireguard" | "gre" | string;
  protocol_label: string;
  local_node_id: number;
  peer_node_id: number;
  local_interface_id: number;
  peer_interface_id: number;
  local_interface_name: string;
  peer_interface_name: string;
  local_status: string;
  peer_status: string;
  middleware_type: string | null;
  local_monitor: LinkMonitorSummary | null;
  peer_monitor: LinkMonitorSummary | null;
};

type TopologyDisplayEdge = TopologyEdge & {
  link_count: number;
  links: TopologyEdge[];
};

type TopologyResponse = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
};

type PeerItem = {
  id: number;
  interface_id: number;
  name: string | null;
  public_key: string;
  preshared_key_value: string | null;
  allowed_ips: string[];
  endpoint_host: string | null;
  endpoint_port: number | null;
  persistent_keepalive: number | null;
  peer_custom_config: string | null;
  peer_node_id: number | null;
  peer_interface_id: number | null;
};

type ManagedLink = {
  local_interface: ConfigItem;
  peer_interface: ConfigItem;
  local_peer: PeerItem;
  peer_peer: PeerItem;
  middleware: MiddlewareConfig | null;
};

type ManagedCreateProtocol = "wireguard" | "gre";

type MiddlewareConfig = Udp2RawMiddleware | MimicMiddleware;

type Udp2RawMiddleware = {
  type: "udp2raw";
  enabled: boolean;
  server_side: "local" | "peer";
  server_listen_host: string;
  server_connect_host: string | null;
  server_listen_port: number;
  server_forward_host: string | null;
  server_forward_port: number | null;
  client_listen_host: string;
  client_listen_port: number;
  raw_mode: string;
  cipher_mode: string;
  password: string;
  auto_rule: boolean;
};

type MimicMiddleware = {
  type: "mimic";
  enabled: boolean;
  local_bind_interface: string;
  peer_bind_interface: string;
  xdp_mode: "auto" | "native" | "skb";
  link_type: string;
  handshake_interval: number | null;
  keepalive_interval: number | null;
  padding: number | null;
};

type ChangePlan = {
  id: number;
  title: string;
  status: string;
  summary: string;
  diff: string;
  affected_node_ids: number[];
  task_status: string | null;
  task_result: Record<string, unknown> | null;
};

type TaskRequestResult = {
  task_id: number | null;
  status: string;
  message: string;
  result: Record<string, unknown> | null;
};

type AgentTaskStatus = {
  id: number;
  node_id: number;
  type: string;
  status: string;
  result: Record<string, unknown> | null;
};

type NodePluginAction = {
  name: string;
  task_type: string;
  risk: string;
  requires_confirm: boolean;
};

type NodePluginStatus = {
  type: string;
  display_name: string;
  description: string;
  min_agent_version: string;
  capabilities: string[];
  actions: NodePluginAction[];
  available: boolean;
  missing_capabilities: string[];
  agent_version: string | null;
  version_supported: boolean;
  node_status: string;
};

type NodePluginActionResult = {
  task_id: number;
  plugin_type: string;
  action: string;
  status: string;
  message: string;
};

type BirdResource = {
  resource_key: string;
  path: string;
  name: string;
  size: number;
  sha256: string;
  mtime: string;
  editable: boolean;
  is_main: boolean;
};

type BirdFileTreeNode = {
  name: string;
  path: string;
  directories: Map<string, BirdFileTreeNode>;
  files: BirdResource[];
};

type BirdTreeItem = {
  id: string;
  name: string;
  path: string;
  type: "directory" | "file";
  resource?: BirdResource;
  children?: BirdTreeItem[];
};

type BirdFileDraft = {
  resource: BirdResource;
  content: string;
  originalContent: string;
  sha256: string;
};

type PortInventorySetting = {
  range_start: number | null;
  range_end: number | null;
};

type PortInventoryEntry = {
  id: number;
  node_id: number;
  protocol: "TCP" | "UDP";
  port: number;
  purpose: string;
  source: string;
  detected_process: string | null;
  detected_pid: string | null;
  detected_source: string | null;
  created_at: string;
  updated_at: string;
};

type PortInventory = {
  setting: PortInventorySetting;
  entries: PortInventoryEntry[];
};

type PortScanResult = {
  protocol: "TCP" | "UDP";
  port: number;
  purpose?: string;
  source?: string;
  detected_process?: string | null;
  detected_pid?: string | null;
  detected_source?: string | null;
};

type AgentUpgradePlan = {
  node_id: number;
  current_version: string | null;
  target_version: string | null;
  upgrade_mode: "self_upgrade" | "manual" | "none" | "unavailable";
  reason: string | null;
  matched_platform: string | null;
  matched_asset: { path: string; sha256: string; size: number | null } | null;
  manual_command: string | null;
  status: string | null;
};

type ImportCandidate = {
  id: number;
  node_id: number;
  path: string;
  interface_name: string;
  warnings: string[];
  imported: boolean;
};

type NodeCreateResult = {
  node: NodeItem;
  agent_token: string;
};

type LoginResult = {
  token: string;
  username: string;
};

type ControllerSettings = {
  controller_url: string;
  username: string;
  site_title: string;
  site_logo_url: string;
};

type BrandingSettings = {
  site_title: string;
  site_logo_url: string;
};

type Toast = {
  id: number;
  type: "success" | "error" | "info";
  text: string;
};

// API 基础路径；生产由 FastAPI 同源托管，Vite dev 通过 /api proxy 转发。
const INFERRED_API_BASE = "";
const API_BASE =
  import.meta.env.VITE_LINK42_API_BASE ||
  INFERRED_API_BASE;

// 默认主控地址；节点 Agent 从本机访问时通常使用 127.0.0.1。
const DEFAULT_CONTROLLER_URL =
  import.meta.env.VITE_LINK42_CONTROLLER_URL || API_BASE;
const DEFAULT_SITE_TITLE = "Link42";
const DEFAULT_SITE_LOGO_URL = "/logo.png";
const AUTH_TOKEN_KEY = "link42.authToken";
const AUTH_EXPIRED_EVENT = "link42:auth-expired";
const THEME_KEY = "link42.theme";
const TASK_POLL_INTERVAL_MS = 2000;
const AGENT_TASK_POLL_LIMIT = 90;
const SHORT_TASK_POLL_LIMIT = 30;
const PORT_INVENTORY_PAGE_SIZE = 10;

// 读取本地保存的主题，未设置时跟随系统偏好。
function initialTheme(): "light" | "dark" {
  const saved = window.localStorage.getItem(THEME_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

// 把逗号或换行分隔的输入转换成去空后的列表。
function splitList(value: string): string[] {
  // 将输入框中的逗号或换行分隔内容转换成 API 需要的数组；不要按冒号切分，IPv6 会用到 "::"。
  return value
    .split(/[,\n]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

// 对字符串列表去重，并保留第一次出现的顺序。
function uniqueList(values: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

// 从表单字段读取可选整数，空值返回 null。
function optionalInt(value: FormDataEntryValue | null, label = "数值"): number | null {
  const text = String(value || "").trim();
  if (!text) return null;
  if (!/^-?\d+$/.test(text)) {
    throw new Error(`${label}必须是整数`);
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label}超出可支持范围`);
  }
  return parsed;
}

async function api<T>(path: string, options?: RequestInit & { skipAuth?: boolean }): Promise<T> {
  // 统一封装 fetch，集中处理 JSON 和错误信息。
  const token = options?.skipAuth ? "" : window.localStorage.getItem(AUTH_TOKEN_KEY);
  const { skipAuth: _skipAuth, headers, ...fetchOptions } = options || {};
  const response = await fetch(`${API_BASE}${path}`, {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(headers || {}),
    },
  });
  if (!response.ok) {
    const text = await response.text();
    if (response.status === 401 && path !== "/api/auth/login") {
      window.localStorage.removeItem(AUTH_TOKEN_KEY);
      window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
    }
    throw new Error(formatApiError(response.status, text, response.statusText));
  }
  return response.json() as Promise<T>;
}

type ApiValidationIssue = {
  msg?: string;
  loc?: Array<string | number>;
  type?: string;
};

// 判断未知值是否为普通对象。
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// 把后端错误响应整理成前端提示文本。
function formatApiError(status: number, body: string, fallback: string): string {
  // FastAPI 错误通常放在 detail 字段，这里转成用户能直接理解的提示。
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed.detail === "string") {
      return `${status}: ${translateApiDetail(parsed.detail)}`;
    }
    if (Array.isArray(parsed.detail)) {
      return `${status}: ${parsed.detail
        .map(formatValidationIssue)
        .join("; ")}`;
    }
  } catch {
    // 非 JSON 响应直接走下面的兜底文本。
  }
  return `${status}: ${translateApiDetail(body || fallback)}`;
}

// 把 Pydantic 校验错误整理成中文提示。
function formatValidationIssue(item: unknown): string {
  if (!isRecord(item)) return "请求参数校验失败";
  const issue = item as ApiValidationIssue;
  const message = translateApiDetail(issue.msg || issue.type || "请求参数校验失败");
  const field = validationFieldLabel(issue.loc);
  return field ? `${field}：${message}` : message;
}

// 将后端校验路径转换成用户能理解的字段名。
function validationFieldLabel(loc: ApiValidationIssue["loc"]): string {
  if (!Array.isArray(loc)) return "";
  const labels: Record<string, string> = {
    username: "用户名",
    password: "密码",
    new_password: "新密码",
    controller_url: "主控访问地址",
    site_title: "站点标题",
    name: "名称",
    endpoint_ips: "入口地址",
    topology_endpoint: "拓扑展示地址",
    github_proxy_url: "GitHub 代理地址",
    listen_port: "监听端口",
    endpoint_port: "入口端口",
    allowed_ips: "允许路由",
    persistent_keepalive: "保活间隔",
    range_start: "起始端口",
    range_end: "结束端口",
    port: "端口",
    purpose: "用途",
    resource_key: "配置文件",
    content: "配置内容",
    protocol_type: "连接协议",
    peer_node_id: "对端节点",
    local_interface_name: "本端接口名称",
    peer_interface_name: "对端接口名称",
    local_outer_ip: "本端外层源 IP",
    peer_outer_ip: "对端外层源 IP",
    local_tunnel_ips: "本端隧道地址",
    peer_tunnel_ips: "对端隧道地址",
    local_routes: "本端经隧道路由",
    peer_routes: "对端经隧道路由",
    mtu: "MTU",
    gre_key: "GRE Key",
    ttl: "TTL",
    risk_accepted: "风险确认",
  };
  const field = [...loc].reverse().find((part) => typeof part === "string" && part !== "body");
  return typeof field === "string" ? labels[field] || field : "";
}

const API_DETAIL_MESSAGES: Record<string, string> = {
  "agent is offline": "Agent 离线，节点当前不能执行部署或扫描任务",
  "node is offline": "节点离线，暂时不能执行插件任务",
  "node name already exists": "节点名称已存在",
  "node not found": "节点不存在",
  "not found": "内容不存在",
  "interface name already exists on node": "该节点上已存在同名 WireGuard 配置",
  "interface not found": "WireGuard 配置不存在",
  "peer interface not found": "对端 WireGuard 配置不存在",
  "wireguard config not found": "WireGuard 配置不存在",
  "managed node link is incomplete": "受管连接数据不完整，请重新创建或检查双方配置",
  "deployable wireguard config must have exactly one enabled peer":
    "可部署配置必须且只能有一个启用对端",
  "change plan not found": "部署计划不存在",
  "change plan is not draft": "该部署计划已被确认或已结束，不能重复执行",
  "change plan has no task payload": "部署计划缺少 Agent 任务内容",
  "change plan has no diff": "本次没有需要下发的配置变化",
  "wireguard config must be deployed before start": "WireGuard 配置需要先部署再启动",
  "OpenWrt UCI nodes do not support wg-quick import scan": "OpenWrt/UCI 节点不支持 wg-quick 文件导入扫描",
  "wireguard interface must be stopped before delete": "删除前必须先断开对应 WireGuard 连接",
  "peer node must be different": "请选择另一个节点作为对端",
  "local node has no endpoint address": "当前节点缺少可作为入口的地址",
  "peer node has no endpoint address": "对端节点缺少可作为入口的地址",
  "local endpoint address is not registered on node": "本端入口地址不属于当前节点",
  "peer endpoint address is not registered on node": "对端入口地址不属于所选节点",
  "at least one endpoint address is required": "本端或对端至少需要填写一个入口地址",
  "udp2raw server endpoint address is required": "udp2raw 服务端侧需要填写可连接的入口地址",
  "udp2raw server listen port is required": "请填写 udp2raw 服务端监听端口",
  "udp2raw client listen port is required": "请填写 udp2raw 客户端本地监听端口",
  "udp2raw server side requires WireGuard listen port": "udp2raw 服务端所在节点必须填写 WireGuard 监听端口",
  "mimic requires endpoint address on both sides": "启用 mimic 时双方入口地址都必须填写",
  "mimic requires WireGuard listen port on both sides": "启用 mimic 时双方 WireGuard 监听端口都必须填写",
  "mimic peer endpoint port is required": "mimic 对端入口需要填写端口，或填写对端监听端口",
  "mimic local endpoint port is required": "mimic 本端入口需要填写端口，或填写本端监听端口",
  "mimic local bind interface is required": "请选择本端 mimic 出口网卡",
  "mimic peer bind interface is required": "请选择对端 mimic 出口网卡",
  "wireguard tool is not installed": "主控缺少 wg 工具，无法自动生成密钥",
  "managed node links are deployed directly": "受管连接由系统直接下发，不使用部署计划",
  "use managed link operation": "受管连接需要使用双端操作",
  "wireguard config is not a managed node link": "该配置不是受管节点连接",
  "local imported endpoint does not point to peer node": "本端导入配置的入口地址不指向所选对端节点",
  "peer imported endpoint does not point to local node": "对端导入配置的入口地址不指向当前节点",
  "node has wireguard configs": "节点下仍有 WireGuard 配置，请先删除所有配置",
  "connection not found": "连接不存在",
  "use wireguard API for WireGuard connections": "WireGuard 连接请使用 WireGuard 配置入口操作",
  "gre connection endpoints are incomplete": "GRE 连接端点不完整，请重新创建",
  "gre risk must be accepted": "创建或修改 GRE 前需要确认风险提示",
  "gre outer addresses must be different": "GRE 双方外层地址不能相同",
  "gre ttl requires pmtu discovery": "填写 GRE TTL 时必须启用 PMTU discovery",
  "protocol_type must be gre": "连接协议不匹配，请重新选择连接类型",
  "address must be IPv4": "地址必须是 IPv4",
  "CIDR value must be IPv4": "CIDR 必须使用 IPv4 地址",
  "interface name is required": "接口名称不能为空",
  "interface name must be 15 characters or fewer": "接口名称不能超过 15 个字符",
  "interface name contains unsupported characters": "接口名称只能包含字母、数字、下划线、点和短横线",
  "GRE key must be a number": "GRE Key 必须是数字",
  "GRE key must be between 0 and 4294967295": "GRE Key 必须在 0 到 4294967295 之间",
  "MTU must be between 576 and 9000": "MTU 必须在 576-9000 之间",
  "TTL must be between 1 and 255": "TTL 必须在 1-255 之间",
  "not authenticated": "登录已失效，请重新登录",
  "invalid username or password": "用户名或密码错误",
  "invalid agent credentials": "节点认证失败，请重新复制 Agent 启动命令",
  "controller url is required": "请填写主控访问地址",
  "controller url is required before agent upgrade": "请先在系统设置中填写主控访问地址",
  "username is required": "请填写用户名",
  "logo must be PNG, JPEG, or WebP": "Logo 只能上传 PNG、JPEG 或 WebP 图片",
  "logo not uploaded": "还没有上传 Logo",
  "logo file is required": "请选择要上传的 Logo 文件",
  "logo file must be no larger than 3 MiB": "Logo 文件不能超过 3 MiB",
  "invalid agent release manifest": "Agent 发布清单无效，请检查主控发布资产",
  "agent release not found": "找不到对应的 Agent 发布版本",
  "agent release asset not found": "找不到对应平台的 Agent 安装包",
  "invalid agent release asset path": "Agent 安装包路径无效",
  "agent release asset file not found": "Agent 安装包文件不存在",
  "agent self upgrade is not available": "当前节点暂不支持一键升级，请使用手动升级命令",
  "only one middleware can be enabled": "同一条连接只能启用一种中间层",
  "unsupported middleware type": "暂不支持该中间层类型",
  "middleware plugin not found": "中间层插件不存在",
  "node does not support mimic middleware": "该节点暂不支持 mimic",
  "node does not support installing mimic": "该节点暂不支持自动安装 mimic",
  "plugin not found": "插件不存在",
  "plugin action not found": "插件操作不存在",
  "agent does not support plugin version": "当前 Agent 版本过低，请升级 Agent 后再使用该插件",
  "plugin is not supported by this node": "该节点未上报插件所需能力，请升级或重启 Agent 后重试",
  "range_start must be less than or equal to range_end": "起始端口不能大于结束端口",
  "port is outside configured range": "端口不在当前台账范围内",
  "port entry already exists": "该端口记录已存在",
  "port entry not found": "端口记录不存在",
  "topology x and y must be provided together": "拓扑坐标必须同时包含横向和纵向位置",
  "replace interface not found": "要替换的导入配置不存在",
  "replace interface must be unmanaged imported config": "只能替换尚未接管的导入配置",
  "import candidate not found": "导入候选不存在",
  "candidate already imported": "该候选配置已经导入",
  "only imported interfaces need takeover": "只有导入观察记录需要接管",
  "imported config contains multiple peers and must be split before takeover":
    "导入配置包含多个对端，请先拆分成单对端配置后再接管",
  "imported config must have exactly one enabled peer before takeover":
    "导入配置必须且只能有一个启用对端后才能接管",
  "link monitor not found": "链路监测不存在",
  "invalid monitor window": "监测时间范围无效",
  "udp2raw asset not found": "找不到 udp2raw 安装资产",
  "port must be between 1 and 65535": "端口必须在 1-65535 之间",
  "CIDR value must contain prefix length": "CIDR 地址必须带前缀长度，例如 10.0.0.1/32",
  "URL must not contain whitespace or quotes": "URL 不能包含空格或引号",
  "URL must start with http:// or https://": "URL 必须以 http:// 或 https:// 开头",
  "URL must be an absolute path or start with http:// or https://": "URL 必须是绝对路径，或以 http:// / https:// 开头",
  "persistent_keepalive must be between 0 and 65535": "保活间隔必须在 0-65535 之间",
  "monitor target must be an IPv4 or IPv6 address": "监测目标必须是 IPv4 或 IPv6 地址",
  "interval_seconds must be between 1 and 300": "刷新频率必须在 1-300 秒之间",
  "retention_days must be between 1 and 90": "保留时间必须在 1-90 天之间",
  "server_side must be local or peer": "udp2raw 服务端位置无效",
  "udp2raw ip fields must be IPv4 or IPv6 addresses, not domain names": "udp2raw 地址必须填写 IP，不能填写域名",
  "raw_mode must be faketcp, udp, or icmp": "udp2raw 传输模式只能是 faketcp、udp 或 icmp",
  "cipher_mode must be xor, aes128cbc, or none": "udp2raw 加密模式只能是 xor、aes128cbc 或 none",
  "mimic interface name contains unsupported characters": "mimic 网卡名称包含不支持的字符",
  "xdp_mode must be auto, native, or skb": "XDP 模式只能是 auto、native 或 skb",
  "mimic numeric options must be non-negative": "mimic 数值选项不能为负数",
  "mimic padding must be between 0 and 16": "mimic 填充长度必须在 0-16 之间",
  "Field required": "必填项不能为空",
  "Input should be a valid integer": "请输入有效整数",
  "Input should be a valid string": "请输入有效文本",
  "Input should be a valid list": "请输入有效列表",
  "mimic already installed": "mimic 已安装",
  "mimic install task queued": "mimic 安装任务已创建",
  "scan task already queued": "扫描任务已存在，正在等待 Agent 执行",
  "scan task queued": "扫描任务已创建，等待 Agent 执行",
  "插件任务已创建": "插件任务已创建",
  "升级任务已存在": "升级任务已存在",
  "升级任务已创建": "升级任务已创建",
};

// 把后端稳定英文错误详情翻译成中文界面提示。
function translateApiDetail(detail: string): string {
  // 后端 detail 保持稳定英文，前端负责给中文界面补充可读提示。
  const trimmed = detail.trim();
  if (!trimmed) return "操作失败，请稍后重试";
  if (trimmed.startsWith("Value error, ")) {
    return translateApiDetail(trimmed.slice("Value error, ".length));
  }
  const direct = API_DETAIL_MESSAGES[trimmed];
  if (direct) return direct;
  if (/^agent does not support task:/.test(trimmed)) {
    return "当前 Agent 版本不支持这个任务，请升级 Agent 后重试";
  }
  if (/^wireguard tool failed:/.test(trimmed)) {
    return `wg 工具执行失败：${trimmed.replace(/^wireguard tool failed:\s*/, "") || "请检查主控环境"}`;
  }
  const ipFieldMatch = trimmed.match(/^(.+) must be an IP address for (udp2raw|mimic)$/);
  if (ipFieldMatch) {
    const target = ipFieldMatch[2] === "mimic" ? "mimic" : "udp2raw";
    return `${target} 地址必须填写 IP，不能填写域名`;
  }
  const cidrMatch = trimmed.match(/^invalid CIDR value:\s*(.+)$/);
  if (cidrMatch) {
    return `CIDR 地址格式无效：${cidrMatch[1]}`;
  }
  return trimmed;
}

// 翻译普通错误文本，保留 HTTP 状态码前缀。
function translateErrorMessage(message: string): string {
  const match = message.match(/^(\d{3}):\s*(.*)$/);
  if (!match) return translateApiDetail(message);
  return `${match[1]}: ${translateApiDetail(match[2])}`;
}

// 把未知异常转成用户提示。
function formatUserError(error: unknown): string {
  return error instanceof Error ? translateErrorMessage(error.message) : translateApiDetail(String(error));
}

// 翻译 Agent 任务返回中的常见英文信息。
function translateTaskText(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) return "";
  const translated = translateApiDetail(trimmed);
  if (translated !== trimmed) return translated;
  if (trimmed.startsWith("command failed:")) {
    return `节点命令执行失败：${trimmed.replace(/^command failed:\s*/, "")}`;
  }
  if (trimmed.startsWith("command timed out after")) {
    return "节点命令执行超时，请检查节点负载、网络或相关服务状态。";
  }
  if (trimmed.includes("BIRD resource changed on node")) {
    return "保存前节点上的配置文件已被其他人修改，请重新读取配置树后再合并修改。";
  }
  if (trimmed.includes("BIRD resource does not exist")) {
    return "保存前节点上的配置文件已被删除或移动，请重新读取配置树。";
  }
  if (trimmed.includes("duplicate BIRD resource")) {
    return "同一个配置文件被重复提交，请刷新后再试。";
  }
  return trimmed;
}

// 从任务结果中提取适合给用户看的错误说明。
function collectTaskMessages(value: unknown, depth = 0): string[] {
  if (depth > 3 || value == null) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectTaskMessages(item, depth + 1));
  }
  if (!isRecord(value)) return [];
  const result: string[] = [];
  for (const key of ["error", "message", "reason", "stderr", "stdout"]) {
    const text = value[key];
    if (typeof text === "string" && text.trim()) {
      result.push(text.trim());
    }
  }
  for (const key of ["check", "reload", "up", "down", "stop", "start", "apply", "delete_config", "health", "runtime"]) {
    if (key in value) {
      result.push(...collectTaskMessages(value[key], depth + 1));
    }
  }
  return result;
}

// 限制节点输出长度，避免弹窗变成日志转储。
function clampTaskText(text: string): string {
  return text.length > 900 ? `${text.slice(0, 900)}\n...（内容较长，已截断）` : text;
}

// 将 Agent 任务结果整理成可读提示。
function formatTaskResultForUser(result: Record<string, unknown> | null | undefined, fallback = "任务执行失败"): string {
  if (!result || Object.keys(result).length === 0) return fallback;
  const details: string[] = [];
  if (result.status === "cancelled") {
    details.push("任务已取消。");
  }
  if (result.valid === false) {
    details.push("配置校验未通过，节点没有应用这次修改。");
  }
  if (result.applied === false && result.restored === true) {
    details.push("写入失败后已恢复原配置。");
  }
  const messages = uniqueList(
    collectTaskMessages(result)
      .map(translateTaskText)
      .map(clampTaskText)
      .filter(Boolean),
  ).slice(0, 6);
  return uniqueList([fallback, ...details, ...messages]).join("\n\n");
}

// 整理插件任务失败结果，优先展示用户能处理的原因。
function formatPluginTaskError(task: AgentTaskStatus, fallback = "插件任务执行失败"): string {
  const result = task.result || {};
  const reload = isRecord(result.reload) ? result.reload : null;
  const messages: string[] = [];
  const error = typeof result.error === "string" ? result.error : "";
  if (error.includes("BIRD resource changed on node")) {
    messages.push("保存前节点上的配置文件已被其他人修改，请重新读取配置树后再合并修改。");
  } else if (error.includes("BIRD resource does not exist")) {
    messages.push("保存前节点上的配置文件已被删除或移动，请重新读取配置树。");
  } else if (error.includes("duplicate BIRD resource")) {
    messages.push("同一个配置文件被重复提交，请刷新后再试。");
  }
  if (reload && Number(reload.returncode) !== 0) {
    messages.push("birdc configure 执行失败，已恢复本次写入的配置文件。");
  }
  return uniqueList([fallback, ...messages, ...formatTaskResultForUser(result, fallback).split("\n\n")]).join("\n\n");
}

// 判断节点是否可在配置面板中选择。
function isNodeSelectable(node: NodeItem): boolean {
  // 只有 Agent 在线的节点才允许进入 WireGuard 下级菜单。
  return node.status === "online";
}

// 将节点能力列表转换成便于判断的集合。
function nodeCapabilities(node: NodeItem | null): Set<string> {
  return new Set(node?.agent_capabilities || []);
}

// 从节点平台信息或旧能力标识中推断服务管理器。
function nodeServiceManager(node: NodeItem | null): string {
  const serviceManager = String(node?.agent_platform?.service_manager || "");
  if (serviceManager) return serviceManager;
  const capabilities = nodeCapabilities(node);
  if (capabilities.has("service:openwrt-uci")) return "openwrt-uci";
  if (capabilities.has("service:systemd")) return "systemd";
  if (capabilities.has("service:openrc")) return "openrc";
  if (capabilities.has("service:direct-wg-quick")) return "direct-wg-quick";
  return "";
}

// 生成节点系统类型的人类可读标签。
function nodeSystemLabel(node: NodeItem | null): string {
  const labels: Record<string, string> = {
    "openwrt-uci": "OpenWrt / UCI",
    systemd: "Linux / systemd",
    openrc: "Linux / OpenRC",
    "direct-wg-quick": "Linux / wg-quick",
  };
  const serviceManager = nodeServiceManager(node);
  return labels[serviceManager] || serviceManager || "未知服务管理器";
}

// 判断节点是否支持扫描 wg-quick 文件导入候选。
function nodeSupportsWgQuickImport(node: NodeItem | null): boolean {
  return nodeCapabilities(node).has("wg_quick_import") && nodeServiceManager(node) !== "openwrt-uci";
}

// 根据节点能力和平台信息生成 mimic 安装状态。
function mimicPluginStatus(node: NodeItem | null): { label: string; detail: string; installable: boolean; installed: boolean; rebootRequired: boolean } {
  const capabilities = nodeCapabilities(node);
  const platform = node?.agent_platform || {};
  const middlewareStatus = String(node?.middleware_install_status || "");
  const rebootRequired = middlewareStatus === "mimic_reboot_required" || platform.mimic_reboot_required === true;
  if (rebootRequired) {
    return {
      label: "需要重启",
      detail: "mimic 已安装，但 DKMS 模块构建在新内核上；重启节点进入新内核后生效。",
      installable: false,
      installed: false,
      rebootRequired: true,
    };
  }
  if (!node || node.status !== "online") {
    return { label: "未知", detail: "节点离线，无法判断 mimic 安装状态。", installable: false, installed: false, rebootRequired: false };
  }
  if (capabilities.has("middleware.mimic")) {
    return { label: "已安装", detail: "Agent 已检测到 mimic，可在受管连接中启用。", installable: false, installed: true, rebootRequired: false };
  }
  if (capabilities.has("middleware.install.mimic")) {
    return { label: "可安装", detail: "将从 hack3ric/mimic 官方 GitHub 最新发布版本下载。", installable: true, installed: false, rebootRequired: false };
  }
  return { label: "不支持", detail: "需要非 OpenWrt、systemd、Linux kernel > 6.1、Debian/Ubuntu 且 Agent 支持安装器。", installable: false, installed: false, rebootRequired: false };
}

// 生成导入扫描不可用时显示的提示。
function importScanUnavailableMessage(node: NodeItem | null, online: boolean): string {
  if (!online) {
    return "Agent 在线并上报能力后显示导入扫描。";
  }
  if (nodeServiceManager(node) === "openwrt-uci") {
    return "OpenWrt/UCI 节点不支持 wg-quick 文件导入。";
  }
  if (!node?.agent_capabilities?.length) {
    return "Agent 上报能力后显示可用的导入方式。";
  }
  return "当前节点未上报 wg-quick 文件导入能力。";
}

// 返回 BIRD 配置文件所在目录。
function birdDirectory(path: string): string {
  const index = path.lastIndexOf("/");
  return index > 0 ? path.slice(0, index) : "/";
}

// 将扁平 BIRD 文件列表组织成树状文件管理结构。
function buildBirdFileTree(files: BirdResource[]): BirdTreeItem[] {
  const root: BirdFileTreeNode = { name: "/", path: "/", directories: new Map(), files: [] };
  for (const file of files) {
    const parts = file.path.split("/").filter(Boolean);
    const fileName = parts.pop() || file.name;
    let current = root;
    let currentPath = "";
    for (const part of parts) {
      currentPath = `${currentPath}/${part}`;
      let child = current.directories.get(part);
      if (!child) {
        child = { name: part, path: currentPath, directories: new Map(), files: [] };
        current.directories.set(part, child);
      }
      current = child;
    }
    current.files.push({ ...file, name: fileName });
  }
  return birdTreeNodeChildren(root);
}

// 递归生成单个 BIRD 目录节点下的子节点。
function birdTreeNodeChildren(node: BirdFileTreeNode): BirdTreeItem[] {
  const directories = Array.from(node.directories.values())
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((directory) => ({
      id: directory.path,
      name: directory.name,
      path: directory.path,
      type: "directory" as const,
      children: birdTreeNodeChildren(directory),
    }));
  const files = [...node.files]
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((file) => ({
      id: file.resource_key,
      name: file.name,
      path: file.path,
      type: "file" as const,
      resource: file,
    }));
  return [...directories, ...files];
}

// 把运行状态转换成界面标签。
function statusLabel(status: string): string {
  // 统一把运行状态转换成界面文案。
  const labels: Record<string, string> = {
    running: "已连接",
    stopped: "已断开",
    starting: "启动中",
    stopping: "断开中",
    unknown: "未知",
  };
  return labels[status] || status;
}

// 把节点在线状态转换成界面标签。
function nodeStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    online: "在线",
    offline: "离线",
    unknown: "未知",
  };
  return labels[status] || status;
}

// 把计划和任务状态转换成界面标签。
function workflowStatusLabel(status: string | null | undefined): string {
  if (!status) return "未知";
  const labels: Record<string, string> = {
    draft: "待确认",
    confirmed: "已确认",
    dispatching: "下发中",
    pending: "等待执行",
    running: "执行中",
    succeeded: "已完成",
    failed: "失败",
    cancelled: "已取消",
    staged: "已暂存",
    restarting: "重启中",
    healthy: "正常",
    rolled_back: "已回滚",
  };
  return labels[status] || status;
}

// 把连接协议转换成界面标签。
function protocolLabel(connection: ConnectionItem): string {
  return connection.protocol_label || (connection.protocol_type === "gre" ? "GRE" : "WireGuard");
}

// 读取连接中指定角色的端点。
function connectionEndpointByRole(connection: ConnectionItem | null, role: "local" | "peer"): ConnectionEndpointItem | null {
  return connection?.endpoints.find((endpoint) => endpoint.role === role) || null;
}

// 读取连接中当前节点对应的端点。
function connectionEndpointForNode(connection: ConnectionItem | null, nodeId: number | null): ConnectionEndpointItem | null {
  if (!connection || !nodeId) return null;
  return connection.endpoints.find((endpoint) => endpoint.node_id === nodeId) || null;
}

// 读取连接中当前节点的对端端点。
function connectionPeerEndpointForNode(connection: ConnectionItem | null, nodeId: number | null): ConnectionEndpointItem | null {
  if (!connection || !nodeId) return null;
  return connection.endpoints.find((endpoint) => endpoint.node_id !== nodeId) || null;
}

// 判断节点 Agent 是否支持 GRE 任务。
function nodeSupportsGre(node: NodeItem | null): boolean {
  return Boolean(node && isNodeSelectable(node) && (node.agent_capabilities || []).includes("gre"));
}

// 生成通用连接 API 路径片段，避免连接引用中的冒号影响 URL。
function encodedConnectionRef(connectionRef: string): string {
  return encodeURIComponent(connectionRef);
}

// 读取 GRE 端点协议配置中的字符串字段。
function greProtocolString(endpoint: ConnectionEndpointItem | null, key: string): string {
  const value = endpoint?.protocol_config?.[key];
  return typeof value === "string" ? value : "";
}

// 读取 GRE 端点协议配置中的布尔字段。
function greProtocolBoolean(endpoint: ConnectionEndpointItem | null, key: string, fallback: boolean): boolean {
  const value = endpoint?.protocol_config?.[key];
  return typeof value === "boolean" ? value : fallback;
}

// 读取 GRE 端点协议配置中的可选数字字段。
function greProtocolNumber(endpoint: ConnectionEndpointItem | null, key: string): string {
  const value = endpoint?.protocol_config?.[key];
  return typeof value === "number" ? String(value) : "";
}

// 把端口台账来源转换成界面标签。
function portSourceLabel(source: string | null | undefined): string {
  if (!source) return "手动登记";
  if (source === "manual") return "手动登记";
  if (source === "scan") return "扫描发现";
  if (source === "socket") return "系统监听";
  if (source.startsWith("wg:")) return `WireGuard：${source.slice(3)}`;
  if (source.startsWith("uci:")) return "OpenWrt 配置";
  if (source.startsWith("/")) return "配置文件";
  return source;
}

// 把部署计划标题转换成中文展示。
function formatPlanTitle(title: string): string {
  const applyMatch = title.match(/^Apply WireGuard interface (.+)$/);
  if (applyMatch) return `部署 WireGuard 配置 ${applyMatch[1]}`;
  const takeOverMatch = title.match(/^Take over WireGuard interface (.+)$/);
  if (takeOverMatch) return `接管 WireGuard 配置 ${takeOverMatch[1]}`;
  return title;
}

// 把部署计划摘要转换成中文展示。
function formatPlanSummary(summary: string): string {
  const deployMatch = summary.match(/^Deploy WireGuard config for node (\d+) interface (.+)$/);
  if (deployMatch) return `向节点 ${deployMatch[1]} 下发 ${deployMatch[2]} 的 WireGuard 配置`;
  const useExistingMatch = summary.match(/^Use existing wg-quick config for node (\d+) interface (.+)$/);
  if (useExistingMatch) return `使用节点 ${useExistingMatch[1]} 上现有的 ${useExistingMatch[2]} wg-quick 配置作为接管结果`;
  const replaceMatch = summary.match(/^Back up and replace imported config for node (\d+) interface (.+)$/);
  if (replaceMatch) return `备份并替换节点 ${replaceMatch[1]} 上的导入配置 ${replaceMatch[2]}`;
  return summary;
}

// 根据链路监测状态选择视觉状态。
function monitorTone(status: string | undefined) {
  if (status === "healthy") return "healthy";
  if (status === "warning") return "warning";
  if (status === "critical") return "critical";
  return "unknown";
}

// 格式化延迟数值。
function formatLatency(value: number | null | undefined) {
  return typeof value === "number" ? `${Math.round(value)}ms` : "--";
}

// 格式化丢包率数值。
function formatLoss(value: number | null | undefined) {
  return typeof value === "number" ? `${(value * 100).toFixed(value > 0.01 ? 1 : 0)}%` : "--";
}

// 计算单条拓扑链路的健康状态。
function topologySingleEdgeTone(edge: TopologyEdge): "healthy" | "warning" | "critical" | "unknown" {
  if (edge.local_status !== "running" || edge.peer_status !== "running") return "critical";
  const statuses = [edge.local_monitor?.status, edge.peer_monitor?.status].filter(Boolean);
  if (statuses.includes("critical")) return "critical";
  if (statuses.includes("warning")) return "warning";
  if (statuses.includes("healthy")) return "healthy";
  return "unknown";
}

// 汇总多条合并链路后的拓扑健康状态。
function topologyEdgeTone(edge: TopologyDisplayEdge): "healthy" | "warning" | "critical" | "unknown" {
  const tones = edge.links.map(topologySingleEdgeTone);
  if (tones.includes("critical")) return "critical";
  if (tones.includes("warning")) return "warning";
  if (tones.includes("unknown")) return "unknown";
  return "healthy";
}

// 计算数值列表平均值，空列表返回 null。
function average(values: number[]) {
  if (values.length === 0) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

// 生成拓扑边标签中的延迟和丢包摘要；拓扑只关心节点间连接关系，不突出具体协议。
function topologyEdgeSummary(edge: TopologyDisplayEdge) {
  const summaries = edge.links.flatMap((link) => [link.local_monitor, link.peer_monitor]).filter(Boolean) as LinkMonitorSummary[];
  const prefix = edge.link_count > 1 ? `${edge.link_count}条链路 · ` : "";
  if (summaries.length === 0) return `${prefix}-- / --`;
  const latencies = summaries
    .map((summary) => summary.last_latency_ms)
    .filter((value): value is number => typeof value === "number");
  const losses = summaries.map((summary) => summary.packet_loss);
  return `${prefix}${formatLatency(average(latencies))} / ${formatLoss(average(losses))}`;
}

// 选择拓扑节点展示的首选地址。
function topologyNodeEndpoint(node: TopologyNode) {
  return node.topology_endpoint || node.endpoint_ips[0] || node.hostname || "未配置地址";
}

type TopologyHandleId = "top" | "right" | "bottom" | "left";

type TopologyNodePosition = {
  x: number;
  y: number;
};

const TOPOLOGY_NODE_WIDTH = 178;
const TOPOLOGY_NODE_HEIGHT = 78;

const topologyHandlePositions: Record<TopologyHandleId, Position> = {
  top: Position.Top,
  right: Position.Right,
  bottom: Position.Bottom,
  left: Position.Left,
};

// 按两个节点的相对方位选择最短方向的连线端点。
function topologyHandlePair(source: TopologyNodePosition | undefined, target: TopologyNodePosition | undefined) {
  if (!source || !target) {
    return { sourceHandle: "right" as TopologyHandleId, targetHandle: "left" as TopologyHandleId };
  }
  const sourceCenter = {
    x: source.x + TOPOLOGY_NODE_WIDTH / 2,
    y: source.y + TOPOLOGY_NODE_HEIGHT / 2,
  };
  const targetCenter = {
    x: target.x + TOPOLOGY_NODE_WIDTH / 2,
    y: target.y + TOPOLOGY_NODE_HEIGHT / 2,
  };
  const dx = targetCenter.x - sourceCenter.x;
  const dy = targetCenter.y - sourceCenter.y;
  if (Math.abs(dx) >= Math.abs(dy)) {
    return dx >= 0
      ? { sourceHandle: "right" as TopologyHandleId, targetHandle: "left" as TopologyHandleId }
      : { sourceHandle: "left" as TopologyHandleId, targetHandle: "right" as TopologyHandleId };
  }
  return dy >= 0
    ? { sourceHandle: "bottom" as TopologyHandleId, targetHandle: "top" as TopologyHandleId }
    : { sourceHandle: "top" as TopologyHandleId, targetHandle: "bottom" as TopologyHandleId };
}

// 渲染拓扑节点四边的 React Flow 连接手柄。
function TopologyHandles() {
  return (
    <>
      {(["top", "right", "bottom", "left"] as TopologyHandleId[]).map((id) => (
        <React.Fragment key={id}>
          <Handle id={id} type="source" position={topologyHandlePositions[id]} isConnectable={false} />
          <Handle id={id} type="target" position={topologyHandlePositions[id]} isConnectable={false} />
        </React.Fragment>
      ))}
    </>
  );
}

// 返回节点地域标签，未填写时使用默认提示。
function nodeRegionLabel(node: Pick<NodeItem, "region">) {
  return node.region?.trim() || "未设置地域";
}

// 从 CIDR 列表中提取第一个可作为探测目标的 IP。
function firstIpFromCidrs(values: string[]) {
  for (const value of values) {
    const text = value.split("/")[0]?.trim();
    if (text && isProbablyIpAddress(text)) return text;
  }
  return "";
}

// 根据接口和对端配置推断推荐链路监测目标。
function suggestedMonitorTarget(config: ConfigItem, peer: PeerItem | null) {
  return firstIpFromCidrs(peer?.allowed_ips || []) || firstIpFromCidrs(config.primary_peer_allowed_ips || []) || "";
}

// 根据通用连接端点推断链路监测目标，优先使用对端隧道 IP。
function suggestedEndpointMonitorTarget(endpoint: ConnectionEndpointItem | null, peerEndpoint: ConnectionEndpointItem | null) {
  return firstIpFromCidrs(peerEndpoint?.tunnel_ips || []) || firstIpFromCidrs(endpoint?.routes || []) || "";
}

// 校验可选端口范围。
function isValidPort(value: number | null): boolean {
  // UDP 端口范围校验，空值表示不填写。
  return value === null || (Number.isInteger(value) && value >= 1 && value <= 65535);
}

// 校验必填端口范围。
function isRequiredPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

// 校验可选 MTU 范围。
function isValidMtu(value: number | null): boolean {
  return value === null || (Number.isInteger(value) && value >= 576 && value <= 9000);
}

// 用轻量规则判断输入是否像 IP 地址。
function isProbablyIpAddress(value: string): boolean {
  const cleaned = value.trim();
  if (!cleaned) return false;
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  return ipv4.test(cleaned) || isValidIpv6Address(cleaned);
}

// 使用 URL 解析器校验 IPv6 字面量。
function isValidIpv6Address(value: string): boolean {
  const cleaned = value.trim();
  if (!cleaned.includes(":") || cleaned.includes("[") || cleaned.includes("]")) return false;
  try {
    new URL(`http://[${cleaned}]/`);
    return true;
  } catch {
    return false;
  }
}

// 校验 CIDR 列表中的地址和前缀长度。
function isValidCidrs(values: string[]): boolean {
  return values.every((value) => {
    const [address, prefixText, ...rest] = value.trim().split("/");
    if (!address || !prefixText || rest.length) return false;
    if (!/^\d+$/.test(prefixText)) return false;
    const prefix = Number(prefixText);
    if (!isProbablyIpAddress(address)) return false;
    return address.includes(":") ? prefix >= 0 && prefix <= 128 : prefix >= 0 && prefix <= 32;
  });
}

// 校验 IPv4 字面量地址。
function isValidIpv4Address(value: string): boolean {
  const cleaned = value.trim();
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  return ipv4.test(cleaned);
}

// 校验 GRE 要求的 IPv4 CIDR 列表。
function isValidIpv4Cidrs(values: string[]): boolean {
  return values.every((value) => {
    const [address, prefixText, ...rest] = value.trim().split("/");
    if (!address || !prefixText || rest.length) return false;
    if (!/^\d+$/.test(prefixText)) return false;
    const prefix = Number(prefixText);
    return isValidIpv4Address(address) && prefix >= 0 && prefix <= 32;
  });
}

// 校验 GRE Key 的可选 32 位无符号整数范围。
function isValidGreKey(value: string): boolean {
  const cleaned = value.trim();
  if (!cleaned) return true;
  if (!/^\d+$/.test(cleaned)) return false;
  const number = Number(cleaned);
  return Number.isSafeInteger(number) && number >= 0 && number <= 4294967295;
}

// 渲染链路监测摘要按钮。
function MonitorSummaryButton({
  summary,
  onClick,
}: {
  summary: LinkMonitorSummary | null;
  onClick: (event: React.MouseEvent<HTMLSpanElement>) => void;
}) {
  const tone = monitorTone(summary?.status);
  return (
    <span
      className={`monitorSummary ${tone}`}
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onClick(event as unknown as React.MouseEvent<HTMLSpanElement>);
        }
      }}
      title="查看链路延迟统计"
    >
      {summary ? (
        <>
          <span><strong>{formatLatency(summary.last_latency_ms)}</strong><small>延迟</small></span>
          <span><strong>{formatLoss(summary.packet_loss)}</strong><small>丢包</small></span>
          <span><strong>{summary.stability_score}</strong><small>稳定</small></span>
        </>
      ) : (
        <span><strong>未监测</strong><small>点击配置</small></span>
      )}
    </span>
  );
}

// 粗略校验 WireGuard base64 key 的格式。
function isProbablyWireGuardKey(value: FormDataEntryValue | null): boolean {
  // WireGuard key 是 base64 字符串，常见长度 44；留空由调用方决定是否允许。
  if (!value) return true;
  return /^[A-Za-z0-9+/]{43}=$/.test(String(value));
}

// 汇总节点可作为 Endpoint 的地址候选。
function nodeEndpointOptions(node: NodeItem): string[] {
  // 新节点使用 endpoint_ips；旧库数据用历史字段兜底展示。
  return Array.from(new Set([
    ...(node.endpoint_ips || []),
    node.public_ip,
    node.management_ip,
    node.hostname,
  ].filter(Boolean) as string[]));
}

type EndpointOption = {
  value: string;
  label: string;
  source: "imported" | "node" | "current";
};

const endpointSelectStyles: StylesConfig<EndpointOption, false> = {
  menuPortal: (base) => ({ ...base, zIndex: 80 }),
};

// 去除重复 Endpoint 选项，保留优先级最高的来源。
function uniqueEndpointOptions(options: EndpointOption[]): EndpointOption[] {
  // 同一个 host 只保留第一次出现的来源，确保原始导入 Endpoint 优先展示。
  const seen = new Set<string>();
  return options.filter((option) => {
    const value = option.value.trim();
    if (!value || seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

// 从导入地址、节点地址和当前值构造 Endpoint 下拉选项。
function endpointOptionsFrom(
  importedHost: string | null | undefined,
  nodeHosts: string[],
  currentHost?: string | null,
): EndpointOption[] {
  return uniqueEndpointOptions([
    ...(importedHost ? [{ value: importedHost, label: importedHost, source: "imported" as const }] : []),
    ...(currentHost ? [{ value: currentHost, label: currentHost, source: "current" as const }] : []),
    ...nodeHosts.map((host) => ({ value: host, label: host, source: "node" as const })),
  ]);
}

// 从节点地址中提取可作为 GRE 外层地址的 IPv4 选项。
function greOuterIpOptionsFromNode(node: NodeItem | null, currentHost?: string | null): EndpointOption[] {
  const nodeHosts = node ? nodeEndpointOptions(node).filter(isValidIpv4Address) : [];
  const current = currentHost && isValidIpv4Address(currentHost) ? currentHost : null;
  return endpointOptionsFrom(null, nodeHosts, current);
}

// 返回 Endpoint 选项来源标签。
function endpointSourceLabel(source: EndpointOption["source"]) {
  if (source === "imported") return "原始入口";
  if (source === "current") return "当前配置";
  return "节点地址";
}

// 生成用户在节点上安装 Agent 的 shell 命令。
function buildAgentCommand(node: NodeItem, controllerUrl: string = DEFAULT_CONTROLLER_URL): string {
  if (!node.agent_token_value) return "";
  return [
    "curl -fsSL https://get.pmman.tech/sh/link42-agent.sh",
    "|",
    "sudo env",
    `LINK42_SERVER_URL=${shellArg(controllerUrl)}`,
    `LINK42_NODE_ID=${shellArg(String(node.id))}`,
    `LINK42_AGENT_TOKEN=${shellArg(node.agent_token_value)}`,
    "sh",
  ].join(" ");
}

// 为 shell 命令参数做单引号转义。
function shellArg(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

// 渲染统一表单字段，自动展示必填标记。
function Field({
  label,
  hint,
  wide = false,
  requiredMark,
  children,
}: {
  label: string;
  hint?: string;
  wide?: boolean;
  requiredMark?: boolean;
  children: React.ReactNode;
}) {
  const required = requiredMark ?? hasRequiredControl(children);
  return (
    <label className={wide ? "field wideField" : "field"}>
      <span className="fieldLabel">
        {label}
        {required && <span className="requiredMark" aria-label="必填">*</span>}
      </span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

// 递归判断字段内是否存在启用状态的 required 控件。
function hasRequiredControl(children: React.ReactNode): boolean {
  let required = false;
  React.Children.forEach(children, (child) => {
    if (required || !React.isValidElement(child)) return;
    const props = child.props as {
      required?: boolean;
      disabled?: boolean;
      children?: React.ReactNode;
    };
    if (props.required && !props.disabled) {
      required = true;
      return;
    }
    if (props.children && hasRequiredControl(props.children)) {
      required = true;
    }
  });
  return required;
}

// 渲染带标题和说明的表单区块。
function FormSection({
  title,
  hint,
  children,
  tone = "default",
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
  tone?: "default" | "middleware";
}) {
  return (
    <section className={`formSection wideField ${tone === "middleware" ? "middlewareSection" : ""}`}>
      <div className="formSectionHeader">
        <h3>{title}</h3>
        {hint && <p>{hint}</p>}
      </div>
      <div className="formSectionGrid">
        {children}
      </div>
    </section>
  );
}

// 渲染可增删的入口地址列表输入。
function EndpointListInput({
  value,
  onChange,
  placeholder,
  onDuplicate,
}: {
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  onDuplicate?: (endpoint: string) => void;
}) {
  const [draft, setDraft] = useState("");

  // 将草稿输入追加到入口地址列表。
  function addDraft() {
    const additions = splitList(draft);
    if (additions.length === 0) return;
    const existing = new Set(value.map((item) => item.trim()).filter(Boolean));
    const next = [...value];
    let duplicate = "";
    for (const endpoint of additions) {
      if (existing.has(endpoint)) {
        duplicate ||= endpoint;
        continue;
      }
      existing.add(endpoint);
      next.push(endpoint);
    }
    if (duplicate) {
      onDuplicate?.(duplicate);
    }
    if (next.length !== value.length) {
      onChange(next);
      setDraft("");
    }
  }

  // 按索引移除入口地址。
  function removeEndpoint(index: number) {
    onChange(value.filter((_, itemIndex) => itemIndex !== index));
  }

  // 更新指定索引处的入口地址。
  function updateEndpoint(index: number, endpoint: string) {
    onChange(value.map((item, itemIndex) => itemIndex === index ? endpoint : item));
  }

  return (
    <div className="endpointListInput">
      <div className="endpointListRow endpointListDraft">
        <input
          name="endpoint_ip_draft"
          value={draft}
          onChange={(event) => setDraft(event.currentTarget.value)}
          onKeyDown={(event) => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            addDraft();
          }}
          placeholder={placeholder}
          aria-label="新增入口地址"
        />
        <button type="button" className="endpointListButton endpointListAddButton" onClick={addDraft} disabled={!draft.trim()} title="添加入口地址">
          <Plus size={16} />
        </button>
      </div>
      <div className="endpointListRows">
        {value.length === 0 ? (
          <div className="endpointListEmpty">尚未添加入口地址</div>
        ) : value.map((endpoint, index) => (
          <div className="endpointListRow" key={`${endpoint}-${index}`}>
            <input
              value={endpoint}
              onChange={(event) => updateEndpoint(index, event.currentTarget.value)}
              placeholder={placeholder}
              aria-label={`入口地址 ${index + 1}`}
            />
            <button type="button" className="endpointListButton endpointListRemoveButton" onClick={() => removeEndpoint(index)} title="移除入口地址">
              <X size={15} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// 渲染可从候选地址选择也可手动输入的 Endpoint 控件。
function EndpointSelect({
  name,
  defaultValue,
  placeholder,
  options,
  disabled = false,
  locked = false,
}: {
  name: string;
  defaultValue: string;
  placeholder: string;
  options: EndpointOption[];
  disabled?: boolean;
  locked?: boolean;
}) {
  const [value, setValue] = useState(defaultValue);
  const [inputValue, setInputValue] = useState("");
  const selectedOption = useMemo<EndpointOption | null>(() => {
    if (!value) return null;
    return options.find((option) => option.value === value) || {
      value,
      label: "手动输入",
      source: "current",
    };
  }, [options, value]);

  useEffect(() => {
    setValue(defaultValue);
    setInputValue("");
  }, [defaultValue]);

  // 处理下拉选项变更。
  function handleChange(option: SingleValue<EndpointOption>) {
    setValue(option?.value || "");
    setInputValue("");
  }

  // 处理用户创建新的 Endpoint 值。
  function handleCreate(inputValue: string) {
    setValue(inputValue.trim());
    setInputValue("");
  }

  // 失焦时提交仍停留在输入框里的手动值。
  function commitInputValue() {
    const cleaned = inputValue.trim();
    if (cleaned) {
      setValue(cleaned);
      setInputValue("");
    }
  }

  return (
    <div className="endpointSelect">
      <CreatableSelect<EndpointOption, false>
        classNamePrefix="endpointSelect"
        value={selectedOption}
        options={options}
        isDisabled={disabled || locked}
        isClearable={!locked}
        inputValue={inputValue}
        placeholder={placeholder}
        noOptionsMessage={() => "没有可选地址，可直接输入"}
        formatCreateLabel={(inputValue) => `使用 "${inputValue}"`}
        onChange={handleChange}
        onCreateOption={handleCreate}
        onInputChange={(newValue, actionMeta) => {
          if (actionMeta.action === "input-change") {
            setInputValue(newValue);
          }
        }}
        onBlur={commitInputValue}
        menuPortalTarget={document.body}
        styles={endpointSelectStyles}
        formatOptionLabel={(option) => (
          <div className="endpointSelectOption">
            <span>{option.value}</span>
            <small>{endpointSourceLabel(option.source)}</small>
          </div>
        )}
      />
      <input
        type="hidden"
        name={name}
        value={value}
        disabled={disabled}
      />
      {locked && <small>由 udp2raw 接管</small>}
    </div>
  );
}

// 渲染 mimic 中间层配置字段。
function MimicFields({
  enabled,
  defaults,
  localNode,
  peerNode,
  disabled,
  onEnabledChange,
}: {
  enabled: boolean;
  defaults?: Partial<MimicMiddleware> | null;
  localNode?: NodeItem | null;
  peerNode?: NodeItem | null;
  disabled?: boolean;
  onEnabledChange: (value: boolean) => void;
}) {
  const localInterfaces = interfaceOptions(localNode);
  const peerInterfaces = interfaceOptions(peerNode);
  // 切换 mimic 启用状态，并在启用时给 MTU 一个更保守的默认值。
  function handleEnabledChange(event: React.ChangeEvent<HTMLInputElement>) {
    const nextEnabled = event.currentTarget.checked;
    onEnabledChange(nextEnabled);
    if (nextEnabled) {
      const mtuInput = event.currentTarget.form?.elements.namedItem("mtu");
      if (mtuInput instanceof HTMLInputElement) {
        mtuInput.value = "1408";
      }
    }
  }
  return (
    <FormSection
      title="mimic 透明中间层"
      hint="mimic 在 Linux 网卡层透明处理 WireGuard UDP 流量，不修改入口地址；需要非 OpenWrt、kernel > 6.1 且节点已安装 mimic。"
      tone="middleware"
    >
      <label className="checkField wideField">
        <input
          name="mimic_enabled"
          type="checkbox"
          checked={enabled}
          disabled={disabled}
          onChange={handleEnabledChange}
        />
        <input type="hidden" name="mimic_enabled_state" value={enabled ? "on" : ""} disabled={disabled} />
        <span>启用 mimic</span>
      </label>
      {enabled && (
        <>
          <Field label="本端出口网卡" hint="选择承载本端 WireGuard 入口流量的物理或上联网卡。">
            <select name="mimic_local_bind_interface" defaultValue={defaults?.local_bind_interface || localInterfaces[0] || ""} required disabled={disabled}>
              <option value="">请选择网卡</option>
              {localInterfaces.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </Field>
          <Field label="对端出口网卡" hint="选择承载对端 WireGuard 入口流量的物理或上联网卡。">
            <select name="mimic_peer_bind_interface" defaultValue={defaults?.peer_bind_interface || peerInterfaces[0] || ""} required disabled={disabled}>
              <option value="">请选择网卡</option>
              {peerInterfaces.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </Field>
          <Field label="XDP 模式" hint="默认 skb 兼容性更稳；确认网卡 native XDP 稳定后可切 native。">
            <select name="mimic_xdp_mode" defaultValue={defaults?.xdp_mode || "skb"} disabled={disabled}>
              <option value="skb">skb</option>
              <option value="auto">auto</option>
              <option value="native">native</option>
            </select>
          </Field>
          <Field label="链路类型" hint="大多数以太网环境保持 eth。">
            <input name="mimic_link_type" defaultValue={defaults?.link_type || "eth"} disabled={disabled} />
          </Field>
          <Field label="握手间隔" hint="对应 mimic 的 handshake interval；留空使用 mimic 默认值。">
            <input name="mimic_handshake_interval" defaultValue={defaults?.handshake_interval || ""} inputMode="numeric" disabled={disabled} />
          </Field>
          <Field label="保活时间" hint="对应 mimic 的 keepalive time；留空使用 mimic 默认值。">
            <input name="mimic_keepalive_interval" defaultValue={defaults?.keepalive_interval || ""} inputMode="numeric" disabled={disabled} />
          </Field>
          <Field label="填充长度" hint="范围 0-16；留空不额外指定。">
            <input name="mimic_padding" defaultValue={defaults?.padding || ""} inputMode="numeric" disabled={disabled} />
          </Field>
          <div className="formNotice wideField">
            mimic 不会把入口地址改为 127.0.0.1；请保持上方双方入口地址为真实可达地址，并确认防火墙放行对应 WireGuard 端口。
          </div>
        </>
      )}
    </FormSection>
  );
}

// 从节点平台信息中读取可绑定的普通网卡列表。
function interfaceOptions(node?: NodeItem | null): string[] {
  const platform = node?.agent_platform || {};
  const values = platform.network_interfaces;
  return Array.isArray(values) ? values.map((item) => String(item)).filter(Boolean) : [];
}

// 渲染 WireGuard 路由模式选择器。
function RouteModeSelect({
  defaultValue = "off",
  disabled,
}: {
  defaultValue?: string | null;
  disabled?: boolean;
}) {
  return (
    <select name="table_name" defaultValue={defaultValue ?? "off"} disabled={disabled}>
      <option value="">自动生成路由（默认）</option>
      <option value="off">不自动生成路由（Table=off）</option>
    </select>
  );
}

// 渲染 udp2raw 中间层配置字段。
function Udp2RawFields({
  enabled,
  serverSide,
  localListenPort,
  peerListenPort,
  defaults,
  disabled,
  onEnabledChange,
  onServerSideChange,
}: {
  enabled: boolean;
  serverSide: "local" | "peer";
  localListenPort?: number | null;
  peerListenPort?: number | null;
  defaults?: Partial<Udp2RawMiddleware> | null;
  disabled?: boolean;
  onEnabledChange: (value: boolean) => void;
  onServerSideChange: (value: "local" | "peer") => void;
}) {
  const serverWireGuardListenPort = serverSide === "local" ? localListenPort : peerListenPort;
  const forwardPortDefault = defaults?.server_forward_port || serverWireGuardListenPort || "";
  // 切换 udp2raw 启用状态，并在启用时给 MTU 一个更保守的默认值。
  function handleEnabledChange(event: React.ChangeEvent<HTMLInputElement>) {
    const nextEnabled = event.currentTarget.checked;
    onEnabledChange(nextEnabled);
    if (nextEnabled) {
      const form = event.currentTarget.form;
      const mtuInput = form?.elements.namedItem("mtu");
      if (mtuInput instanceof HTMLInputElement) {
        mtuInput.value = "1300";
      }
    }
  }

  return (
    <FormSection
      title="udp2raw 连接中间层"
      hint="客户端监听本机 UDP 并封装发往服务端；服务端收到后解包，再转发到本机 WireGuard UDP 端口。"
      tone="middleware"
    >
      <label className="checkField wideField">
        <input
          name="udp2raw_enabled"
          type="checkbox"
          checked={enabled}
          disabled={disabled}
          onChange={handleEnabledChange}
        />
        <input type="hidden" name="udp2raw_enabled_state" value={enabled ? "on" : ""} disabled={disabled} />
        <span>启用 udp2raw</span>
      </label>
      {enabled && (
        <>
          <Field label="服务端所在节点" hint="服务端需要有 WireGuard ListenPort；客户端侧 WireGuard 可不写 ListenPort。">
            <select
              name="udp2raw_server_side"
              value={serverSide}
              disabled={disabled}
              onChange={(event) => onServerSideChange(event.currentTarget.value as "local" | "peer")}
            >
              <option value="peer">对端运行 udp2raw 服务端，本端运行客户端</option>
              <option value="local">本端运行 udp2raw 服务端，对端运行客户端</option>
            </select>
          </Field>
          <Field label="客户端连接服务端 IP" hint="写入客户端的 -r；必须是 IP，不能填域名。">
            <input name="udp2raw_server_connect_host" defaultValue={defaults?.server_connect_host || ""} placeholder="203.0.113.20" disabled={disabled} />
          </Field>
          <Field label="服务端监听地址" hint="服务端的 -l 地址；通常 0.0.0.0，必须是 IP。">
            <input name="udp2raw_server_listen_host" defaultValue={defaults?.server_listen_host || "0.0.0.0"} disabled={disabled} />
          </Field>
          <Field label="服务端监听端口" hint="客户端连接的 raw TCP/faketcp/icmp 端口。">
            <input name="udp2raw_server_listen_port" defaultValue={defaults?.server_listen_port || ""} inputMode="numeric" required={enabled} disabled={disabled} />
          </Field>
          <Field label="服务端转发到 IP" hint="服务端解包后把 UDP 发往这里；通常 127.0.0.1。">
            <input name="udp2raw_server_forward_host" defaultValue={defaults?.server_forward_host || "127.0.0.1"} disabled={disabled} />
          </Field>
          <Field label="服务端转发到端口" hint="可选；留空则使用服务端侧 WireGuard ListenPort。">
            <input
              key={`udp2raw-forward-port-${serverSide}-${forwardPortDefault}`}
              name="udp2raw_server_forward_port"
              defaultValue={forwardPortDefault}
              inputMode="numeric"
              disabled={disabled}
            />
          </Field>
          <Field label="客户端本地监听地址" hint="WireGuard 入口会被接管到这个本地 UDP 地址。">
            <input name="udp2raw_client_listen_host" defaultValue={defaults?.client_listen_host || "127.0.0.1"} disabled={disabled} />
          </Field>
          <Field label="客户端本地监听端口" hint="填写本节点 WireGuard 连接对端接口时要使用的本地 udp2raw UDP 端口；本端对端入口会被接管到 127.0.0.1:此端口。">
            <input name="udp2raw_client_listen_port" defaultValue={defaults?.client_listen_port || ""} inputMode="numeric" required={enabled} disabled={disabled} />
          </Field>
          <Field label="传输模式" hint="faketcp 伪装性更强；udp 更直接；icmp 仅在明确需要时使用。">
            <select name="udp2raw_raw_mode" defaultValue={defaults?.raw_mode || "faketcp"} disabled={disabled}>
              <option value="faketcp">faketcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
            </select>
          </Field>
          <Field label="加密模式" hint="xor 开销低；none 不加密；aes128cbc 兼容 udp2raw 原生模式。">
            <select name="udp2raw_cipher_mode" defaultValue={defaults?.cipher_mode || "xor"} disabled={disabled}>
              <option value="xor">xor</option>
              <option value="aes128cbc">aes128cbc</option>
              <option value="none">none</option>
            </select>
          </Field>
          <Field label="共享密码" hint="两端必须一致；留空时主控自动生成并保存。">
            <input name="udp2raw_password" defaultValue={defaults?.password || ""} disabled={disabled} />
          </Field>
          <label className="checkField wideField">
            <input name="udp2raw_auto_rule" type="checkbox" defaultChecked={defaults?.auto_rule ?? true} disabled={disabled} />
            <span>启用 udp2raw 自动规则（-a）</span>
          </label>
          <div className="formNotice wideField">
            {serverSide === "peer"
              ? "本端入口会指向本端 udp2raw 客户端；对端服务端解包后转发到对端 WireGuard。OpenWrt 作为服务端时，入口防火墙区域仍需手动放行服务端监听端口。"
              : "对端入口会指向对端 udp2raw 客户端；本端服务端解包后转发到本端 WireGuard。OpenWrt 作为服务端时，入口防火墙区域仍需手动放行服务端监听端口。"}
          </div>
        </>
      )}
    </FormSection>
  );
}

// 从表单中读取并组装 udp2raw 配置。
function readUdp2RawForm(
  form: FormData,
  localListenPort?: number | null,
  peerListenPort?: number | null,
): Record<string, unknown> | null {
  const enabled = form.get("udp2raw_enabled") === "on" || form.get("udp2raw_enabled_state") === "on";
  if (!enabled) return null;
  const serverSide = String(form.get("udp2raw_server_side") || "peer");
  const serverForwardPort =
    optionalInt(form.get("udp2raw_server_forward_port"), "udp2raw 服务端转发目的端口") ??
    (serverSide === "local" ? localListenPort ?? null : peerListenPort ?? null);
  return {
    enabled: true,
    server_side: serverSide,
    server_listen_host: String(form.get("udp2raw_server_listen_host") || "0.0.0.0").trim(),
    server_connect_host: String(form.get("udp2raw_server_connect_host") || "").trim() || null,
    server_listen_port: optionalInt(form.get("udp2raw_server_listen_port"), "udp2raw 服务端监听端口"),
    server_forward_host: String(form.get("udp2raw_server_forward_host") || "127.0.0.1").trim(),
    server_forward_port: serverForwardPort,
    client_listen_host: String(form.get("udp2raw_client_listen_host") || "127.0.0.1").trim(),
    client_listen_port: optionalInt(form.get("udp2raw_client_listen_port"), "udp2raw 客户端本地监听端口"),
    raw_mode: String(form.get("udp2raw_raw_mode") || "faketcp"),
    cipher_mode: String(form.get("udp2raw_cipher_mode") || "xor"),
    password: String(form.get("udp2raw_password") || "").trim() || null,
    auto_rule: form.get("udp2raw_auto_rule") === "on",
  };
}

// 从表单中读取并组装 mimic 配置。
function readMimicForm(form: FormData): Record<string, unknown> | null {
  const enabled = form.get("mimic_enabled") === "on" || form.get("mimic_enabled_state") === "on";
  if (!enabled) return null;
  return {
    enabled: true,
    local_bind_interface: String(form.get("mimic_local_bind_interface") || "").trim(),
    peer_bind_interface: String(form.get("mimic_peer_bind_interface") || "").trim(),
    xdp_mode: String(form.get("mimic_xdp_mode") || "skb"),
    link_type: String(form.get("mimic_link_type") || "eth").trim() || "eth",
    handshake_interval: optionalInt(form.get("mimic_handshake_interval"), "mimic 握手间隔"),
    keepalive_interval: optionalInt(form.get("mimic_keepalive_interval"), "mimic 保活间隔"),
    padding: optionalInt(form.get("mimic_padding"), "mimic 填充长度"),
  };
}

// 校验 mimic 表单和 WireGuard 依赖字段是否满足部署要求。
function validateMimicForm(
  mimic: Record<string, unknown> | null,
  localListenPort: number | null,
  peerListenPort: number | null,
  localEndpointHost: string,
  peerEndpointHost: string,
) {
  if (!mimic) return;
  if (!mimic.local_bind_interface || !mimic.peer_bind_interface) {
    throw new Error("mimic 需要选择双方出口网卡");
  }
  if (!localEndpointHost || !peerEndpointHost) {
    throw new Error("mimic 需要双方入口地址都填写");
  }
  if (!localListenPort || !peerListenPort) {
    throw new Error("mimic 透明匹配需要双方 WireGuard ListenPort 都填写");
  }
  if (!["auto", "native", "skb"].includes(String(mimic.xdp_mode))) {
    throw new Error("mimic XDP 模式必须是 auto、native 或 skb");
  }
  if (mimic.padding !== null && mimic.padding !== undefined) {
    const padding = Number(mimic.padding);
    if (!Number.isInteger(padding) || padding < 0 || padding > 16) {
    throw new Error("mimic 填充长度必须在 0-16 之间");
    }
  }
}

// 校验 udp2raw 表单和 WireGuard 依赖字段是否满足部署要求。
function validateUdp2RawForm(udp2raw: Record<string, unknown> | null, localListenPort: number | null, peerListenPort: number | null) {
  if (!udp2raw) return;
  const serverSide = String(udp2raw.server_side);
  const serverListenHost = String(udp2raw.server_listen_host || "");
  const serverConnectHost = String(udp2raw.server_connect_host || "");
  const serverForwardHost = String(udp2raw.server_forward_host || "");
  const clientListenHost = String(udp2raw.client_listen_host || "");
  const serverListenPort = (udp2raw.server_listen_port as number | null | undefined) ?? null;
  const clientListenPort = (udp2raw.client_listen_port as number | null | undefined) ?? null;
  const serverForwardPort = (udp2raw.server_forward_port as number | null | undefined) ?? null;
  if (
    !isValidPort(serverListenPort) ||
    !isValidPort(clientListenPort)
  ) {
    throw new Error("udp2raw 服务端监听端口和客户端本地 UDP 监听端口必须填写 1-65535 之间的整数");
  }
  if (!isValidPort(serverForwardPort)) {
    throw new Error("udp2raw 服务端转发目的端口必须留空，或填写 1-65535 之间的整数");
  }
  if (!isProbablyIpAddress(serverListenHost) || !isProbablyIpAddress(serverForwardHost) || !isProbablyIpAddress(clientListenHost)) {
    throw new Error("udp2raw 监听地址和转发目的地址必须填写 IP，不能填写域名");
  }
  if (!isProbablyIpAddress(serverConnectHost)) {
    throw new Error("udp2raw 服务端对外地址必须填写 IP，不能填写域名");
  }
  if (serverSide === "local" && !localListenPort) {
    throw new Error("udp2raw 服务端在本端时，本端 WireGuard 监听端口必须填写");
  }
  if (serverSide === "peer" && !peerListenPort) {
    throw new Error("udp2raw 服务端在对端时，对端 WireGuard 监听端口必须填写");
  }
}

// 渲染 Link42 主界面并集中管理页面状态。
function App() {
  // Link42 主界面组件，集中承载节点和连接管理流程。
  // 页面状态保持在顶层，避免在当前单页应用里引入额外状态管理。
  const [authToken, setAuthToken] = useState(() => window.localStorage.getItem(AUTH_TOKEN_KEY) || "");
  const [authChecked, setAuthChecked] = useState(false);
  const [currentUser, setCurrentUser] = useState<string | null>(null);
  const [loginError, setLoginError] = useState("");
  const [theme, setTheme] = useState<"light" | "dark">(() => initialTheme());
  const [controllerUrl, setControllerUrl] = useState(DEFAULT_CONTROLLER_URL);
  const [settingsUsername, setSettingsUsername] = useState("pmman");
  const [siteTitle, setSiteTitle] = useState(DEFAULT_SITE_TITLE);
  const [siteLogoUrl, setSiteLogoUrl] = useState(DEFAULT_SITE_LOGO_URL);
  const [settingsLogoPreviewUrl, setSettingsLogoPreviewUrl] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [topology, setTopology] = useState<TopologyResponse>({ nodes: [], edges: [] });
  const [topologyDraftPositions, setTopologyDraftPositions] = useState<Record<number, { x: number; y: number }>>({});
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  const selectedNodeIdRef = useRef<number | null>(null);
  const [configs, setConfigs] = useState<ConfigItem[]>([]);
  const [selectedConfigId, setSelectedConfigId] = useState<number | null>(null);
  const selectedConfigIdRef = useRef<number | null>(null);
  const [connections, setConnections] = useState<ConnectionItem[]>([]);
  const [selectedConnectionRef, setSelectedConnectionRef] = useState<string | null>(null);
  const selectedConnectionRefRef = useRef<string | null>(null);
  const [peer, setPeer] = useState<PeerItem | null>(null);
  const [managedLink, setManagedLink] = useState<ManagedLink | null>(null);
  const [importCandidates, setImportCandidates] = useState<ImportCandidate[]>([]);
  const [plan, setPlan] = useState<ChangePlan | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [createDialog, setCreateDialog] = useState<"external" | "managed-protocol" | "managed" | null>(null);
  const [managedCreateProtocol, setManagedCreateProtocol] = useState<ManagedCreateProtocol>("wireguard");
  const [nodeCreateOpen, setNodeCreateOpen] = useState(false);
  const [nodeCreateEndpointIps, setNodeCreateEndpointIps] = useState<string[]>([]);
  const [editingNodeId, setEditingNodeId] = useState<number | null>(null);
  const [editingNodeEndpointIps, setEditingNodeEndpointIps] = useState<string[]>([]);
  const [agentUpgradePlan, setAgentUpgradePlan] = useState<AgentUpgradePlan | null>(null);
  const [managedPeerNodeId, setManagedPeerNodeId] = useState<number | null>(null);
  const [replaceLocalConfigId, setReplaceLocalConfigId] = useState<number | null>(null);
  const [replacePeerConfigId, setReplacePeerConfigId] = useState<number | null>(null);
  const [forceEndpointMismatch, setForceEndpointMismatch] = useState(false);
  const [middlewareType, setMiddlewareType] = useState<"none" | "udp2raw" | "mimic">("none");
  const [udp2rawEnabled, setUdp2rawEnabled] = useState(false);
  const [mimicEnabled, setMimicEnabled] = useState(false);
  const [udp2rawServerSide, setUdp2rawServerSide] = useState<"local" | "peer">("peer");
  const initializedManagedLinkDraftConfigIdRef = useRef<number | null>(null);
  const [managedCreateMtu, setManagedCreateMtu] = useState("1420");
  const [peerNodeConfigs, setPeerNodeConfigs] = useState<ConfigItem[]>([]);
  const [importCandidatesExpanded, setImportCandidatesExpanded] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteNodeConfig, setDeleteNodeConfig] = useState(false);
  const [topologyFullscreenOpen, setTopologyFullscreenOpen] = useState(false);
  const [topologyResetConfirmOpen, setTopologyResetConfirmOpen] = useState(false);
  const [monitorDialogConfigId, setMonitorDialogConfigId] = useState<number | null>(null);
  const [monitorDialogEndpointRef, setMonitorDialogEndpointRef] = useState<string | null>(null);
  const [monitorWindow, setMonitorWindow] = useState("1h");
  const [monitorDetail, setMonitorDetail] = useState<LinkMonitorSamplesResponse | null>(null);
  const [nodePlugins, setNodePlugins] = useState<NodePluginStatus[]>([]);
  const [nodePluginDialogOpen, setNodePluginDialogOpen] = useState(false);
  const [activeNodePluginType, setActiveNodePluginType] = useState("");
  const [nodePluginError, setNodePluginError] = useState("");
  const [nodePluginTasks, setNodePluginTasks] = useState<Record<string, AgentTaskStatus>>({});
  const [birdResources, setBirdResources] = useState<BirdResource[]>([]);
  const [birdDrafts, setBirdDrafts] = useState<Record<string, BirdFileDraft>>({});
  const [birdSelectedResource, setBirdSelectedResource] = useState("");
  const [birdOpeningResource, setBirdOpeningResource] = useState("");
  const [birdEditorSyntax, setBirdEditorSyntax] = useState<"bird" | "plain">("bird");
  const [birdEditorLineNumbers, setBirdEditorLineNumbers] = useState(true);
  const [birdEditorLineWrapping, setBirdEditorLineWrapping] = useState(true);
  const [birdEditorFoldGutter, setBirdEditorFoldGutter] = useState(true);
  const [birdEditorAutocompletion, setBirdEditorAutocompletion] = useState(true);
  const [portInventory, setPortInventory] = useState<PortInventory | null>(null);
  const [portRangeStart, setPortRangeStart] = useState("");
  const [portRangeEnd, setPortRangeEnd] = useState("");
  const [portSearch, setPortSearch] = useState("");
  const [portInventoryPage, setPortInventoryPage] = useState(1);
  const [portScanResults, setPortScanResults] = useState<PortScanResult[]>([]);
  const [pendingActions, setPendingActions] = useState<Set<string>>(() => new Set());
  const topologyEdgeSelectionRef = useRef<number | null>(null);
  const topologyLocalPositionsRef = useRef<Record<number, { x: number; y: number }>>({});
  const birdSelectedResourceRef = useRef("");
  // 统一更新当前选中节点，并同步 ref 防止异步刷新串台。
  function selectNodeId(nodeId: number | null) {
    selectedNodeIdRef.current = nodeId;
    setSelectedNodeId(nodeId);
  }

  // 判断异步回调返回时节点是否仍是当前选中节点。
  function isCurrentSelectedNode(nodeId: number) {
    return selectedNodeIdRef.current === nodeId;
  }

  // 统一更新当前选中配置，并同步 ref 防止异步刷新串台。
  function selectConfigId(configId: number | null) {
    selectedConfigIdRef.current = configId;
    setSelectedConfigId(configId);
  }

  // 统一更新当前选中通用连接，并同步 ref 防止异步刷新串台。
  function selectConnectionRef(connectionRef: string | null) {
    selectedConnectionRefRef.current = connectionRef;
    setSelectedConnectionRef(connectionRef);
  }
  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId) || null,
    [nodes, selectedNodeId],
  );
  const nodeRegionGroups = useMemo(() => {
    const groups = new Map<string, NodeItem[]>();
    for (const node of nodes) {
      const region = nodeRegionLabel(node);
      groups.set(region, [...(groups.get(region) || []), node]);
    }
    return Array.from(groups.entries())
      .map(([region, items], index) => ({
        id: `node-region-${index}`,
        region,
        nodes: items,
        onlineCount: items.filter(isNodeSelectable).length,
      }))
      .sort((left, right) => {
        if (left.region === "未设置地域") return 1;
        if (right.region === "未设置地域") return -1;
        return left.region.localeCompare(right.region, "zh-Hans-CN");
      });
  }, [nodes]);
  const selectedConfig = useMemo(
    () => configs.find((item) => item.id === selectedConfigId) || null,
    [configs, selectedConfigId],
  );
  const selectedGreConnection = useMemo(
    () => connections.find((item) => item.connection_ref === selectedConnectionRef && item.protocol_type === "gre") || null,
    [connections, selectedConnectionRef],
  );
  const selectedGreLocalEndpoint = useMemo(
    () => connectionEndpointByRole(selectedGreConnection, "local"),
    [selectedGreConnection],
  );
  const selectedGrePeerEndpoint = useMemo(
    () => connectionEndpointByRole(selectedGreConnection, "peer"),
    [selectedGreConnection],
  );
  const selectedGreNodeEndpoint = useMemo(
    () => connectionEndpointForNode(selectedGreConnection, selectedNodeId),
    [selectedGreConnection, selectedNodeId],
  );
  const selectedGreNodePeerEndpoint = useMemo(
    () => connectionPeerEndpointForNode(selectedGreConnection, selectedNodeId),
    [selectedGreConnection, selectedNodeId],
  );
  const monitorDialogConfig = useMemo(
    () => configs.find((item) => item.id === monitorDialogConfigId) || null,
    [configs, monitorDialogConfigId],
  );
  const monitorDialogConnection = useMemo(
    () => connections.find((item) => item.endpoints.some((endpoint) => endpoint.endpoint_ref === monitorDialogEndpointRef)) || null,
    [connections, monitorDialogEndpointRef],
  );
  const monitorDialogEndpoint = useMemo(
    () => monitorDialogConnection?.endpoints.find((endpoint) => endpoint.endpoint_ref === monitorDialogEndpointRef) || null,
    [monitorDialogConnection, monitorDialogEndpointRef],
  );
  const monitorDialogPeerEndpoint = useMemo(
    () => monitorDialogConnection?.endpoints.find((endpoint) => endpoint.endpoint_ref !== monitorDialogEndpointRef) || null,
    [monitorDialogConnection, monitorDialogEndpointRef],
  );
  const monitorDialogSubjectName = monitorDialogConfig?.name || monitorDialogEndpoint?.interface_name || "";
  const monitorDialogNodeName = monitorDialogConfig
    ? selectedNode?.name || "节点"
    : monitorDialogEndpoint?.node_name || selectedNode?.name || "节点";
  const monitorDialogTargetHint = monitorDialogConfig
    ? suggestedMonitorTarget(monitorDialogConfig, peer)
    : suggestedEndpointMonitorTarget(monitorDialogEndpoint, monitorDialogPeerEndpoint);
  const monitorDialogActionTarget = monitorDialogConfig
    ? `wireguard:${monitorDialogConfig.id}`
    : monitorDialogEndpoint ? `endpoint:${monitorDialogEndpoint.endpoint_ref}` : "none";
  const selectedNodeOnline = selectedNode ? isNodeSelectable(selectedNode) : false;
  const availableNodePlugins = nodePlugins.filter((plugin) => plugin.available);
  const activeNodePlugin = nodePlugins.find((plugin) => plugin.type === activeNodePluginType) || nodePlugins[0] || null;
  const birdPlugin = nodePlugins.find((plugin) => plugin.type === "bird") || null;
  const portInventoryPlugin = nodePlugins.find((plugin) => plugin.type === "port-inventory") || null;
  const birdFileTree = useMemo(() => buildBirdFileTree(birdResources), [birdResources]);
  const birdSelectedDirectory = birdSelectedResource ? birdDirectory(birdSelectedResource) : "";
  const birdSelectedDraft = birdSelectedResource ? birdDrafts[birdSelectedResource] || null : null;
  const birdContent = birdSelectedDraft?.content || "";
  const birdDirtyDrafts = Object.values(birdDrafts).filter((draft) => draft.content !== draft.originalContent);
  const birdHasUnsavedChanges = birdDirtyDrafts.length > 0;
  const birdTreeLocked = Boolean(birdOpeningResource);
  const filteredPortEntries = useMemo(() => {
    const query = portSearch.trim().toLowerCase();
    const entries = portInventory?.entries || [];
    if (!query) return entries;
    return entries.filter((entry) =>
      String(entry.port).includes(query)
      || String(entry.protocol || "").toLowerCase().includes(query)
      || String(entry.purpose || "").toLowerCase().includes(query)
      || String(entry.detected_process || "").toLowerCase().includes(query)
      || String(entry.detected_source || "").toLowerCase().includes(query),
    );
  }, [portInventory, portSearch]);
  const portInventoryPageCount = Math.max(1, Math.ceil(filteredPortEntries.length / PORT_INVENTORY_PAGE_SIZE));
  const portInventoryPageStart = (Math.min(portInventoryPage, portInventoryPageCount) - 1) * PORT_INVENTORY_PAGE_SIZE;
  const pagedPortEntries = filteredPortEntries.slice(portInventoryPageStart, portInventoryPageStart + PORT_INVENTORY_PAGE_SIZE);
  const birdEditorExtensions = useMemo(
    () => [
      ...(birdEditorLineWrapping ? [EditorView.lineWrapping] : []),
      ...(birdEditorSyntax === "bird" ? [StreamLanguage.define(nginx)] : []),
      keymap.of([
        indentWithTab,
      ]),
    ],
    [birdEditorSyntax, birdEditorLineWrapping],
  );
  const editingNode = useMemo(
    () => nodes.find((node) => node.id === editingNodeId) || null,
    [nodes, editingNodeId],
  );
  const editingNodeMimicStatus = mimicPluginStatus(editingNode);
  const isConfigRunning = selectedConfig?.runtime_status === "running";
  const isConfigStopped = !selectedConfig || ["stopped", "unknown"].includes(selectedConfig.runtime_status);
  const isConfigBusy = selectedConfig ? ["starting", "stopping"].includes(selectedConfig.runtime_status) : false;
  const isGreRunning = selectedGreConnection?.status === "running";
  const isGreStopped = !selectedGreConnection || ["stopped", "unknown"].includes(selectedGreConnection.status);
  const isGreBusy = selectedGreConnection ? ["starting", "stopping", "changing"].includes(selectedGreConnection.status) : false;
  const selectedGreAllNodesOnline = selectedGreConnection
    ? selectedGreConnection.endpoints.every((endpoint) => {
        const endpointNode = nodes.find((node) => node.id === endpoint.node_id);
        return Boolean(endpointNode && isNodeSelectable(endpointNode));
      })
    : false;
  const selectedGreLocalNode = selectedGreLocalEndpoint
    ? nodes.find((node) => node.id === selectedGreLocalEndpoint.node_id) || null
    : null;
  const selectedGrePeerNode = selectedGrePeerEndpoint
    ? nodes.find((node) => node.id === selectedGrePeerEndpoint.node_id) || null
    : null;
  const editGreLocalOuterIpOptions = greOuterIpOptionsFromNode(
    selectedGreLocalNode,
    greProtocolString(selectedGreLocalEndpoint, "outer_local_ip"),
  );
  const editGrePeerOuterIpOptions = greOuterIpOptionsFromNode(
    selectedGrePeerNode,
    greProtocolString(selectedGrePeerEndpoint, "outer_local_ip"),
  );
  const selectedConfigIsManagedLink = selectedConfig?.source === "managed-node";
  const selectedConfigIsUnmanagedImport = selectedConfig?.source === "imported" && !selectedConfig.managed;
  const selectedNodeSupportsWgQuickImport = nodeSupportsWgQuickImport(selectedNode);
  const hasDeployDiff = Boolean(plan?.diff.trim());
  const selectedPeerNodeOptions = selectedNode
    ? nodes.filter((item) => item.id !== selectedNode.id && isNodeSelectable(item))
    : [];
  const selectedGrePeerNodeOptions = selectedNode
    ? nodes.filter((item) => item.id !== selectedNode.id && nodeSupportsGre(item))
    : [];
  const managedCreatePeerNodeOptions = managedCreateProtocol === "gre" ? selectedGrePeerNodeOptions : selectedPeerNodeOptions;
  const selectedManagedPeerNode = nodes.find((item) => item.id === managedPeerNodeId) || null;
  const udp2rawActive = middlewareType === "udp2raw" && udp2rawEnabled;
  const mimicActive = middlewareType === "mimic" && mimicEnabled;
  const selectedLocalEndpoints = selectedNode ? nodeEndpointOptions(selectedNode) : [];
  const selectedPeerEndpoints = selectedManagedPeerNode ? nodeEndpointOptions(selectedManagedPeerNode) : [];
  const managedGreLocalOuterIpOptions = greOuterIpOptionsFromNode(selectedNode);
  const managedGrePeerOuterIpOptions = greOuterIpOptionsFromNode(selectedManagedPeerNode);
  const managedGreLocalOuterIpDefault = managedGreLocalOuterIpOptions[0]?.value || "";
  const managedGrePeerOuterIpDefault = managedGrePeerOuterIpOptions[0]?.value || "";
  const selectedManagedLinkPeerNode = managedLink
    ? nodes.find((node) => node.id === managedLink.peer_interface.node_id) || null
    : null;
  // 判断指定操作 key 是否处于执行中。
  const actionPending = (key: string) => pendingActions.has(key);
  // 生成节点级操作的 pending key。
  const nodeActionKey = (nodeId: number | null | undefined, action: string) => `node:${nodeId || "none"}:${action}`;
  // 生成配置级操作的 pending key。
  const configActionKey = (configId: number | null | undefined, action: string) => `config:${configId || "none"}:${action}`;
  // 生成通用连接级操作的 pending key。
  const connectionActionKey = (connectionRef: string | null | undefined, action: string) => `connection:${connectionRef || "none"}:${action}`;
  // 生成链路监测操作的 pending key。
  const monitorActionKey = (targetId: number | string | null | undefined, action: string) => `monitor:${targetId || "none"}:${action}`;
  // 生成导入候选操作的 pending key。
  const candidateActionKey = (candidateId: number) => `candidate:${candidateId}:import`;
  const selectedConfigAnyTaskPending = selectedConfigId
    ? [
        "create-plan",
        "refresh-deployed",
        "start",
        "stop",
        "delete",
        "confirm-plan",
        "take-over",
        "save-config",
        "save-peer",
        "save-managed-link",
      ].some((action) => actionPending(configActionKey(selectedConfigId, action)))
    : false;
  const selectedManagedLinkPeerEndpoints = selectedManagedLinkPeerNode
    ? nodeEndpointOptions(selectedManagedLinkPeerNode)
    : [];
  const topologyGridColor = theme === "dark" ? "#2c4654" : "#c9d7de";
  const replaceLocalConfig = replaceLocalConfigId
    ? configs.find((item) => item.id === replaceLocalConfigId) || null
    : null;
  const replacePeerConfigOptions = peerNodeConfigs.filter((item) => item.source === "imported" && !item.managed);
  const replacePeerConfig = replacePeerConfigId
    ? replacePeerConfigOptions.find((item) => item.id === replacePeerConfigId) || null
    : null;
  const managedLocalEndpointOptions = endpointOptionsFrom(
    replacePeerConfig?.primary_peer_endpoint_host,
    selectedLocalEndpoints,
  );
  const managedPeerEndpointOptions = endpointOptionsFrom(
    replaceLocalConfig?.primary_peer_endpoint_host,
    selectedPeerEndpoints,
  );
  const managedLocalEndpointDefault = managedLocalEndpointOptions[0]?.value || "";
  const managedPeerEndpointDefault = managedPeerEndpointOptions[0]?.value || "";
  const managedLocalAllowedIpsDefault = (replaceLocalConfig?.primary_peer_allowed_ips?.length
    ? replaceLocalConfig.primary_peer_allowed_ips
    : replacePeerConfig?.tunnel_ips || []).join(", ");
  const managedPeerAllowedIpsDefault = (replacePeerConfig?.primary_peer_allowed_ips?.length
    ? replacePeerConfig.primary_peer_allowed_ips
    : replaceLocalConfig?.tunnel_ips || []).join(", ");
  const editLocalEndpointOptions = endpointOptionsFrom(
    null,
    selectedLocalEndpoints,
    managedLink?.peer_peer.endpoint_host,
  );
  const editPeerEndpointOptions = endpointOptionsFrom(
    null,
    selectedManagedLinkPeerEndpoints,
    managedLink?.local_peer.endpoint_host,
  );
  const editLocalEndpointDefault = managedLink?.peer_peer.endpoint_host || "";
  const editPeerEndpointDefault = managedLink?.local_peer.endpoint_host || "";
  const topologyNodePositions = useMemo<Record<number, TopologyNodePosition>>(() => {
    const count = Math.max(topology.nodes.length, 1);
    const radius = Math.max(180, Math.min(340, count * 42));
    return Object.fromEntries(topology.nodes.map((node, index) => {
      const angle = (Math.PI * 2 * index) / count - Math.PI / 2;
      const draft = topologyDraftPositions[node.id];
      const x = draft?.x ?? node.topology_x ?? 420 + Math.cos(angle) * radius;
      const y = draft?.y ?? node.topology_y ?? 260 + Math.sin(angle) * radius;
      return [node.id, { x, y }];
    }));
  }, [topology.nodes, topologyDraftPositions]);
  const topologyFlowNodes = useMemo<FlowNode[]>(() =>
    topology.nodes.map((node) => {
      const position = topologyNodePositions[node.id] || { x: 0, y: 0 };
      const online = node.status === "online";
      return {
        id: String(node.id),
        position,
        data: {
          label: (
            <div className={online ? "topologyNode online" : "topologyNode"}>
              <TopologyHandles />
              <div className="topologyNodeHeader">
                <strong>{node.name}</strong>
                <span className={online ? "statusDot online" : "statusDot"} />
              </div>
              <small>{node.region || "未设置地域"}</small>
              <span>{topologyNodeEndpoint(node)}</span>
            </div>
          ),
        },
        draggable: true,
        className: online ? "topologyFlowNode online" : "topologyFlowNode",
      };
    }),
  [topology.nodes, topologyNodePositions]);
  const topologyDisplayEdges = useMemo<TopologyDisplayEdge[]>(() => {
    const groups = new Map<string, TopologyEdge[]>();
    for (const edge of topology.edges) {
      const [first, second] = [edge.local_node_id, edge.peer_node_id].sort((left, right) => left - right);
      const key = `${first}:${second}`;
      groups.set(key, [...(groups.get(key) || []), edge]);
    }
    return Array.from(groups.entries()).map(([key, links]) => {
      const [localNodeId, peerNodeId] = key.split(":").map(Number);
      const firstLink = links[0];
      return {
        ...firstLink,
        id: `nodes-${localNodeId}-${peerNodeId}`,
        local_node_id: localNodeId,
        peer_node_id: peerNodeId,
        link_count: links.length,
        links,
      };
    });
  }, [topology.edges]);
  const topologyFlowEdges = useMemo<FlowEdge[]>(() =>
    topologyDisplayEdges.map((edge) => {
      const tone = topologyEdgeTone(edge);
      const handles = topologyHandlePair(
        topologyNodePositions[edge.local_node_id],
        topologyNodePositions[edge.peer_node_id],
      );
      return {
        id: edge.id,
        source: String(edge.local_node_id),
        target: String(edge.peer_node_id),
        sourceHandle: handles.sourceHandle,
        targetHandle: handles.targetHandle,
        label: topologyEdgeSummary(edge),
        animated: edge.links.some((link) => link.local_status === "running" && link.peer_status === "running"),
        className: `topologyEdge ${tone}`,
        data: edge,
      };
    }),
  [topologyDisplayEdges, topologyNodePositions]);

  // 点击拓扑节点时选中对应节点并滚动到节点详情。
  const handleTopologyNodeClick: NodeMouseHandler = (_event, node) => {
    const nodeId = Number(node.id);
    selectNodeId(nodeId);
    selectConfigId(null);
    selectConnectionRef(null);
    setPlan(null);
    setImportCandidatesExpanded(false);
    window.setTimeout(() => {
      document.querySelector(`[data-node-id="${nodeId}"]`)?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 180);
  };

  // 节点拖动结束后保存拓扑坐标。
  const handleTopologyNodeDragStop: OnNodeDrag = (_event, node) => {
    const nodeId = Number(node.id);
    const position = { x: node.position.x, y: node.position.y };
    void runAction(
      async () => {
        await saveTopologyPosition(nodeId, position.x, position.y);
        setTopologyDraftPositions((current) => {
          const draft = current[nodeId];
          if (draft && (draft.x !== position.x || draft.y !== position.y)) {
            return current;
          }
          const next = { ...current };
          delete next[nodeId];
          return next;
        });
      },
      nodeActionKey(nodeId, "topology-position"),
    );
  };

  // 拖动过程中先记录本地草稿坐标，减少刷新造成的回弹。
  const handleTopologyNodeDrag: OnNodeDrag = (_event, node) => {
    const nodeId = Number(node.id);
    setTopologyDraftPositions((current) => ({
      ...current,
      [nodeId]: { x: node.position.x, y: node.position.y },
    }));
  };

  // 点击拓扑链路时选中对应配置并滚动到配置详情。
  const handleTopologyEdgeClick: EdgeMouseHandler = (_event, edge) => {
    const data = edge.data as TopologyDisplayEdge | undefined;
    if (!data) return;
    const links = data.links.length > 0 ? data.links : [data];
    const selectedSideLink = links.find((link) => link.local_node_id === selectedNodeId || link.peer_node_id === selectedNodeId);
    const link = selectedSideLink || links[0];
    const targetNodeId = link.peer_node_id === selectedNodeId ? link.peer_node_id : link.local_node_id;
    const targetConfigId = link.peer_node_id === selectedNodeId ? link.peer_interface_id : link.local_interface_id;
    const targetConnectionRef = link.connection_ref;
    topologyEdgeSelectionRef.current = link.protocol_type === "wireguard" && targetNodeId !== selectedNodeId ? targetConfigId : null;
    selectNodeId(targetNodeId);
    if (link.protocol_type === "gre" && targetConnectionRef) {
      selectConfigId(null);
      selectConnectionRef(targetConnectionRef);
    } else {
      selectConnectionRef(null);
      selectConfigId(targetConfigId);
    }
    setPlan(null);
    window.setTimeout(() => {
      const selector = link.protocol_type === "gre" && targetConnectionRef
        ? `[data-connection-ref="${targetConnectionRef}"]`
        : `[data-config-id="${targetConfigId}"]`;
      document.querySelector(selector)?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    }, 180);
  };

  // 显示短暂 toast 消息。
  function notify(type: Toast["type"], text: string) {
    // 右上角 toast 避免把所有消息堆在主页主流程里。
    const id = Date.now() + Math.random();
    setToasts((items) => [...items, { id, type, text }]);
    window.setTimeout(() => {
      setToasts((items) => items.filter((item) => item.id !== id));
    }, type === "error" ? 6000 : 3800);
  }

  // 重置受管连接创建表单的草稿状态。
  function resetManagedLinkDraft(overrides: { replaceLocalConfigId?: number | null } = {}) {
    setManagedCreateProtocol("wireguard");
    setManagedPeerNodeId(null);
    setReplaceLocalConfigId(overrides.replaceLocalConfigId ?? null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    setMiddlewareType("none");
    setUdp2rawEnabled(false);
    setMimicEnabled(false);
    setUdp2rawServerSide("peer");
    setManagedCreateMtu("1420");
  }

  // 关闭创建弹窗并清理受管连接草稿。
  function closeCreateDialog() {
    setCreateDialog(null);
    resetManagedLinkDraft();
  }

  // 打开受管连接创建弹窗，并可预置接管本端配置。
  function openManagedCreateDialog(overrides: { replaceLocalConfigId?: number | null } = {}) {
    resetManagedLinkDraft(overrides);
    setCreateDialog(overrides.replaceLocalConfigId ? "managed" : "managed-protocol");
  }

  // 切换受管连接创建协议，并清理另一种协议专用的草稿状态。
  function switchManagedCreateProtocol(protocol: ManagedCreateProtocol) {
    setManagedCreateProtocol(protocol);
    setManagedPeerNodeId(null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    if (protocol === "gre") {
      setReplaceLocalConfigId(null);
      setMiddlewareType("none");
      setUdp2rawEnabled(false);
      setMimicEnabled(false);
      setUdp2rawServerSide("peer");
      setManagedCreateMtu("1476");
    } else {
      setManagedCreateMtu("1420");
    }
  }

  // 从协议选择弹窗进入对应的受管连接创建表单。
  function selectManagedCreateProtocol(protocol: ManagedCreateProtocol) {
    switchManagedCreateProtocol(protocol);
    setCreateDialog("managed");
  }

  // 清空登录态和所有依赖登录的页面状态。
  function clearAuthenticatedState() {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
    setAuthToken("");
    setCurrentUser(null);
    setNodes([]);
    setTopology({ nodes: [], edges: [] });
    setTopologyDraftPositions({});
    selectNodeId(null);
    setConfigs([]);
    selectConfigId(null);
    setConnections([]);
    selectConnectionRef(null);
    setPeer(null);
    setManagedLink(null);
    setImportCandidates([]);
    setPlan(null);
    setCreateDialog(null);
    setNodeCreateOpen(false);
    setEditingNodeId(null);
    setAgentUpgradePlan(null);
    setManagedPeerNodeId(null);
    setReplaceLocalConfigId(null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    setMiddlewareType("none");
    setUdp2rawEnabled(false);
    setMimicEnabled(false);
    setUdp2rawServerSide("peer");
    setManagedCreateMtu("1420");
    setPeerNodeConfigs([]);
    setSettingsOpen(false);
    setMonitorDialogConfigId(null);
    setMonitorDetail(null);
    setPendingActions(new Set());
  }

  // 返回一个可等待的延迟 Promise。
  function sleep(ms: number) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  // 包装用户操作，统一处理 pending 状态和错误提示。
  async function runAction(action: () => Promise<void>, key?: string) {
    // 所有用户操作都通过这里展示 API 错误，避免点击后页面无反馈。
    if (key && pendingActions.has(key)) {
      return;
    }
    if (key) {
      setPendingActions((items) => {
        const next = new Set(items);
        next.add(key);
        return next;
      });
    }
    try {
      await action();
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("401:")) {
        clearAuthenticatedState();
        return;
      }
      notify("error", formatUserError(error));
    } finally {
      if (key) {
        setPendingActions((items) => {
          const next = new Set(items);
          next.delete(key);
          return next;
        });
      }
    }
  }

  // 手动占用一个 pending key。
  function holdActionPending(key: string) {
    setPendingActions((items) => {
      const next = new Set(items);
      next.add(key);
      return next;
    });
  }

  // 手动释放一个 pending key。
  function releaseActionPending(key: string) {
    setPendingActions((items) => {
      const next = new Set(items);
      next.delete(key);
      return next;
    });
  }

  // 处理登录表单提交。
  async function login(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setLoginError("");
    let result: LoginResult;
    try {
      result = await api<LoginResult>("/api/auth/login", {
        method: "POST",
        skipAuth: true,
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
        }),
      });
    } catch (error) {
      setLoginError(formatUserError(error).replace(/^401:\s*/, ""));
      return;
    }
    window.localStorage.setItem(AUTH_TOKEN_KEY, result.token);
    setAuthToken(result.token);
    setCurrentUser(result.username);
    await refreshSettings();
    await refreshHome();
  }

  // 注销当前 Web 会话。
  async function logout() {
    await api<{ status: string }>("/api/auth/logout", { method: "POST" });
    clearAuthenticatedState();
  }

  // 刷新主控设置和品牌配置。
  async function refreshSettings() {
    const data = await api<ControllerSettings>("/api/settings");
    setControllerUrl(data.controller_url || DEFAULT_CONTROLLER_URL);
    setSettingsUsername(data.username || "pmman");
    setSiteTitle(data.site_title || DEFAULT_SITE_TITLE);
    setSiteLogoUrl(data.site_logo_url || DEFAULT_SITE_LOGO_URL);
  }

  // 未登录时读取公开品牌配置。
  async function refreshBranding() {
    const data = await api<BrandingSettings>("/api/branding", { skipAuth: true });
    setSiteTitle(data.site_title || DEFAULT_SITE_TITLE);
    setSiteLogoUrl(data.site_logo_url || DEFAULT_SITE_LOGO_URL);
  }

  // 保存主控设置，必要时先上传 logo 文件。
  async function saveSettings(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const newPassword = String(form.get("new_password") || "");
    if (newPassword && newPassword.length < 6) {
      throw new Error("新密码至少需要 6 个字符");
    }
    const logoFile = form.get("site_logo_file");
    let uploadedLogoUrl: string | null = null;
    if (logoFile instanceof File && logoFile.size > 0) {
      const logoSettings = await api<ControllerSettings>("/api/settings/logo", {
        method: "POST",
        headers: { "Content-Type": logoFile.type },
        body: logoFile,
      });
      uploadedLogoUrl = logoSettings.site_logo_url || DEFAULT_SITE_LOGO_URL;
    }
    const payload: {
      controller_url: string;
      username: string;
      site_title: string;
      new_password?: string;
    } = {
      controller_url: String(form.get("controller_url") || "").trim(),
      username: String(form.get("username") || "").trim(),
      site_title: String(form.get("site_title") || "").trim() || DEFAULT_SITE_TITLE,
    };
    if (newPassword) {
      payload.new_password = newPassword;
    }
    const data = await api<ControllerSettings>("/api/settings", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    setControllerUrl(data.controller_url || DEFAULT_CONTROLLER_URL);
    setSettingsUsername(data.username || "pmman");
    setSiteTitle(data.site_title || DEFAULT_SITE_TITLE);
    setSiteLogoUrl(uploadedLogoUrl || data.site_logo_url || DEFAULT_SITE_LOGO_URL);
    setSettingsLogoPreviewUrl("");
    setSettingsOpen(false);
    if (newPassword) {
      clearAuthenticatedState();
      notify("success", "账号已更新，请使用新凭据重新登录。");
      return;
    }
    setCurrentUser(data.username || currentUser);
    notify("success", "设置已保存。");
  }

  // 选择本地 logo 文件后生成预览地址。
  function previewLogoFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    setSettingsLogoPreviewUrl((previous) => {
      if (previous.startsWith("blob:")) {
        URL.revokeObjectURL(previous);
      }
      return file ? URL.createObjectURL(file) : "";
    });
  }

  // 刷新节点列表。
  async function refreshNodes() {
    // 刷新节点列表；节点必须由用户主动点选，离线节点不能进入下级菜单。
    const data = await api<NodeItem[]>("/api/nodes");
    setNodes(data);
  }

  // 刷新拓扑数据，并合并尚未被后端确认的本地拖动坐标。
  async function refreshTopology() {
    const data = await api<TopologyResponse>("/api/topology");
    const localPositions = topologyLocalPositionsRef.current;
    const mergedNodes = data.nodes.map((node) => {
      const local = localPositions[node.id];
      if (!local) return node;
      if (node.topology_x === local.x && node.topology_y === local.y) {
        const next = { ...topologyLocalPositionsRef.current };
        delete next[node.id];
        topologyLocalPositionsRef.current = next;
        return node;
      }
      return {
        ...node,
        topology_x: local.x,
        topology_y: local.y,
        topology_locked: true,
      };
    });
    setTopology({ ...data, nodes: mergedNodes });
  }

  // 刷新主页所需的节点、拓扑、配置和弹窗详情。
  async function refreshHome() {
    await Promise.all([refreshNodes(), refreshTopology()]);
    if (selectedNodeId) {
      await Promise.all([
        refreshConfigs(selectedNodeId, selectedConfigId),
        refreshConnections(selectedNodeId),
      ]);
    }
    if (selectedConfigId) {
      await refreshPeer(selectedConfigId).catch(() => undefined);
      await refreshManagedLink(selectedConfigId).catch(() => undefined);
    }
    if (monitorDialogConfigId || monitorDialogEndpointRef) {
      await refreshMonitorDetail().catch(() => undefined);
    }
  }

  // 保存单个拓扑节点位置。
  async function saveTopologyPosition(nodeId: number, x: number, y: number) {
    topologyLocalPositionsRef.current = {
      ...topologyLocalPositionsRef.current,
      [nodeId]: { x, y },
    };
    await api<NodeItem>(`/api/nodes/${nodeId}/topology-position`, {
      method: "PATCH",
      body: JSON.stringify({ x, y, locked: true }),
    });
    const currentLocal = topologyLocalPositionsRef.current[nodeId];
    if (!currentLocal || currentLocal.x !== x || currentLocal.y !== y) {
      return;
    }
    setTopology((current) => ({
      ...current,
      nodes: current.nodes.map((node) =>
        node.id === nodeId
          ? { ...node, topology_x: x, topology_y: y, topology_locked: true }
          : node,
      ),
    }));
    setNodes((current) =>
      current.map((node) =>
        node.id === nodeId
          ? { ...node, topology_x: x, topology_y: y, topology_locked: true }
          : node,
      ),
    );
  }

  // 清空所有自定义拓扑位置并恢复自动布局。
  async function resetTopologyLayout() {
    const data = await api<TopologyResponse>("/api/topology/layout/reset", { method: "POST" });
    topologyLocalPositionsRef.current = {};
    setTopologyDraftPositions({});
    setTopology(data);
    setNodes((current) =>
      current.map((node) => ({
        ...node,
        topology_x: null,
        topology_y: null,
        topology_locked: false,
      })),
    );
    setTopologyResetConfirmOpen(false);
    notify("success", "拓扑位置已还原为自动布局。");
  }

  // 刷新指定节点下的通用连接列表。
  async function refreshConnections(nodeId: number) {
    const data = await api<ConnectionItem[]>(`/api/nodes/${nodeId}/connections`);
    if (!isCurrentSelectedNode(nodeId)) return;
    setConnections(data);
    const currentConnectionRef = selectedConnectionRefRef.current;
    if (currentConnectionRef && !data.some((item) => item.connection_ref === currentConnectionRef)) {
      selectConnectionRef(null);
    }
  }

  // 刷新指定节点的 WireGuard 配置列表。
  async function refreshConfigs(
    nodeId: number,
    preferredConfigId?: number | null,
    options: { forceSelect?: boolean } = {},
  ) {
    // 刷新某个节点下的 WireGuard 点对点配置列表。
    const data = await api<ConfigItem[]>(`/api/nodes/${nodeId}/wireguard/configs`);
    if (!isCurrentSelectedNode(nodeId)) return;
    setConfigs(data);
    const currentConfigId = selectedConfigIdRef.current;
    const existing = currentConfigId && data.some((item) => item.id === currentConfigId);
    const preferredExists = preferredConfigId != null && data.some((item) => item.id === preferredConfigId);
    if (preferredExists && (options.forceSelect || currentConfigId === preferredConfigId)) {
      selectConfigId(preferredConfigId);
    } else if (!existing) {
      selectConfigId(null);
    }
  }

  // 读取对端节点可用于替换或导入的配置列表。
  async function refreshPeerNodeConfigs(nodeId: number) {
    const data = await api<ConfigItem[]>(`/api/nodes/${nodeId}/wireguard/configs`);
    setPeerNodeConfigs(data);
  }

  // 刷新当前节点可用插件列表。
  async function refreshNodePlugins(nodeId: number) {
    const data = await api<NodePluginStatus[]>(`/api/nodes/${nodeId}/plugins`);
    if (!isCurrentSelectedNode(nodeId)) return;
    setNodePlugins(data);
  }

  // 刷新单个 Agent 任务状态并缓存到插件任务表。
  async function refreshAgentTask(taskId: number, key: string) {
    const task = await api<AgentTaskStatus>(`/api/tasks/${taskId}`);
    setNodePluginTasks((current) => ({ ...current, [key]: task }));
    return task;
  }

  // 触发节点插件 action，并轮询任务直到完成或超时。
  async function executeNodePluginAction(pluginType: string, action: string, payload: Record<string, unknown> = {}) {
    if (!selectedNodeId) return;
    const key = `${pluginType}:${action}`;
    try {
      const result = await api<NodePluginActionResult>(`/api/nodes/${selectedNodeId}/plugins/${pluginType}/${action}`, {
        method: "POST",
        body: JSON.stringify({ payload }),
      });
      for (let attempt = 0; attempt < AGENT_TASK_POLL_LIMIT; attempt += 1) {
        const task = await refreshAgentTask(result.task_id, key);
        if (task.status === "succeeded") {
          return task;
        }
        if (task.status === "failed") {
          setNodePluginError(formatPluginTaskError(task));
          return task;
        }
        await sleep(TASK_POLL_INTERVAL_MS);
      }
      notify("info", "插件任务仍在执行，请稍后刷新节点状态。");
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("401:")) {
        throw error;
      }
      setNodePluginError(formatUserError(error));
    }
  }

  // 读取端口台账范围和条目。
  async function refreshPortInventory(nodeId = selectedNodeId) {
    if (!nodeId) return;
    const data = await api<PortInventory>(`/api/nodes/${nodeId}/port-inventory`);
    if (!isCurrentSelectedNode(nodeId)) return;
    setPortInventory(data);
    setPortRangeStart(data.setting.range_start ? String(data.setting.range_start) : "");
    setPortRangeEnd(data.setting.range_end ? String(data.setting.range_end) : "");
  }

  // 保存端口台账范围，并可询问是否立即扫描。
  async function savePortInventoryRange(options: { askScan?: boolean } = {}) {
    if (!selectedNodeId) return;
    const rangeStart = Number(portRangeStart);
    const rangeEnd = Number(portRangeEnd);
    if (!isRequiredPort(rangeStart) || !isRequiredPort(rangeEnd) || rangeStart > rangeEnd) {
      throw new Error("端口范围必须填写 1-65535，且起始端口不能大于结束端口");
    }
    const setting = await api<PortInventorySetting>(`/api/nodes/${selectedNodeId}/port-inventory/range`, {
      method: "PUT",
      body: JSON.stringify({ range_start: rangeStart, range_end: rangeEnd }),
    });
    setPortInventory((current) => ({
      setting,
      entries: current?.entries || [],
    }));
    notify("success", "端口范围已保存。");
    if (options.askScan && selectedNodeOnline && window.confirm("端口范围已保存，是否立即扫描该范围内正在监听的端口？")) {
      await scanPortInventory();
    }
  }

  // 触发端口台账插件扫描并保存扫描结果。
  async function scanPortInventory() {
    if (!portInventoryPlugin?.available || !selectedNodeOnline) return;
    const rangeStart = Number(portRangeStart || portInventory?.setting.range_start);
    const rangeEnd = Number(portRangeEnd || portInventory?.setting.range_end);
    if (!isRequiredPort(rangeStart) || !isRequiredPort(rangeEnd) || rangeStart > rangeEnd) {
      throw new Error("请先填写有效端口范围");
    }
    const task = await executeNodePluginAction("port-inventory", "scan", {
      range_start: rangeStart,
      range_end: rangeEnd,
    });
    if (!task || task.status === "failed") return;
    const results = Array.isArray(task.result?.ports) ? task.result.ports as PortScanResult[] : [];
    setPortScanResults(results);
    notify("success", `扫描完成，发现 ${results.length} 个占用端口。`);
  }

  // 创建端口台账条目。
  async function createPortInventoryEntry(entry: Omit<PortScanResult, "purpose"> & { purpose?: string }) {
    if (!selectedNodeId) return;
    await api<PortInventoryEntry>(`/api/nodes/${selectedNodeId}/port-inventory/entries`, {
      method: "POST",
      body: JSON.stringify({
        protocol: entry.protocol,
        port: entry.port,
        purpose: entry.purpose || "",
        source: entry.source || "manual",
        detected_process: entry.detected_process || null,
        detected_pid: entry.detected_pid || null,
        detected_source: entry.detected_source || null,
      }),
    });
    await refreshPortInventory();
    notify("success", "端口条目已添加。");
  }

  // 处理手动新增端口台账条目的表单提交。
  async function createManualPortInventoryEntry(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const protocol = String(form.get("protocol") || "TCP") as "TCP" | "UDP";
    const port = Number(form.get("port"));
    const purpose = String(form.get("purpose") || "").trim();
    if (!isRequiredPort(port)) {
      throw new Error("端口号必须是 1-65535");
    }
    await createPortInventoryEntry({ protocol, port, purpose, source: "manual" });
    formElement.reset();
  }

  // 更新端口台账条目的用途说明。
  async function updatePortInventoryEntryPurpose(entry: PortInventoryEntry, purpose: string) {
    if (!selectedNodeId) return;
    const updated = await api<PortInventoryEntry>(`/api/nodes/${selectedNodeId}/port-inventory/entries/${entry.id}`, {
      method: "PATCH",
      body: JSON.stringify({ purpose }),
    });
    setPortInventory((current) => current ? {
      ...current,
      entries: current.entries.map((item) => item.id === updated.id ? updated : item),
    } : current);
  }

  // 删除端口台账条目。
  async function deletePortInventoryEntry(entry: PortInventoryEntry) {
    if (!selectedNodeId) return;
    await api(`/api/nodes/${selectedNodeId}/port-inventory/entries/${entry.id}`, { method: "DELETE" });
    setPortInventory((current) => current ? {
      ...current,
      entries: current.entries.filter((item) => item.id !== entry.id),
    } : current);
    notify("success", "端口条目已删除。");
  }

  // 重置 BIRD 编辑器缓存和选中文件。
  function resetBirdEditorState(clearResources = false) {
    if (clearResources) {
      setBirdResources([]);
    }
    setBirdDrafts({});
    setBirdSelectedResource("");
    setBirdOpeningResource("");
  }

  // 在存在未保存 BIRD 修改时询问是否放弃。
  function confirmDiscardBirdChanges(): boolean {
    if (!birdHasUnsavedChanges) return true;
    return window.confirm("当前 BIRD 配置有未保存修改，是否放弃这些修改？");
  }

  // 打开节点插件弹窗并初始化首个插件。
  function openNodePluginDialog() {
    if (nodePlugins.length === 0) return;
    resetBirdEditorState(true);
    setPortInventory(null);
    setPortScanResults([]);
    setPortSearch("");
    setPortInventoryPage(1);
    const preferredPlugin = nodePlugins.find((plugin) => plugin.type === "bird") || nodePlugins[0];
    setActiveNodePluginType(preferredPlugin.type);
    setNodePluginDialogOpen(true);
  }

  // 关闭节点插件弹窗，必要时提示放弃未保存修改。
  function closeNodePluginDialog() {
    if (!confirmDiscardBirdChanges()) return;
    setNodePluginDialogOpen(false);
  }

  // 切换节点插件标签页，离开 BIRD 时保护未保存修改。
  function switchNodePluginTab(pluginType: string) {
    if (pluginType === activeNodePluginType) return;
    if (!confirmDiscardBirdChanges()) return;
    resetBirdEditorState(pluginType === "bird");
    if (pluginType === "port-inventory") {
      setPortInventory(null);
      setPortScanResults([]);
      setPortSearch("");
      setPortInventoryPage(1);
    }
    setActiveNodePluginType(pluginType);
  }

  // 读取 BIRD 配置树。
  async function listBirdResources(options: { confirmDiscard?: boolean; clearDrafts?: boolean } = {}) {
    if (options.confirmDiscard && !confirmDiscardBirdChanges()) return;
    if (options.clearDrafts) {
      resetBirdEditorState(false);
    }
    const task = await executeNodePluginAction("bird", "list");
    if (!task || task.status === "failed") return;
    const files = (task?.result?.files || []) as BirdResource[];
    setBirdResources(files);
    const selectedResource = birdSelectedResourceRef.current;
    if (!files.some((file) => file.resource_key === selectedResource)) {
      setBirdSelectedResource("");
    }
    notify(files.length > 0 ? "info" : "success", files.length > 0 ? "配置树已读取，请选择一个配置文件打开。" : "没有发现可编辑的 BIRD 配置文件。");
  }

  // 读取并缓存单个 BIRD 配置文件。
  async function readBirdResource(resourceKey = birdSelectedResource) {
    if (!resourceKey) return;
    if (birdOpeningResource) return;
    if (birdDrafts[resourceKey]) {
      setBirdSelectedResource(resourceKey);
      return;
    }
    setBirdOpeningResource(resourceKey);
    try {
      const task = await executeNodePluginAction("bird", "read", { resource_key: resourceKey });
      if (!task || task.status === "failed") return;
      const result = task?.result as (Record<string, unknown> | null | undefined);
      if (result?.content != null) {
        setBirdSelectedResource(resourceKey);
        setBirdDrafts((current) => ({
          ...current,
          [resourceKey]: {
            resource: result as unknown as BirdResource,
            content: String(result.content),
            originalContent: String(result.content),
            sha256: String(result.sha256 || ""),
          },
        }));
        notify("success", "配置文件已打开。");
      }
    } finally {
      setBirdOpeningResource("");
    }
  }

  // 校验当前选中的 BIRD 配置文件内容。
  async function validateBirdResource() {
    if (!birdSelectedResource) return;
    const task = await executeNodePluginAction("bird", "validate", {
      resource_key: birdSelectedResource,
      content: birdContent,
    });
    if (!task || task.status === "failed") return;
    if (task.result?.valid) {
      notify("success", "BIRD 配置校验通过。");
    } else {
      setNodePluginError(formatPluginTaskError(task, "BIRD 配置校验未通过"));
    }
  }

  // 批量保存所有已修改的 BIRD 配置文件并刷新 BIRD。
  async function applyBirdResources(options: { confirm?: boolean } = {}) {
    if (birdDirtyDrafts.length === 0) {
      notify("info", "配置内容没有变化。");
      return;
    }
    if (options.confirm !== false) {
      const confirmed = window.confirm(`确认保存 ${birdDirtyDrafts.length} 个 BIRD 配置文件的变更，并执行 birdc configure 刷新配置？`);
      if (!confirmed) return;
    }
    const task = await executeNodePluginAction("bird", "apply_many", {
      files: birdDirtyDrafts.map((draft) => ({
        resource_key: draft.resource.resource_key,
        content: draft.content,
        base_sha256: draft.sha256,
      })),
      reload: true,
    });
    if (!task || task.status === "failed") return;
    if (task?.result?.applied) {
      const savedFiles = Array.isArray(task.result.files) ? task.result.files as Array<Record<string, unknown>> : [];
      setBirdDrafts((current) => {
        const next = { ...current };
        for (const saved of savedFiles) {
          const resourceKey = String(saved.resource_key || "");
          if (!resourceKey || !next[resourceKey]) continue;
          next[resourceKey] = {
            ...next[resourceKey],
            originalContent: next[resourceKey].content,
            sha256: String(saved.sha256 || next[resourceKey].sha256),
          };
        }
        return next;
      });
      notify("success", `已保存 ${birdDirtyDrafts.length} 个 BIRD 配置文件，并已执行 birdc configure。`);
      await listBirdResources();
    } else {
      setNodePluginError(formatPluginTaskError(task, "BIRD 配置未应用"));
    }
  }

  // 处理 BIRD 编辑器 Ctrl+S 快捷保存。
  function handleBirdEditorKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const key = event.key.toLowerCase();
    if (key !== "s" || (!event.ctrlKey && !event.metaKey) || event.altKey) return;
    event.preventDefault();
    event.stopPropagation();
    if (!birdSelectedResource) return;
    if (birdDirtyDrafts.length === 0) {
      notify("info", "配置内容没有变化。");
      return;
    }
    if (actionPending("plugin:bird:list") || actionPending("plugin:bird:apply")) return;
    void runAction(() => applyBirdResources({ confirm: false }), "plugin:bird:apply");
  }

  // 刷新当前配置的唯一 WireGuard peer。
  async function refreshPeer(configId: number) {
    // 刷新某个配置下的唯一对端；当前产品规则是一份配置只连接一个对端。
    const data = await api<PeerItem | null>(`/api/wireguard/configs/${configId}/peer`);
    if (selectedConfigIdRef.current !== configId) return;
    setPeer(data);
  }

  // 刷新当前配置所属的受管连接详情。
  async function refreshManagedLink(configId: number) {
    const data = await api<ManagedLink>(`/api/wireguard/configs/${configId}/managed-link`);
    if (selectedConfigIdRef.current !== configId) return;
    setManagedLink(data);
  }

  // 刷新链路监测详情和样本。
  function monitorDialogApiPath() {
    if (monitorDialogConfig) return `/api/wireguard/configs/${monitorDialogConfig.id}/link-monitor`;
    if (monitorDialogEndpoint) return `/api/connection-endpoints/${monitorDialogEndpoint.id}/link-monitor`;
    return "";
  }

  // 刷新链路监测详情和样本。
  async function refreshMonitorDetail(windowValue = monitorWindow) {
    const apiPath = monitorDialogApiPath();
    if (!apiPath) {
      setMonitorDetail(null);
      return;
    }
    const monitor = await api<LinkMonitor | null>(apiPath);
    if (!monitor) {
      setMonitorDetail(null);
      return;
    }
    const detail = await api<LinkMonitorSamplesResponse>(`/api/link-monitors/${monitor.id}/samples?window=${encodeURIComponent(windowValue)}`);
    setMonitorDetail(detail);
  }

  // 保存链路监测配置。
  async function saveLinkMonitor(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const apiPath = monitorDialogApiPath();
    if (!apiPath || !selectedNodeId) return;
    const form = new FormData(event.currentTarget);
    await api<LinkMonitor>(apiPath, {
      method: "POST",
      body: JSON.stringify({
        target_host: String(form.get("target_host") || "").trim(),
        interval_seconds: optionalInt(form.get("interval_seconds"), "监测间隔") ?? 10,
        retention_days: optionalInt(form.get("retention_days"), "保留天数") ?? 7,
        enabled: form.get("enabled") === "on",
      }),
    });
    await refreshMonitorDetail();
    await Promise.all([
      refreshConfigs(selectedNodeId, selectedConfigId),
      refreshConnections(selectedNodeId),
      refreshTopology(),
    ]);
    notify("success", "链路监测已保存。");
  }

  // 删除链路监测配置。
  async function deleteLinkMonitor() {
    if (!monitorDetail || !selectedNodeId) return;
    await api<{ status: string }>(`/api/link-monitors/${monitorDetail.monitor.id}`, { method: "DELETE" });
    setMonitorDetail(null);
    await Promise.all([
      refreshConfigs(selectedNodeId, selectedConfigId),
      refreshConnections(selectedNodeId),
      refreshTopology(),
    ]);
    notify("success", "链路监测已删除。");
  }

  // 刷新节点上的 wg-quick 导入候选。
  async function refreshImportCandidates(nodeId: number) {
    // 刷新当前节点的 wg-quick 导入候选。
    const data = await api<ImportCandidate[]>(`/api/nodes/${nodeId}/wireguard/import-candidates`);
    if (!isCurrentSelectedNode(nodeId)) return;
    setImportCandidates(data);
  }

  useEffect(() => {
    // 处理全局认证过期事件，统一清理登录态。
    function handleAuthExpired() {
      clearAuthenticatedState();
    }

    window.addEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
  }, []);

  useEffect(() => {
    // 页面启动时恢复登录态，未登录时只加载品牌信息。
    async function bootstrap() {
      if (!authToken) {
        await refreshBranding().catch(() => undefined);
        setAuthChecked(true);
        return;
      }
      try {
        const me = await api<{ authenticated: boolean; username: string | null }>("/api/auth/me");
        setCurrentUser(me.username);
        await refreshSettings();
        await refreshHome();
      } catch {
        clearAuthenticatedState();
      } finally {
        setAuthChecked(true);
      }
    }
    void bootstrap();
  }, [authToken]);

  useEffect(() => {
    if (!authToken) return;
    const timer = window.setInterval(() => {
      refreshHome().catch((error) => {
        if (!(error instanceof Error && error.message.startsWith("401:"))) {
          notify("error", formatUserError(error));
        }
      });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [selectedNodeId, selectedConfigId, selectedConnectionRef, monitorDialogConfigId, monitorDialogEndpointRef, monitorWindow, authToken]);

  useEffect(() => {
    document.title = siteTitle || DEFAULT_SITE_TITLE;
  }, [siteTitle]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useEffect(() => {
    if (nodeCreateOpen) {
      setNodeCreateEndpointIps([]);
    }
  }, [nodeCreateOpen]);

  useEffect(() => {
    if (editingNode) {
      setEditingNodeEndpointIps(nodeEndpointOptions(editingNode));
    } else {
      setEditingNodeEndpointIps([]);
    }
  }, [editingNodeId]);

  useEffect(() => {
    return () => {
      if (settingsLogoPreviewUrl.startsWith("blob:")) {
        URL.revokeObjectURL(settingsLogoPreviewUrl);
      }
    };
  }, [settingsLogoPreviewUrl]);

  useEffect(() => {
    if (managedPeerNodeId) {
      refreshPeerNodeConfigs(managedPeerNodeId).catch((error) => notify("error", formatUserError(error)));
    } else {
      setPeerNodeConfigs([]);
      setReplacePeerConfigId(null);
    }
  }, [managedPeerNodeId]);

  useEffect(() => {
    setImportCandidatesExpanded(false);
    setConfigs([]);
    setConnections([]);
    selectConnectionRef(null);
    setImportCandidates([]);
    setNodePlugins([]);
    setNodePluginTasks({});
    setBirdResources([]);
    setBirdDrafts({});
    setBirdSelectedResource("");
    setPortInventory(null);
    setPortScanResults([]);
    setPortSearch("");
    setPortInventoryPage(1);
    setNodePluginDialogOpen(false);
    setActiveNodePluginType("");
    if (selectedNodeId) {
      const preferredConfigId = topologyEdgeSelectionRef.current;
      topologyEdgeSelectionRef.current = null;
      if (!preferredConfigId) {
        selectConfigId(null);
      }
      setPlan(null);
      setManagedPeerNodeId(null);
      refreshConfigs(selectedNodeId, preferredConfigId).catch((error) => notify("error", formatUserError(error)));
      refreshConnections(selectedNodeId).catch((error) => notify("error", formatUserError(error)));
      refreshImportCandidates(selectedNodeId).catch((error) => notify("error", formatUserError(error)));
      refreshNodePlugins(selectedNodeId).catch((error) => notify("error", formatUserError(error)));
    } else {
      topologyEdgeSelectionRef.current = null;
      setConfigs([]);
      setConnections([]);
      selectConfigId(null);
      selectConnectionRef(null);
      setImportCandidates([]);
      setNodePlugins([]);
      setNodePluginTasks({});
      setBirdResources([]);
      setBirdDrafts({});
      setBirdSelectedResource("");
      setPortInventory(null);
      setPortScanResults([]);
      setPortSearch("");
      setPortInventoryPage(1);
      setNodePluginDialogOpen(false);
      setActiveNodePluginType("");
      setPlan(null);
    }
  }, [selectedNodeId]);

  useEffect(() => {
    birdSelectedResourceRef.current = birdSelectedResource;
  }, [birdSelectedResource]);

  useEffect(() => {
    if (!nodePluginDialogOpen || nodePlugins.length === 0) return;
    if (birdHasUnsavedChanges) return;
    if (!activeNodePluginType || !nodePlugins.some((plugin) => plugin.type === activeNodePluginType)) {
      setActiveNodePluginType(nodePlugins[0].type);
    }
  }, [nodePluginDialogOpen, nodePlugins, activeNodePluginType, birdHasUnsavedChanges]);

  useEffect(() => {
    if (!nodePluginDialogOpen || activeNodePluginType !== "bird" || birdResources.length > 0) return;
    if (!birdPlugin?.available || !selectedNodeOnline || actionPending("plugin:bird:list")) return;
    void runAction(() => listBirdResources(), "plugin:bird:list");
  }, [nodePluginDialogOpen, activeNodePluginType, birdPlugin?.available, selectedNodeOnline, birdResources.length]);

  useEffect(() => {
    if (!nodePluginDialogOpen || activeNodePluginType !== "port-inventory" || !selectedNodeId || portInventory) return;
    void runAction(() => refreshPortInventory(selectedNodeId), "plugin:port-inventory:load");
  }, [nodePluginDialogOpen, activeNodePluginType, selectedNodeId, portInventory]);

  useEffect(() => {
    setPortInventoryPage(1);
  }, [portSearch]);

  useEffect(() => {
    setPortInventoryPage((page) => Math.min(page, portInventoryPageCount));
  }, [portInventoryPageCount]);

  useEffect(() => {
    if (!birdHasUnsavedChanges) return;
    // 浏览器关闭或刷新前拦截未保存的 BIRD 修改。
    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [birdHasUnsavedChanges]);

  useEffect(() => {
    if (!editingNodeId || !authToken) {
      setAgentUpgradePlan(null);
      return;
    }
    refreshAgentUpgradePlan(editingNodeId).catch((error) => notify("error", formatUserError(error)));
  }, [editingNodeId, authToken]);

  useEffect(() => {
    if (selectedConfigId) {
      if (selectedConfigIsManagedLink) {
        setPeer(null);
        refreshManagedLink(selectedConfigId).catch((error) => notify("error", formatUserError(error)));
      } else {
        setManagedLink(null);
        refreshPeer(selectedConfigId).catch((error) => notify("error", formatUserError(error)));
      }
    } else {
      setPeer(null);
      setManagedLink(null);
    }
  }, [selectedConfigId, selectedConfigIsManagedLink]);

  useEffect(() => {
    if (!selectedConfigId || !selectedConfigIsManagedLink || !managedLink) {
      initializedManagedLinkDraftConfigIdRef.current = null;
      return;
    }
    const belongsToSelectedConfig =
      managedLink.local_interface.id === selectedConfigId || managedLink.peer_interface.id === selectedConfigId;
    if (!belongsToSelectedConfig || initializedManagedLinkDraftConfigIdRef.current === selectedConfigId) return;

    initializedManagedLinkDraftConfigIdRef.current = selectedConfigId;
    if (!managedLink.middleware) {
      setMiddlewareType("none");
      setUdp2rawEnabled(false);
      setMimicEnabled(false);
      setUdp2rawServerSide("peer");
      return;
    }
    if (managedLink.middleware.type === "udp2raw") {
      setMiddlewareType("udp2raw");
      setUdp2rawEnabled(Boolean(managedLink.middleware.enabled));
      setMimicEnabled(false);
      setUdp2rawServerSide(managedLink.middleware.server_side || "peer");
    } else if (managedLink.middleware.type === "mimic") {
      setMiddlewareType("mimic");
      setUdp2rawEnabled(false);
      setMimicEnabled(Boolean(managedLink.middleware.enabled));
      setUdp2rawServerSide("peer");
    }
  }, [selectedConfigId, selectedConfigIsManagedLink, managedLink]);

  useEffect(() => {
    if (!monitorDialogConfigId && !monitorDialogEndpointRef) return;
    refreshMonitorDetail(monitorWindow).catch((error) => notify("error", formatUserError(error)));
  }, [monitorDialogConfigId, monitorDialogEndpointRef, monitorWindow]);

  useEffect(() => {
    if (createDialog !== "managed" || managedCreateProtocol !== "wireguard" || udp2rawActive || mimicActive) return;
    setManagedCreateMtu(String(replaceLocalConfig?.mtu || replacePeerConfig?.mtu || 1420));
  }, [createDialog, managedCreateProtocol, replaceLocalConfig?.mtu, replacePeerConfig?.mtu, udp2rawActive, mimicActive]);

  useEffect(() => {
    if (!selectedNodeId || !selectedConfigId || !selectedNodeOnline) return;
    const nodeId = selectedNodeId;
    const configId = selectedConfigId;
    let cancelled = false;
    // 定时刷新当前 WireGuard 配置的运行状态。
    async function refreshRuntimeStatus() {
      try {
        await api<ConfigItem>(`/api/wireguard/configs/${configId}/refresh-status`, { method: "POST" });
        if (!cancelled) {
          await refreshConfigs(nodeId, configId);
        }
      } catch (error) {
        if (!cancelled) {
          notify("error", formatUserError(error));
        }
      }
    }
    void refreshRuntimeStatus();
    const timer = window.setInterval(() => {
      void refreshRuntimeStatus();
    }, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedNodeId, selectedConfigId, selectedNodeOnline]);

  useEffect(() => {
    if (!plan || !["confirmed", "dispatching", "running"].includes(plan.status)) return;
    const timer = window.setInterval(async () => {
      try {
        const updated = await api<ChangePlan>(`/api/change-plans/${plan.id}`);
        setPlan(updated);
        if (["succeeded", "failed", "cancelled"].includes(updated.status)) {
          notify(updated.status === "succeeded" ? "success" : "error", updated.status === "succeeded" ? "Agent 已完成部署任务。" : formatTaskResultForUser(updated.task_result, "Agent 任务执行失败"));
          window.clearInterval(timer);
        }
      } catch (error) {
        notify("error", formatUserError(error));
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [plan?.id, plan?.status]);

  // 创建节点后展示一次性 Agent 令牌，用户需要立即保存到节点配置中。
  async function createNode(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const controllerUrl = String(form.get("controller_url") || DEFAULT_CONTROLLER_URL).trim();
    const endpointIps = uniqueList([...nodeCreateEndpointIps, ...splitList(String(form.get("endpoint_ip_draft") || ""))]);
    if (endpointIps.length === 0) {
      throw new Error("请至少填写一个节点入口地址");
    }
    const result = await api<NodeCreateResult>("/api/nodes", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"),
        hostname: null,
        region: String(form.get("region") || "").trim() || null,
        management_ip: endpointIps[0] || null,
        public_ip: endpointIps[0] || null,
        endpoint_ips: endpointIps,
        topology_endpoint: String(form.get("topology_endpoint") || "").trim() || endpointIps[0] || null,
        github_proxy_url: null,
      }),
    });
    notify(
      "success",
      [
        `节点已创建，当前离线。节点 ID：${result.node.id}`,
        `Agent 令牌：${result.agent_token}`,
        `主控地址：${controllerUrl}`,
      ].join("\n"),
    );
    formElement.reset();
    setNodeCreateEndpointIps([]);
    setNodeCreateOpen(false);
    await refreshNodes();
    await refreshTopology();
    selectNodeId(null);
  }

  // 修改节点名称和入口地址；入口地址用于后续受管节点互联 Endpoint 选择。
  async function saveNode(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingNode) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const endpointIps = uniqueList([...editingNodeEndpointIps, ...splitList(String(form.get("endpoint_ip_draft") || ""))]);
    if (endpointIps.length === 0) {
      throw new Error("请至少填写一个节点入口地址");
    }
    const updated = await api<NodeItem>(`/api/nodes/${editingNode.id}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: form.get("name"),
        endpoint_ips: endpointIps,
        hostname: editingNode.hostname,
        region: String(form.get("region") || "").trim() || null,
        management_ip: endpointIps[0] || null,
        public_ip: endpointIps[0] || null,
        topology_endpoint: String(form.get("topology_endpoint") || "").trim() || endpointIps[0] || null,
        github_proxy_url: String(form.get("github_proxy_url") || "").trim() || null,
      }),
    });
    setNodes((items) => items.map((item) => item.id === updated.id ? updated : item));
    await refreshTopology();
    notify("success", "节点信息已保存。");
  }

  // 轮换后旧 Agent 令牌立即失效，编辑弹窗会展示新的令牌。
  async function rotateNodeToken() {
    if (!editingNode) return;
    const result = await api<NodeCreateResult>(`/api/nodes/${editingNode.id}/rotate-agent-token`, { method: "POST" });
    setNodes((items) => items.map((item) => item.id === result.node.id ? result.node : item));
    notify("success", "Agent 令牌已轮换，旧令牌已失效。");
  }

  // 删除当前编辑的节点，并在删除当前节点时清理选中状态。
  async function deleteEditingNode() {
    if (!editingNode) return;
    const nodeConfigCount = editingNode.id === selectedNodeId ? configs.length : null;
    if (nodeConfigCount !== null && nodeConfigCount > 0) {
      throw new Error("节点下仍有 WireGuard 配置，请先删除所有配置");
    }
    if (!window.confirm(`确认删除节点 ${editingNode.name}？删除后该节点 Agent 令牌会失效。`)) return;
    await api<{ status: string }>(`/api/nodes/${editingNode.id}`, { method: "DELETE" });
    if (selectedNodeId === editingNode.id) {
      selectNodeId(null);
      selectConfigId(null);
      setConfigs([]);
      setImportCandidates([]);
      setPlan(null);
    }
    setEditingNodeId(null);
    await refreshNodes();
    notify("success", "节点已删除。");
  }

  // 复制当前节点的 Agent 启动命令到剪贴板。
  async function copyAgentCommand() {
    if (!editingNode) return;
    const command = buildAgentCommand(editingNode, controllerUrl);
    if (!command) {
      throw new Error("当前节点没有可查看的 Agent 令牌，请先轮换令牌");
    }
    await navigator.clipboard.writeText(command);
    notify("success", "Agent 启动命令已复制。");
  }

  // 刷新指定节点的 Agent 升级计划。
  async function refreshAgentUpgradePlan(nodeId: number = editingNodeId || 0) {
    if (!nodeId) return;
    const data = await api<AgentUpgradePlan>(`/api/nodes/${nodeId}/agent/upgrade-plan`);
    setAgentUpgradePlan(data);
  }

  // 复制 Agent 手动升级命令到剪贴板。
  async function copyAgentUpgradeCommand() {
    if (!agentUpgradePlan?.manual_command) {
      throw new Error("当前没有可用的手动升级命令");
    }
    await navigator.clipboard.writeText(agentUpgradePlan.manual_command);
    notify("success", "Agent 升级命令已复制。");
  }

  // 请求节点 Agent 执行自升级任务。
  async function requestAgentUpgrade() {
    if (!editingNode || !agentUpgradePlan) return;
    if (agentUpgradePlan.upgrade_mode !== "self_upgrade") {
      throw new Error(agentUpgradePlan.reason || "当前节点不能一键升级");
    }
    const upgradeTaskKey = nodeActionKey(editingNode.id, "agent-upgrade-task");
    holdActionPending(upgradeTaskKey);
    try {
      const result = await api<TaskRequestResult>(`/api/nodes/${editingNode.id}/agent/upgrade`, {
        method: "POST",
        body: JSON.stringify({ target_version: agentUpgradePlan.target_version, force: false }),
      });
      notify("success", translateApiDetail(result.message));
      await refreshNodes();
      await refreshAgentUpgradePlan(editingNode.id);
      if (result.task_id) {
        await pollAgentUpgradeTask(result.task_id, editingNode.id);
      }
    } finally {
      releaseActionPending(upgradeTaskKey);
    }
  }

  // 请求节点安装 mimic 中间层。
  async function requestMimicInstall() {
    if (!editingNode) return;
    const status = mimicPluginStatus(editingNode);
    if (!status.installable) {
      throw new Error(status.detail);
    }
    const result = await api<TaskRequestResult>(`/api/nodes/${editingNode.id}/middleware/mimic/install`, {
      method: "POST",
    });
    notify("success", translateApiDetail(result.message));
    await refreshNodes();
    if (result.task_id) {
      await pollMiddlewareInstallTask(result.task_id, editingNode.id);
    }
  }

  // 轮询中间层安装任务直到完成或超时。
  async function pollMiddlewareInstallTask(taskId: number, nodeId: number) {
    for (let attempt = 0; attempt < AGENT_TASK_POLL_LIMIT; attempt += 1) {
      await sleep(TASK_POLL_INTERVAL_MS);
      const task = await api<AgentTaskStatus>(`/api/tasks/${taskId}`);
      await refreshNodes();
      if (task.status === "succeeded") {
        if (task.result?.reboot_required) {
          notify("info", "mimic 已安装，但需要重启节点进入新内核后生效。");
          return;
        }
        notify("success", "mimic 安装任务完成，等待 Agent 心跳刷新能力。");
        return;
      }
      if (task.status === "failed") {
        notify("error", formatTaskResultForUser(task.result, "mimic 安装失败"));
        return;
      }
    }
    notify("info", "mimic 安装任务仍在进行，请稍后刷新节点状态。");
  }

  // 轮询 Agent 升级任务直到完成或超时。
  async function pollAgentUpgradeTask(taskId: number, nodeId: number) {
    for (let attempt = 0; attempt < AGENT_TASK_POLL_LIMIT; attempt += 1) {
      await sleep(TASK_POLL_INTERVAL_MS);
      const task = await api<AgentTaskStatus>(`/api/tasks/${taskId}`);
      await refreshNodes();
      await refreshAgentUpgradePlan(nodeId);
      if (task.status === "succeeded") {
        notify("success", "Agent 升级已暂存，等待服务重启后上报新版本。");
        return;
      }
      if (task.status === "failed") {
        notify("error", formatTaskResultForUser(task.result, "Agent 升级失败"));
        return;
      }
    }
    notify("info", "Agent 升级任务仍在进行，请稍后刷新节点状态。");
  }

  // 创建或修改 WireGuard 点对点配置的期望状态，不会立刻改动节点。
  async function saveConfig(event: React.FormEvent<HTMLFormElement>, mode: "create" | "update") {
    event.preventDefault();
    if (!selectedNodeId) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能修改该节点的 WireGuard 配置");
    }
    const listenPort = optionalInt(form.get("listen_port"), "监听端口");
    const mtu = optionalInt(form.get("mtu"), "MTU") ?? 1420;
    const tunnelIps = splitList(String(form.get("tunnel_ips") || ""));
    if (!isValidCidrs(tunnelIps)) {
      throw new Error("接口地址必须使用 CIDR 格式，例如 10.42.0.1/24");
    }
    if (!isValidPort(listenPort)) {
      throw new Error("监听端口必须在 1-65535 之间");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (!isProbablyWireGuardKey(form.get("public_key")) || !isProbablyWireGuardKey(form.get("private_key"))) {
      throw new Error("WireGuard 密钥格式应为 44 位 base64 字符串");
    }
    const createPeerPublicKey = String(form.get("peer_public_key") || "").trim();
    const createPeerAllowedIps = splitList(String(form.get("peer_allowed_ips") || ""));
    const createPeerEndpointPort = optionalInt(form.get("peer_endpoint_port"), "对端入口端口");
    const createPeerKeepalive = optionalInt(form.get("peer_persistent_keepalive"), "对端保活间隔");
    if (mode === "create") {
      const hasCreatePeerData = Boolean(
        createPeerAllowedIps.length ||
        createPeerEndpointPort !== null ||
        createPeerKeepalive !== null ||
        String(form.get("peer_name") || "").trim() ||
        String(form.get("peer_preshared_key") || "").trim() ||
        String(form.get("peer_endpoint_host") || "").trim() ||
        String(form.get("peer_custom_config") || "").trim(),
      );
      if (hasCreatePeerData && !createPeerPublicKey) {
        throw new Error("填写 Peer 信息时必须填写对端公钥");
      }
      if (!isProbablyWireGuardKey(createPeerPublicKey)) {
        throw new Error("对端公钥格式应为 44 位 base64 字符串");
      }
      if (!isProbablyWireGuardKey(form.get("peer_preshared_key"))) {
        throw new Error("预共享密钥格式应为 44 位 base64 字符串");
      }
      if (!isValidCidrs(createPeerAllowedIps)) {
        throw new Error("允许路由必须使用 CIDR 格式，例如 172.20.0.0/14 或 fd00::/8");
      }
      if (!isValidPort(createPeerEndpointPort)) {
        throw new Error("入口端口必须留空，或填写 1-65535 之间的整数");
      }
      if (createPeerKeepalive !== null && (!Number.isInteger(createPeerKeepalive) || createPeerKeepalive < 0 || createPeerKeepalive > 65535)) {
        throw new Error("保活间隔必须是 0-65535 之间的整数");
      }
    }
    const payload = {
      name: form.get("name"),
      tunnel_ips: tunnelIps,
      listen_port: listenPort,
      private_key: form.get("private_key") || null,
      public_key: form.get("public_key") || null,
      mtu,
      table_name: form.get("table_name") || null,
      interface_custom_config: form.get("interface_custom_config") || null,
    };
    const item = mode === "update" && selectedConfigId
      ? await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        })
      : await api<ConfigItem>(`/api/nodes/${selectedNodeId}/wireguard/configs`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
    if (mode === "create" && createPeerPublicKey) {
      await api<PeerItem>(`/api/wireguard/configs/${item.id}/peer`, {
        method: "PUT",
        body: JSON.stringify({
          name: form.get("peer_name") || null,
          public_key: createPeerPublicKey,
          preshared_key: form.get("peer_preshared_key") || null,
          endpoint_host: form.get("peer_endpoint_host") || null,
          endpoint_port: createPeerEndpointPort,
          allowed_ips: createPeerAllowedIps,
          persistent_keepalive: createPeerKeepalive,
          peer_custom_config: form.get("peer_custom_config") || null,
        }),
      });
    }
    formElement.reset();
    await refreshConfigs(selectedNodeId, item.id, { forceSelect: mode === "create" });
    setPlan(null);
    if (mode === "create") {
      setCreateDialog(null);
    }
    notify("success", mode === "update" ? "WireGuard 配置已保存。" : "WireGuard 配置已添加。");
  }

  // 在两个受管节点之间创建双方配置；密钥由后端调用 wg 自动生成。
  async function createManagedLink(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能创建受管节点连接");
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const peerNodeId = Number(form.get("peer_node_id"));
    const localTunnelIps = splitList(String(form.get("local_tunnel_ips") || ""));
    const peerTunnelIps = splitList(String(form.get("peer_tunnel_ips") || ""));
    const localAllowedIps = splitList(String(form.get("local_allowed_ips") || ""));
    const peerAllowedIps = splitList(String(form.get("peer_allowed_ips") || ""));
    const localEndpointHost = String(form.get("local_endpoint_host") || "").trim();
    const peerEndpointHost = String(form.get("peer_endpoint_host") || "").trim();
    const localEndpointPort = optionalInt(form.get("local_endpoint_port"), "本端入口端口");
    const peerEndpointPort = optionalInt(form.get("peer_endpoint_port"), "对端入口端口");
    const localListenPort = optionalInt(form.get("local_listen_port"), "本端监听端口");
    const peerListenPort = optionalInt(form.get("peer_listen_port"), "对端监听端口");
    const mtu = optionalInt(form.get("mtu"), "MTU") ?? 1420;
    const udp2raw = middlewareType === "udp2raw" ? readUdp2RawForm(form, localListenPort, peerListenPort) : null;
    const mimic = middlewareType === "mimic" ? readMimicForm(form) : null;
    if (!peerNodeId || peerNodeId === selectedNodeId) {
      throw new Error("请选择另一个在线受管节点");
    }
    if (!isValidCidrs(localTunnelIps) || !isValidCidrs(peerTunnelIps)) {
      throw new Error("双方 IP 必须使用 CIDR 格式，例如 10.42.0.1/32");
    }
    if (!isValidCidrs(localAllowedIps) || !isValidCidrs(peerAllowedIps)) {
      throw new Error("允许路由必须使用 CIDR 格式，例如 10.42.0.2/32 或 192.168.10.0/24");
    }
    if (!isValidPort(localListenPort) || !isValidPort(peerListenPort)) {
      throw new Error("双方监听端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidPort(localEndpointPort) || !isValidPort(peerEndpointPort)) {
      throw new Error("双方入口端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (!localEndpointHost && !peerEndpointHost) {
      throw new Error("本端或对端至少需要填写一个入口地址");
    }
    validateUdp2RawForm(udp2raw, localListenPort, peerListenPort);
    validateMimicForm(mimic, localListenPort, peerListenPort, localEndpointHost, peerEndpointHost);
    if (replaceLocalConfigId && !replacePeerConfigId) {
      throw new Error("请选择对端的导入配置覆盖项");
    }
    const result = await api<{ local_interface: ConfigItem; peer_interface: ConfigItem }>(
      `/api/nodes/${selectedNodeId}/wireguard/managed-links`,
      {
        method: "POST",
        body: JSON.stringify({
          peer_node_id: peerNodeId,
          local_interface_name: form.get("local_interface_name"),
          peer_interface_name: form.get("peer_interface_name") || form.get("local_interface_name"),
          local_tunnel_ips: localTunnelIps,
          peer_tunnel_ips: peerTunnelIps,
          local_allowed_ips: localAllowedIps.length ? localAllowedIps : null,
          peer_allowed_ips: peerAllowedIps.length ? peerAllowedIps : null,
          local_endpoint_host: localEndpointHost || null,
          local_endpoint_port: localEndpointPort,
          peer_endpoint_host: peerEndpointHost || null,
          peer_endpoint_port: peerEndpointPort,
          local_listen_port: localListenPort,
          peer_listen_port: peerListenPort,
          mtu,
          table_name: form.get("table_name") || null,
          local_interface_custom_config: form.get("local_interface_custom_config") || null,
          local_peer_custom_config: form.get("local_peer_custom_config") || null,
          peer_interface_custom_config: form.get("peer_interface_custom_config") || null,
          peer_peer_custom_config: form.get("peer_peer_custom_config") || null,
          replace_local_interface_id: replaceLocalConfigId,
          replace_peer_interface_id: replacePeerConfigId,
          force_endpoint_mismatch: forceEndpointMismatch,
          udp2raw,
          mimic,
        }),
      },
    );
    formElement.reset();
    await refreshConfigs(selectedNodeId, result.local_interface.id, { forceSelect: true });
    setPlan(null);
    setManagedPeerNodeId(null);
    setReplaceLocalConfigId(null);
    setReplacePeerConfigId(null);
    setForceEndpointMismatch(false);
    setMiddlewareType("none");
    setUdp2rawEnabled(false);
    setMimicEnabled(false);
    setUdp2rawServerSide("peer");
    setManagedCreateProtocol("wireguard");
    setCreateDialog(null);
    [1000, 2500, 4500].forEach((delay) => {
      window.setTimeout(() => {
        void refreshConfigs(selectedNodeId, result.local_interface.id);
        if (selectedConfigIdRef.current === result.local_interface.id) {
          void refreshManagedLink(result.local_interface.id);
        }
      }, delay);
    });
    notify("success", `已创建 ${result.local_interface.name} / ${result.peer_interface.name}，两端部署和开机自启任务已下发。`);
  }

  // 从 GRE 表单读取两端通用参数，并在前端提前做基础校验。
  function readGreCommonPayload(form: FormData) {
    const localOuterIp = String(form.get("local_outer_ip") || "").trim();
    const peerOuterIp = String(form.get("peer_outer_ip") || "").trim();
    const localTunnelIps = splitList(String(form.get("local_tunnel_ips") || ""));
    const peerTunnelIps = splitList(String(form.get("peer_tunnel_ips") || ""));
    const localRoutes = splitList(String(form.get("local_routes") || ""));
    const peerRoutes = splitList(String(form.get("peer_routes") || ""));
    const mtu = optionalInt(form.get("mtu"), "MTU") ?? 1476;
    const ttl = optionalInt(form.get("ttl"), "TTL");
    const greKey = String(form.get("gre_key") || "").trim();
    if (!isValidIpv4Address(localOuterIp) || !isValidIpv4Address(peerOuterIp)) {
      throw new Error("GRE 外层地址必须填写 IPv4 字面量，不能使用域名或 IPv6");
    }
    if (localOuterIp === peerOuterIp) {
      throw new Error("GRE 双方外层地址不能相同");
    }
    if (!isValidIpv4Cidrs(localTunnelIps) || !isValidIpv4Cidrs(peerTunnelIps)) {
      throw new Error("GRE 隧道地址必须使用 IPv4 CIDR，例如 10.42.8.1/30");
    }
    if (!isValidIpv4Cidrs(localRoutes) || !isValidIpv4Cidrs(peerRoutes)) {
      throw new Error("经隧道路由必须使用 IPv4 CIDR，例如 10.77.0.0/24");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (ttl !== null && (!Number.isInteger(ttl) || ttl < 1 || ttl > 255)) {
      throw new Error("TTL 必须是 1-255 之间的整数");
    }
    if (ttl !== null && form.get("pmtudisc") !== "on") {
      throw new Error("填写 GRE TTL 时必须启用 PMTU discovery");
    }
    if (!isValidGreKey(greKey)) {
      throw new Error("GRE Key 必须是 0 到 4294967295 之间的整数");
    }
    return {
      local_interface_name: String(form.get("local_interface_name") || "").trim(),
      peer_interface_name: String(form.get("peer_interface_name") || "").trim(),
      local_outer_ip: localOuterIp,
      peer_outer_ip: peerOuterIp,
      local_tunnel_ips: localTunnelIps,
      peer_tunnel_ips: peerTunnelIps,
      local_routes: localRoutes,
      peer_routes: peerRoutes,
      mtu,
      gre_key: greKey || null,
      ttl,
      pmtudisc: form.get("pmtudisc") === "on",
      risk_accepted: form.get("risk_accepted") === "on",
    };
  }

  // 创建受管 GRE 连接，并让双方 Agent 部署后启动。
  async function createGreConnection(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedNodeId || !selectedNode) return;
    if (!nodeSupportsGre(selectedNode)) {
      throw new Error("当前节点尚未上报 GRE 能力，请安装 iproute2 或升级 Agent 后重试");
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const peerNodeId = Number(form.get("peer_node_id"));
    const peerNode = nodes.find((node) => node.id === peerNodeId) || null;
    if (!peerNode || peerNode.id === selectedNodeId) {
      throw new Error("请选择另一个支持 GRE 的在线节点");
    }
    if (!nodeSupportsGre(peerNode)) {
      throw new Error("对端节点尚未上报 GRE 能力，请安装 iproute2 或升级 Agent 后重试");
    }
    const payload = {
      protocol_type: "gre",
      peer_node_id: peerNodeId,
      ...readGreCommonPayload(form),
    };
    const connection = await api<ConnectionItem>(`/api/nodes/${selectedNodeId}/connections/managed`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setCreateDialog(null);
    setManagedCreateProtocol("wireguard");
    setManagedPeerNodeId(null);
    formElement.reset();
    selectConfigId(null);
    selectConnectionRef(connection.connection_ref);
    void Promise.all([refreshConnections(selectedNodeId), refreshTopology()]).catch((error) => notify("error", formatUserError(error)));
    notify("success", `GRE 连接 ${connection.name} 已创建，双方部署和启动任务已下发。`);
  }

  // 保存 GRE 连接修改，并重新下发双方配置。
  async function saveGreConnection(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedGreConnection || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能修改 GRE 连接");
    }
    await api<ConnectionItem>(`/api/connections/${encodedConnectionRef(selectedGreConnection.connection_ref)}`, {
      method: "PATCH",
      body: JSON.stringify(readGreCommonPayload(new FormData(event.currentTarget))),
    });
    await Promise.all([refreshConnections(selectedNodeId), refreshTopology()]);
    notify("success", "GRE 连接已保存，并已重新下发双方配置。");
  }

  // 启动当前选中的 GRE 连接。
  async function startSelectedGreConnection() {
    if (!selectedGreConnection || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能启动 GRE 连接");
    }
    await api<ConnectionItem>(`/api/connections/${encodedConnectionRef(selectedGreConnection.connection_ref)}/start`, { method: "POST" });
    await Promise.all([refreshConnections(selectedNodeId), refreshTopology()]);
    notify("success", "GRE 启动任务已创建，等待双方 Agent 执行。");
  }

  // 断开当前选中的 GRE 连接。
  async function stopSelectedGreConnection() {
    if (!selectedGreConnection || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能断开 GRE 连接");
    }
    await api<ConnectionItem>(`/api/connections/${encodedConnectionRef(selectedGreConnection.connection_ref)}/stop`, { method: "POST" });
    await Promise.all([refreshConnections(selectedNodeId), refreshTopology()]);
    notify("success", "GRE 断开任务已创建，等待双方 Agent 执行。");
  }

  // 删除当前选中的 GRE 连接，并清理双方节点上的 GRE 配置。
  async function deleteSelectedGreConnection() {
    if (!selectedGreConnection || !selectedNodeId) return;
    if (!window.confirm(`确认删除 GRE 连接 ${selectedGreConnection.name}？系统会下发双方清理任务。`)) return;
    await api<{ status: string }>(`/api/connections/${encodedConnectionRef(selectedGreConnection.connection_ref)}`, { method: "DELETE" });
    selectConnectionRef(null);
    await Promise.all([refreshConnections(selectedNodeId), refreshTopology()]);
    notify("success", "GRE 连接记录已删除，双方清理任务已下发。");
  }

  // 设置唯一对端后仍需生成并确认 Change Plan 才会部署。
  async function savePeer(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedConfigId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能保存或部署对端配置");
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const allowedIps = splitList(String(form.get("allowed_ips") || ""));
    const endpointPort = optionalInt(form.get("endpoint_port"), "入口端口");
    const keepalive = optionalInt(form.get("persistent_keepalive"), "保活间隔");
    if (!isProbablyWireGuardKey(form.get("public_key"))) {
      throw new Error("对端公钥格式应为 44 位 base64 字符串");
    }
    if (!isProbablyWireGuardKey(form.get("preshared_key"))) {
      throw new Error("预共享密钥格式应为 44 位 base64 字符串");
    }
    if (!isValidCidrs(allowedIps)) {
      throw new Error("允许路由必须使用 CIDR 格式，例如 10.42.0.2/32");
    }
    if (!isValidPort(endpointPort)) {
      throw new Error("入口端口必须在 1-65535 之间");
    }
    if (keepalive !== null && (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535)) {
      throw new Error("保活间隔必须是 0-65535 之间的整数");
    }
    await api<PeerItem>(`/api/wireguard/configs/${selectedConfigId}/peer`, {
      method: "PUT",
      body: JSON.stringify({
        name: form.get("name") || null,
        public_key: form.get("public_key"),
        preshared_key: form.get("preshared_key") || null,
        endpoint_host: form.get("endpoint_host") || null,
        endpoint_port: endpointPort,
        allowed_ips: allowedIps,
        persistent_keepalive: keepalive,
        peer_custom_config: form.get("peer_custom_config") || null,
      }),
    });
    formElement.reset();
    await refreshPeer(selectedConfigId);
    if (selectedNodeId) {
      await refreshConfigs(selectedNodeId, selectedConfigId);
    }
    notify("success", "对端已保存；生成并确认部署计划后才会下发到 Agent。");
  }

  // 保存受管连接双方配置，并直接下发双方部署任务。
  async function saveManagedLink(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能修改受管连接");
    }
    const form = new FormData(event.currentTarget);
    const localTunnelIps = splitList(String(form.get("local_tunnel_ips") || ""));
    const peerTunnelIps = splitList(String(form.get("peer_tunnel_ips") || ""));
    const localAllowedIps = splitList(String(form.get("local_allowed_ips") || ""));
    const peerAllowedIps = splitList(String(form.get("peer_allowed_ips") || ""));
    const localListenPort = optionalInt(form.get("local_listen_port"), "本端监听端口");
    const peerListenPort = optionalInt(form.get("peer_listen_port"), "对端监听端口");
    const localEndpointPort = optionalInt(form.get("local_endpoint_port"), "本端入口端口");
    const peerEndpointPort = optionalInt(form.get("peer_endpoint_port"), "对端入口端口");
    const localEndpointHost = String(form.get("local_endpoint_host") || "").trim();
    const peerEndpointHost = String(form.get("peer_endpoint_host") || "").trim();
    const keepalive = optionalInt(form.get("persistent_keepalive"), "保活间隔");
    const mtu = optionalInt(form.get("mtu"), "MTU") ?? 1420;
    const udp2raw = middlewareType === "udp2raw" ? readUdp2RawForm(form, localListenPort, peerListenPort) : null;
    const mimic = middlewareType === "mimic" ? readMimicForm(form) : null;
    if (!isValidCidrs(localTunnelIps) || !isValidCidrs(peerTunnelIps)) {
      throw new Error("双方 IP 必须使用 CIDR 格式，例如 10.42.0.1/32, fd42::1/64");
    }
    if (!isValidCidrs(localAllowedIps) || !isValidCidrs(peerAllowedIps)) {
      throw new Error("允许路由必须使用 CIDR 格式，例如 10.42.0.2/32 或 192.168.10.0/24");
    }
    if (!isValidPort(localListenPort) || !isValidPort(peerListenPort)) {
      throw new Error("双方监听端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidPort(localEndpointPort) || !isValidPort(peerEndpointPort)) {
      throw new Error("双方入口端口必须留空，或填写 1-65535 之间的整数");
    }
    if (!isValidMtu(mtu)) {
      throw new Error("MTU 必须是 576-9000 之间的整数");
    }
    if (!localEndpointHost && !peerEndpointHost) {
      throw new Error("本端或对端至少需要填写一个入口地址");
    }
    if (keepalive !== null && (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535)) {
      throw new Error("保活间隔必须是 0-65535 之间的整数");
    }
    validateUdp2RawForm(udp2raw, localListenPort, peerListenPort);
    validateMimicForm(mimic, localListenPort, peerListenPort, localEndpointHost, peerEndpointHost);
    const configId = selectedConfigId;
    await api<ManagedLink>(`/api/wireguard/configs/${configId}/managed-link`, {
      method: "PATCH",
      body: JSON.stringify({
        local_interface_name: form.get("local_interface_name"),
        peer_interface_name: form.get("peer_interface_name"),
        local_tunnel_ips: localTunnelIps,
        peer_tunnel_ips: peerTunnelIps,
        local_allowed_ips: localAllowedIps.length ? localAllowedIps : null,
        peer_allowed_ips: peerAllowedIps.length ? peerAllowedIps : null,
        local_endpoint_host: localEndpointHost || null,
        local_endpoint_port: localEndpointPort,
        peer_endpoint_host: peerEndpointHost || null,
        peer_endpoint_port: peerEndpointPort,
        local_listen_port: localListenPort,
        peer_listen_port: peerListenPort,
        mtu,
        table_name: form.get("table_name") || null,
        persistent_keepalive: keepalive,
        local_interface_custom_config: form.get("local_interface_custom_config") || null,
        local_peer_custom_config: form.get("local_peer_custom_config") || null,
        peer_interface_custom_config: form.get("peer_interface_custom_config") || null,
        peer_peer_custom_config: form.get("peer_peer_custom_config") || null,
        udp2raw,
        mimic,
      }),
    });
    await refreshConfigs(selectedNodeId, configId);
    [1000, 2500, 4500].forEach((delay) => {
      window.setTimeout(() => {
        void refreshConfigs(selectedNodeId, configId);
        if (selectedConfigIdRef.current === configId) {
          void refreshManagedLink(configId);
        }
      }, delay);
    });
    notify("success", "受管连接已保存，并已直接下发双方配置。");
  }

  // 生成部署计划，前端必须展示 diff 并由用户确认后才会创建 Agent 任务。
  async function createApplyPlan() {
    if (!selectedConfigId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能生成部署计划");
    }
    const data = await api<ChangePlan>(`/api/wireguard/configs/${selectedConfigId}/plan-apply`, {
      method: "POST",
    });
    setPlan(data);
    if (!data.diff.trim()) {
      notify("info", selectedConfig?.source === "imported" && !selectedConfig.managed
        ? "导入配置已使用节点现有 wg-quick 文件作为基线，无需重新下发。"
        : "当前配置与已部署配置一致，无需下发。");
    }
  }

  // 请求 Agent 读取节点上的当前配置，下一次部署计划会以此作为 diff 基线。
  async function refreshDeployedConfig() {
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能同步节点配置");
    }
    await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}/refresh-deployed`, { method: "POST" });
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", "已创建同步任务；稍后再次生成部署计划会使用节点当前配置作为基线。");
  }

  // 启动已部署的 WireGuard 接口。
  async function startSelectedConfig() {
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能启动 WireGuard 连接");
    }
    if (selectedConfigIsManagedLink) {
      await api<ManagedLink>(`/api/wireguard/configs/${selectedConfigId}/managed-link/start`, { method: "POST" });
    } else {
      await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}/start`, { method: "POST" });
    }
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", selectedConfigIsManagedLink ? "已创建双方启动任务，等待 Agent 执行。" : isConfigRunning ? "WireGuard 连接已经是已连接状态。" : "启动任务已创建，等待 Agent 执行。");
  }

  // 断开 WireGuard 接口；删除配置前必须先完成这一步。
  async function stopSelectedConfig() {
    if (!selectedConfigId || !selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能断开 WireGuard 连接");
    }
    if (selectedConfigIsManagedLink) {
      await api<ManagedLink>(`/api/wireguard/configs/${selectedConfigId}/managed-link/stop`, { method: "POST" });
    } else {
      await api<ConfigItem>(`/api/wireguard/configs/${selectedConfigId}/stop`, { method: "POST" });
    }
    await refreshConfigs(selectedNodeId, selectedConfigId);
    notify("success", selectedConfigIsManagedLink ? "已创建双方断开任务，等待 Agent 执行。" : isConfigStopped ? "WireGuard 连接已经是已断开状态。" : "断开任务已创建，等待 Agent 执行。");
  }

  // 打开删除确认弹窗，并在需要触碰节点时检查在线和停止状态。
  async function openDeleteDialog() {
    if (!selectedConfigId || !selectedNodeId || !selectedConfig) return;
    if (!selectedConfigIsUnmanagedImport && !selectedNodeOnline) {
      throw new Error("Agent 离线，不能删除 WireGuard 配置");
    }
    if (!selectedConfigIsUnmanagedImport && !isConfigStopped) {
      throw new Error("删除前必须先断开对应 WireGuard 连接");
    }
    setDeleteNodeConfig(false);
    setDeleteDialogOpen(true);
  }

  // 默认只删除 Link42 记录；用户勾选后才同步删除节点配置和服务。
  async function deleteSelectedConfig() {
    if (!selectedConfigId || !selectedNodeId || !selectedConfig) return;
    const query = deleteNodeConfig ? "?delete_node_config=true" : "";
    if (selectedConfigIsManagedLink) {
      await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}/managed-link${query}`, { method: "DELETE" });
    } else {
      await api<{ status: string }>(`/api/wireguard/configs/${selectedConfigId}${query}`, { method: "DELETE" });
    }
    setDeleteDialogOpen(false);
    setDeleteNodeConfig(false);
    selectConfigId(null);
    setPlan(null);
    await refreshConfigs(selectedNodeId, null);
    await refreshImportCandidates(selectedNodeId);
    notify("success", selectedConfigIsManagedLink
      ? (deleteNodeConfig ? "受管连接双方记录已删除，并已下发节点配置清理任务。" : "受管连接双方记录已删除，节点配置已保留。")
      : selectedConfigIsUnmanagedImport
        ? "导入观察记录已删除，节点原始配置文件未改动。"
        : (deleteNodeConfig ? "WireGuard 记录已删除，并已下发节点配置清理任务。" : "WireGuard 记录已删除，节点配置已保留。"));
  }

  // 确认计划会创建 Agent 任务，是配置下发前的安全闸门。
  async function confirmPlan() {
    if (!plan) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能确认部署计划");
    }
    if (!hasDeployDiff) {
      throw new Error("本次没有需要下发的配置变化");
    }
    const data = await api<ChangePlan>(`/api/change-plans/${plan.id}/confirm`, { method: "POST" });
    setPlan(data);
    notify("success", "部署任务已创建，等待 Agent 拉取执行。");
  }

  // 请求 Agent 扫描现有 wg-quick 配置；扫描不需要用户审 diff，直接创建任务。
  async function requestImportScan() {
    if (!selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能扫描节点配置");
    }
    const data = await api<TaskRequestResult>(`/api/nodes/${selectedNodeId}/wireguard/import-scan`, {
      method: "POST",
    });
    notify(
      "success",
      data.status === "pending" ? "扫描任务已创建，等待 Agent 执行。" : "扫描任务已在执行，正在等待结果。",
    );
    await refreshNodes();
    await refreshConfigs(selectedNodeId, selectedConfigId);
    await refreshImportCandidates(selectedNodeId);
    setImportCandidatesExpanded(true);
    if (data.task_id) {
      await pollImportScanTask(data.task_id, selectedNodeId);
    }
  }

  // 轮询导入扫描任务并刷新候选列表。
  async function pollImportScanTask(taskId: number, nodeId: number) {
    for (let attempt = 0; attempt < SHORT_TASK_POLL_LIMIT; attempt += 1) {
      await sleep(1000);
      const task = await api<AgentTaskStatus>(`/api/tasks/${taskId}`);
      await refreshNodes();
      await refreshConfigs(nodeId, selectedConfigId);
      await refreshImportCandidates(nodeId);
      if (task.status === "succeeded") {
        notify("success", "扫描完成，已刷新现有 wg-quick 候选和节点配置。");
        return;
      }
      if (task.status === "failed") {
        notify("error", formatTaskResultForUser(task.result, "扫描失败"));
        return;
      }
    }
    notify("info", "扫描任务仍在执行，页面已刷新；稍后可再次查看。");
  }

  // 导入候选只会写入数据库，默认仍是 unmanaged，不会覆盖节点配置。
  async function importCandidate(candidateId: number) {
    if (!selectedNodeId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能导入节点配置");
    }
    const item = await api<ConfigItem>(`/api/nodes/${selectedNodeId}/wireguard/import`, {
      method: "POST",
      body: JSON.stringify({ candidate_id: candidateId }),
    });
    notify("success", `已导入 ${item.name}，当前仍未接管管理。`);
    await refreshConfigs(selectedNodeId);
    await refreshImportCandidates(selectedNodeId);
    selectConfigId(item.id);
  }

  // 接管导入接口会生成计划；只有确认计划后才会备份并写入节点配置。
  async function takeOverConfig() {
    if (!selectedConfigId) return;
    if (!selectedNodeOnline) {
      throw new Error("Agent 离线，不能接管配置");
    }
    const data = await api<ChangePlan>(`/api/wireguard/configs/${selectedConfigId}/take-over`, {
      method: "POST",
    });
    setPlan(data);
    if (selectedNodeId) {
      await refreshConfigs(selectedNodeId, selectedConfigId);
    }
    if (!data.diff.trim()) {
      notify("success", "已接管现有 wg-quick 配置，未重写节点文件。");
    }
  }

  // 渲染普通或全屏模式下复用的拓扑画布。
  function renderTopologyCanvas(extraClassName = "") {
    return (
      <div className={extraClassName ? `topologyCanvas ${extraClassName}` : "topologyCanvas"}>
        {topology.nodes.length === 0 ? (
          <div className="empty">创建节点和受管连接后会显示拓扑。</div>
        ) : (
          <ReactFlow
            nodes={topologyFlowNodes}
            edges={topologyFlowEdges}
            fitView
            minZoom={0.2}
            maxZoom={1.8}
            nodesConnectable={false}
            onNodeClick={handleTopologyNodeClick}
            onNodeDrag={handleTopologyNodeDrag}
            onNodeDragStop={handleTopologyNodeDragStop}
            onEdgeClick={handleTopologyEdgeClick}
          >
            <Background color={topologyGridColor} gap={18} />
          </ReactFlow>
        )}
      </div>
    );
  }

  // 渲染 BIRD 文件树中的目录或文件节点。
  function renderBirdTreeNode({ node, style }: NodeRendererProps<BirdTreeItem>) {
    const item = node.data;
    const isFile = item.type === "file";
    const selected = isFile && item.resource?.resource_key === birdSelectedResource;
    const opening = isFile && item.resource?.resource_key === birdOpeningResource;
    const draft = isFile && item.resource ? birdDrafts[item.resource.resource_key] : null;
    const cached = Boolean(draft);
    const dirty = Boolean(draft && draft.content !== draft.originalContent);
    return (
      <div
        className={[
          "birdTreeNode",
          isFile ? "file" : "directory",
          selected ? "selected" : "",
          opening ? "loading" : "",
          dirty ? "dirty" : "",
          birdTreeLocked ? "locked" : "",
        ].filter(Boolean).join(" ")}
        style={style}
        onClick={() => {
          if (birdTreeLocked) return;
          if (isFile && item.resource) {
            void runAction(() => readBirdResource(item.resource!.resource_key), `plugin:bird:read:${item.resource.resource_key}`);
          } else {
            node.toggle();
          }
        }}
      >
        {isFile ? (
          <FileText size={15} />
        ) : node.isOpen ? (
          <ChevronDown size={15} />
        ) : (
          <ChevronRight size={15} />
        )}
        {!isFile && <Folder size={15} />}
        <span>
          <strong>{item.name}{dirty ? " *" : ""}</strong>
          {isFile && item.resource && (
            <small>
              {opening ? "打开中…" : `${item.path}${item.resource.is_main ? " / 主配置" : ""}${dirty ? " / 已修改" : cached ? " / 已缓存" : ""}`}
            </small>
          )}
        </span>
      </div>
    );
  }

  if (!authChecked) {
    return <main className="app loginPage" />;
  }

  if (!authToken) {
    return (
      <main className="app loginPage">
        <section className="loginPanel">
          <div className="loginBrand">
            <img src={siteLogoUrl || DEFAULT_SITE_LOGO_URL} alt="" />
            <h1>{siteTitle || DEFAULT_SITE_TITLE}</h1>
          </div>
          <p className="muted">主控访问登录</p>
          <form className="stack" onSubmit={(event) => void runAction(() => login(event), "auth:login")}>
            <Field label="用户名">
              <input name="username" defaultValue={settingsUsername} autoComplete="username" required onChange={() => setLoginError("")} />
            </Field>
            <Field label="密码">
              <input name="password" type="password" autoComplete="current-password" required onChange={() => setLoginError("")} />
            </Field>
            {loginError && <div className="formError" role="alert">{loginError}</div>}
            <button type="submit" disabled={actionPending("auth:login")}><Check size={16} /> {actionPending("auth:login") ? "登录中" : "登录"}</button>
          </form>
        </section>
        <div className="toastStack" aria-live="polite">
          {toasts.map((toast) => (
            <div key={toast.id} className={`toast ${toast.type}`}>
              {toast.text}
            </div>
          ))}
        </div>
      </main>
    );
  }

  return (
    <main className="app">
      <header className="topbar">
        <div className="brandBlock">
          <img className="brandLogo" src={siteLogoUrl || DEFAULT_SITE_LOGO_URL} alt="" />
          <div>
            <h1>{siteTitle || DEFAULT_SITE_TITLE}</h1>
            <p>WireGuard 点对点链路管理面板 / {currentUser || "pmman"}</p>
          </div>
        </div>
        <div className="topbarActions">
          <button
            className="iconButton"
            onClick={() => setTheme((value) => (value === "dark" ? "light" : "dark"))}
            title={theme === "dark" ? "切换到日间模式" : "切换到夜间模式"}
          >
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button className="iconButton" onClick={() => setSettingsOpen(true)} title="设置">
            <Settings size={18} />
          </button>
          <button className="iconButton" onClick={() => void runAction(refreshHome)} title="刷新">
            <RefreshCw size={18} />
          </button>
          <button className="iconButton" onClick={() => void runAction(logout)} title="退出">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <div className="toastStack" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast ${toast.type}`}>
            {toast.text}
          </div>
        ))}
      </div>

      {topologyFullscreenOpen && (
        <div className="modalBackdrop topologyFullscreenBackdrop" role="presentation">
          <section className="modalPanel topologyFullscreenModal" role="dialog" aria-modal="true" aria-labelledby="topology-fullscreen-title">
            <header className="modalHeader topologyFullscreenHeader">
              <div>
                <h2 id="topology-fullscreen-title"><GitBranch size={18} /> 拓扑图</h2>
                <p className="muted">{topology.nodes.length} 个节点 / {topology.edges.length} 条链路；拖动节点可保存位置。</p>
              </div>
              <div className="topologyToolbar">
                <button
                  className="secondary"
                  type="button"
                  disabled={actionPending("topology:reset")}
                  onClick={() => setTopologyResetConfirmOpen(true)}
                >
                  <RefreshCw size={16} /> {actionPending("topology:reset") ? "还原中" : "还原拓扑"}
                </button>
                <button className="iconButton" onClick={() => setTopologyFullscreenOpen(false)} title="关闭">
                  <X size={18} />
                </button>
              </div>
            </header>
            {renderTopologyCanvas("topologyCanvasFullscreen")}
          </section>
        </div>
      )}

      {topologyResetConfirmOpen && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="topology-reset-title">
            <header className="modalHeader">
              <div>
                <h2 id="topology-reset-title"><RefreshCw size={18} /> 还原拓扑</h2>
                <p className="muted">这会清空所有节点的自定义拓扑位置，并重新使用自动布局。</p>
              </div>
              <button className="iconButton" onClick={() => setTopologyResetConfirmOpen(false)} disabled={actionPending("topology:reset")}>
                <X size={18} />
              </button>
            </header>
            <div className="actionRow">
              <button className="secondary" onClick={() => setTopologyResetConfirmOpen(false)} disabled={actionPending("topology:reset")}>取消</button>
              <button className="danger" disabled={actionPending("topology:reset")} onClick={() => void runAction(resetTopologyLayout, "topology:reset")}>
                <RefreshCw size={16} /> {actionPending("topology:reset") ? "还原中" : "确认还原"}
              </button>
            </div>
          </section>
        </div>
      )}

      {nodePluginDialogOpen && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel nodePluginModal" role="dialog" aria-modal="true" aria-labelledby="node-plugin-title">
            <header className="modalHeader">
              <div>
                <h2 id="node-plugin-title"><Plug size={18} /> 节点插件</h2>
                <p className="muted">{selectedNode.name} / {selectedNodeOnline ? "在线" : "离线"}</p>
              </div>
              <button className="iconButton" onClick={closeNodePluginDialog} title="关闭">
                <X size={18} />
              </button>
            </header>

            <div className="nodePluginTabs" role="tablist" aria-label="节点插件">
              {nodePlugins.map((plugin) => (
                <button
                  key={plugin.type}
                  type="button"
                  role="tab"
                  className={plugin.type === activeNodePlugin?.type ? "nodePluginTab active" : "nodePluginTab"}
                  aria-selected={plugin.type === activeNodePlugin?.type}
                  onClick={() => switchNodePluginTab(plugin.type)}
                >
                  <span>{plugin.display_name}</span>
                  <small>{plugin.available ? "可用" : "不可用"}</small>
                </button>
              ))}
            </div>

            {activeNodePlugin && !activeNodePlugin.available && (
              <div className="empty">
                {!activeNodePlugin.version_supported
                  ? `Agent 版本过低：当前 ${activeNodePlugin.agent_version || "未知"}，需要 ${activeNodePlugin.min_agent_version} 或更高。`
                  : `缺少能力：${activeNodePlugin.missing_capabilities.join(", ") || "未知"}；可能需要升级 Agent。`}
              </div>
            )}

            {activeNodePlugin?.type === "bird" && (
              <div className="nodePluginBird">
                <div className="actionRow">
                  <button
                    type="button"
                    className="secondary"
                    disabled={!birdPlugin?.available || !selectedNodeOnline || actionPending("plugin:bird:list")}
                    onClick={() => void runAction(() => listBirdResources({ confirmDiscard: true, clearDrafts: true }), "plugin:bird:list")}
                  >
                    <RefreshCw size={16} /> {actionPending("plugin:bird:list") ? "读取中" : "刷新配置树"}
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    disabled={!birdPlugin?.available || !selectedNodeOnline || !birdSelectedResource || actionPending("plugin:bird:validate")}
                    onClick={() => void runAction(validateBirdResource, "plugin:bird:validate")}
                  >
                    <Check size={16} /> {actionPending("plugin:bird:validate") ? "校验中" : "校验"}
                  </button>
                  <button
                    type="button"
                    disabled={
                      !birdPlugin?.available ||
                      !selectedNodeOnline ||
                      birdDirtyDrafts.length === 0 ||
                      actionPending("plugin:bird:list") ||
                      actionPending("plugin:bird:apply")
                    }
                    onClick={() => void runAction(applyBirdResources, "plugin:bird:apply")}
                  >
                    <Upload size={16} /> {actionPending("plugin:bird:apply") ? "保存中" : `保存并刷新${birdDirtyDrafts.length ? ` (${birdDirtyDrafts.length})` : ""}`}
                  </button>
                </div>

                <div className="birdEditor">
                  <aside className="birdFileManager" aria-label="BIRD 配置文件">
                    <div className="birdFileManagerHeader">
                      <strong>配置文件</strong>
                      <small>{birdResources.length} 个</small>
                    </div>
                    {actionPending("plugin:bird:list") ? (
                      <div className="empty">正在读取配置树...</div>
                    ) : birdResources.length === 0 ? (
                      <div className="empty">未发现可编辑的 BIRD 配置文件。</div>
                    ) : (
                      <div className="birdFileTree">
                        <Tree<BirdTreeItem>
                          data={birdFileTree}
                          idAccessor="id"
                          childrenAccessor="children"
                          rowHeight={42}
                          height={470}
                          width="100%"
                          indent={18}
                          openByDefault={false}
                          selection={birdSelectedResource}
                          disableDrag
                          disableDrop
                          disableEdit
                        >
                          {renderBirdTreeNode}
                        </Tree>
                      </div>
                    )}
                  </aside>

                  <section className="birdEditorPane">
                    {birdSelectedResource ? (
                      <>
                        <div className="birdEditorToolbar">
                          <label>
                            <span>语言模式</span>
                            <select value={birdEditorSyntax} onChange={(event) => setBirdEditorSyntax(event.currentTarget.value as "bird" | "plain")}>
                              <option value="bird">BIRD 配置</option>
                              <option value="plain">纯文本</option>
                            </select>
                          </label>
                          <label>
                            <input type="checkbox" checked={birdEditorLineNumbers} onChange={(event) => setBirdEditorLineNumbers(event.currentTarget.checked)} />
                            <span>行号</span>
                          </label>
                          <label>
                            <input type="checkbox" checked={birdEditorLineWrapping} onChange={(event) => setBirdEditorLineWrapping(event.currentTarget.checked)} />
                            <span>折行</span>
                          </label>
                          <label>
                            <input type="checkbox" checked={birdEditorFoldGutter} onChange={(event) => setBirdEditorFoldGutter(event.currentTarget.checked)} />
                            <span>折叠</span>
                          </label>
                          <label>
                            <input type="checkbox" checked={birdEditorAutocompletion} onChange={(event) => setBirdEditorAutocompletion(event.currentTarget.checked)} />
                            <span>补全</span>
                          </label>
                        </div>
                        <Field label="配置内容" hint={birdSelectedDirectory} wide>
                          <div onKeyDownCapture={handleBirdEditorKeyDown}>
                            <CodeMirror
                              className="birdConfigEditor"
                              value={birdContent}
                              height="520px"
                              basicSetup={{
                                lineNumbers: birdEditorLineNumbers,
                                highlightActiveLine: true,
                                highlightActiveLineGutter: true,
                                foldGutter: birdEditorFoldGutter,
                                autocompletion: birdEditorAutocompletion,
                                bracketMatching: true,
                                closeBrackets: true,
                                searchKeymap: true,
                              }}
                              extensions={birdEditorExtensions}
                              theme={theme}
                              editable={Boolean(birdPlugin?.available && selectedNodeOnline && birdSelectedResource && !birdOpeningResource)}
                              onChange={(value) => {
                                if (!birdSelectedResource) return;
                                setBirdDrafts((current) => {
                                  const draft = current[birdSelectedResource];
                                  if (!draft) return current;
                                  return {
                                    ...current,
                                    [birdSelectedResource]: {
                                      ...draft,
                                      content: value,
                                    },
                                  };
                                });
                              }}
                            />
                          </div>
                        </Field>
                      </>
                    ) : (
                      <div className="empty birdSelectHint">配置树读取完成后，请从左侧选择一个配置文件打开。</div>
                    )}
                  </section>
                </div>
              </div>
            )}

            {activeNodePlugin?.type === "port-inventory" && (
              <div className="portInventoryPlugin">
                {actionPending("plugin:port-inventory:load") && !portInventory && (
                  <div className="empty">正在读取端口台账...</div>
                )}
                <section className="portInventoryPanel">
                  <div className="portInventoryPanelHeader">
                    <div>
                      <h3>端口范围</h3>
                      <p>为该节点维护一个可用入口端口段，并按需扫描占用情况。</p>
                    </div>
                    <span className={portInventoryPlugin?.available && selectedNodeOnline ? "portInventoryState ready" : "portInventoryState"}>
                      {portInventoryPlugin?.available && selectedNodeOnline ? "可扫描" : "不可扫描"}
                    </span>
                  </div>
                  <div className="portInventoryRange">
                    <Field label="起始端口" requiredMark>
                      <input value={portRangeStart} onChange={(event) => setPortRangeStart(event.currentTarget.value)} placeholder="23000" inputMode="numeric" />
                    </Field>
                    <Field label="结束端口" requiredMark>
                      <input value={portRangeEnd} onChange={(event) => setPortRangeEnd(event.currentTarget.value)} placeholder="23099" inputMode="numeric" />
                    </Field>
                    <div className="portInventoryActions">
                      <button type="button" disabled={actionPending("plugin:port-inventory:range")} onClick={() => void runAction(() => savePortInventoryRange({ askScan: true }), "plugin:port-inventory:range")}>
                        <Check size={16} /> 保存范围
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        disabled={!portInventoryPlugin?.available || !selectedNodeOnline || actionPending("plugin:port-inventory:scan")}
                        onClick={() => void runAction(scanPortInventory, "plugin:port-inventory:scan")}
                      >
                        <RefreshCw size={16} /> {actionPending("plugin:port-inventory:scan") ? "扫描中" : "扫描占用"}
                      </button>
                    </div>
                  </div>
                </section>

                {portScanResults.length > 0 && (
                  <section className="portInventoryPanel">
                    <div className="portInventoryPanelHeader">
                      <div>
                        <h3>扫描结果</h3>
                        <p>检测到的占用端口不会自动写入台账，确认后再登记。</p>
                      </div>
                      <span className="portInventoryCount">{portScanResults.length} 个</span>
                    </div>
                    <div className="portInventoryList">
                      {portScanResults.map((result, index) => {
                        // 判断扫描结果是否已经登记在端口台账中。
                        const exists = (portInventory?.entries || []).some((entry) => entry.protocol === result.protocol && entry.port === result.port);
                        return (
                          <div className="portInventoryScanRow" key={`${result.protocol}-${result.port}-${result.detected_source || index}`}>
                            <div className="portInventoryPort">
                              <span>{result.protocol}</span>
                              <strong>{result.port}</strong>
                            </div>
                            <div className="portInventoryMeta">
                              <strong>{result.detected_process || "未知进程"}</strong>
                              <small>{portSourceLabel(result.detected_source || "socket")}</small>
                            </div>
                            <button
                              type="button"
                              className="secondary"
                              disabled={exists || actionPending(`plugin:port-inventory:add:${result.protocol}:${result.port}`)}
                              onClick={() => void runAction(() => createPortInventoryEntry(result), `plugin:port-inventory:add:${result.protocol}:${result.port}`)}
                            >
                              <Plus size={15} /> {exists ? "已登记" : "登记"}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </section>
                )}

                <section className="portInventoryPanel">
                  <div className="portInventoryPanelHeader">
                    <div>
                      <h3>端口记录</h3>
                      <p>记录真实用途，后续通过端口号或用途快速查找。</p>
                    </div>
                    <input className="portInventorySearch" value={portSearch} onChange={(event) => setPortSearch(event.currentTarget.value)} placeholder="搜索端口、用途、来源" />
                  </div>
                  <form className="portInventoryEntryForm" onSubmit={(event) => void runAction(() => createManualPortInventoryEntry(event), "plugin:port-inventory:create")}>
                    <select name="protocol" defaultValue="TCP">
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                    </select>
                    <input name="port" placeholder="端口" inputMode="numeric" required />
                    <input name="purpose" placeholder="用途" />
                    <button type="submit" disabled={actionPending("plugin:port-inventory:create")}><Plus size={16} /> 添加条目</button>
                  </form>
                  <div className="portInventoryList">
                    {filteredPortEntries.length > 0 && (
                      <div className="portInventoryListHead">
                        <span>端口</span>
                        <span>用途</span>
                        <span>来源</span>
                        <span />
                      </div>
                    )}
                    {filteredPortEntries.length === 0 ? (
                      <div className="empty">暂无端口记录。</div>
                    ) : pagedPortEntries.map((entry) => (
                      <div className="portInventoryRow" key={entry.id}>
                        <div className="portInventoryPort">
                          <span>{entry.protocol}</span>
                          <strong>{entry.port}</strong>
                        </div>
                        <input
                          value={entry.purpose || ""}
                          onChange={(event) => {
                            const purpose = event.currentTarget.value;
                            setPortInventory((current) => current ? {
                              ...current,
                              entries: current.entries.map((item) => item.id === entry.id ? { ...item, purpose } : item),
                            } : current);
                          }}
                          onBlur={(event) => void runAction(() => updatePortInventoryEntryPurpose(entry, event.currentTarget.value), `plugin:port-inventory:update:${entry.id}`)}
                          placeholder="填写用途"
                        />
                        <div className="portInventoryMeta">
                          <strong>{entry.detected_process || portSourceLabel(entry.source)}</strong>
                          <small>{portSourceLabel(entry.detected_source || entry.source)}</small>
                        </div>
                        <button type="button" className="danger" onClick={() => void runAction(() => deletePortInventoryEntry(entry), `plugin:port-inventory:delete:${entry.id}`)}>
                          <X size={15} /> 删除
                        </button>
                      </div>
                    ))}
                  </div>
                  {filteredPortEntries.length > PORT_INVENTORY_PAGE_SIZE && (
                    <div className="portInventoryPagination">
                      <span>
                        第 {Math.min(portInventoryPage, portInventoryPageCount)} / {portInventoryPageCount} 页，
                        共 {filteredPortEntries.length} 条
                      </span>
                      <div>
                        <button
                          type="button"
                          className="secondary"
                          disabled={portInventoryPage <= 1}
                          onClick={() => setPortInventoryPage((page) => Math.max(1, page - 1))}
                        >
                          上一页
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          disabled={portInventoryPage >= portInventoryPageCount}
                          onClick={() => setPortInventoryPage((page) => Math.min(portInventoryPageCount, page + 1))}
                        >
                          下一页
                        </button>
                      </div>
                    </div>
                  )}
                </section>
              </div>
            )}
          </section>
        </div>
      )}

      {nodePluginError && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="node-plugin-error-title">
            <header className="modalHeader">
              <div>
                <h2 id="node-plugin-error-title"><X size={18} /> 插件执行失败</h2>
                <p className="muted">请根据错误信息调整配置后重试。</p>
              </div>
              <button className="iconButton" onClick={() => setNodePluginError("")} title="关闭">
                <X size={18} />
              </button>
            </header>
            <pre className="errorDetail">{nodePluginError}</pre>
            <div className="actionRow">
              <button type="button" onClick={() => setNodePluginError("")}>知道了</button>
            </div>
          </section>
        </div>
      )}

      {settingsOpen && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
            <header className="modalHeader">
              <div>
                <h2 id="settings-title"><Settings size={18} /> 系统设置</h2>
                <p className="muted">主控访问地址用于生成 Agent 安装命令；账号用于登录面板。</p>
              </div>
              <button className="iconButton" onClick={() => setSettingsOpen(false)}>
                <X size={18} />
              </button>
            </header>
            <form className="stack" onSubmit={(event) => void runAction(() => saveSettings(event), "settings:save")}>
              <Field label="主控访问地址" hint="Agent 节点能访问到的 URL，例如 http://192.168.123.20:8000。">
                <input name="controller_url" defaultValue={controllerUrl} placeholder={DEFAULT_CONTROLLER_URL} required />
              </Field>
              <Field label="用户名">
                <input name="username" defaultValue={settingsUsername} required />
              </Field>
              <Field label="站点标题" hint="展示在浏览器标题、登录页和顶部栏。">
                <input name="site_title" defaultValue={siteTitle} required />
              </Field>
              <Field label="Logo" hint="上传 PNG、JPEG 或 WebP；文件会保存到主控配置目录，Docker 映射后可持久化。">
                <div className="logoUploadField">
                  <img src={settingsLogoPreviewUrl || siteLogoUrl || DEFAULT_SITE_LOGO_URL} alt="" />
                  <input name="site_logo_file" type="file" accept="image/png,image/jpeg,image/webp" onChange={previewLogoFile} />
                </div>
              </Field>
              <Field label="新密码" hint="留空表示不修改密码。">
                <input name="new_password" type="password" autoComplete="new-password" minLength={6} />
              </Field>
              <button type="submit" disabled={actionPending("settings:save")}><Check size={16} /> {actionPending("settings:save") ? "保存中" : "保存设置"}</button>
            </form>
          </section>
        </div>
      )}

      {nodeCreateOpen && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="node-create-title">
            <header className="modalHeader">
              <div>
                <h2 id="node-create-title"><Server size={18} /> 添加节点</h2>
                <p className="muted">入口地址会用于受管节点之间互联时选择连接地址。</p>
              </div>
              <button className="iconButton" onClick={() => setNodeCreateOpen(false)}>
                <X size={18} />
              </button>
            </header>
            <form onSubmit={(event) => void runAction(() => createNode(event), "node:create")} className="gridForm">
              <Field label="节点名称" hint="用于在控制台识别这个 Agent。">
                <input name="name" placeholder="node-a" required />
              </Field>
              <Field label="主控地址" hint="Agent 安装时连接的 Link42 API 地址。">
                <input name="controller_url" placeholder="http://192.168.123.20:8000" defaultValue={controllerUrl} required />
              </Field>
              <Field label="入口地址" hint="可添加公网 IP、内网 IP 或域名；后续受管连接会从这里选择连接地址。" wide requiredMark>
                <EndpointListInput
                  value={nodeCreateEndpointIps}
                  onChange={setNodeCreateEndpointIps}
                  placeholder="203.0.113.10"
                  onDuplicate={(endpoint) => notify("info", `已有该入口地址：${endpoint}`)}
                />
              </Field>
              <Field label="节点地域" hint="拓扑图展示的地域，例如 广州 / 东京 / HomeLab。">
                <input name="region" placeholder="广州" />
              </Field>
              <Field label="拓扑展示地址" hint="拓扑图展示的本机地址；留空使用第一个入口地址。">
                <input name="topology_endpoint" placeholder="10.10.0.1" />
              </Field>
              <button type="submit" disabled={actionPending("node:create")}><Plus size={16} /> {actionPending("node:create") ? "创建中" : "创建节点"}</button>
            </form>
          </section>
        </div>
      )}

      {editingNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="node-edit-title">
            <header className="modalHeader">
              <div>
                <h2 id="node-edit-title"><Server size={18} /> 节点设置</h2>
                <p className="muted">节点 ID：{editingNode.id} / {nodeStatusLabel(editingNode.status)}</p>
              </div>
              <button className="iconButton" onClick={() => setEditingNodeId(null)}>
                <X size={18} />
              </button>
            </header>
            <form key={`node-edit-${editingNode.id}`} onSubmit={(event) => void runAction(() => saveNode(event), nodeActionKey(editingNode.id, "save"))} className="gridForm">
              <Field label="节点名称" hint="修改后会同步显示在节点列表。">
                <input name="name" placeholder="node-a" defaultValue={editingNode.name} required />
              </Field>
              <Field label="节点地域" hint="拓扑图展示的地域，例如 广州 / 东京 / HomeLab。">
                <input name="region" placeholder="广州" defaultValue={editingNode.region || ""} />
              </Field>
              <Field label="入口地址" hint="可添加公网 IP、内网 IP 或域名；受管连接会校验所选地址属于节点。" wide requiredMark>
                <EndpointListInput
                  value={editingNodeEndpointIps}
                  onChange={setEditingNodeEndpointIps}
                  placeholder="203.0.113.10"
                  onDuplicate={(endpoint) => notify("info", `已有该入口地址：${endpoint}`)}
                />
              </Field>
              <Field label="拓扑展示地址" hint="选择或输入拓扑节点卡片展示的本机地址；留空使用第一个入口地址。" wide>
                <EndpointSelect
                  name="topology_endpoint"
                  options={endpointOptionsFrom(null, editingNodeEndpointIps, editingNode.topology_endpoint)}
                  defaultValue={editingNode.topology_endpoint || ""}
                  placeholder="选择或输入展示地址"
                />
              </Field>
              <Field label="GitHub 代理 URL" hint="Agent 安装 GitHub 发布资产时使用；留空则直连 GitHub。" wide>
                <input name="github_proxy_url" placeholder="https://gh-proxy.example.com/" defaultValue={editingNode.github_proxy_url || ""} />
              </Field>
              <button type="submit" disabled={actionPending(nodeActionKey(editingNode.id, "save"))}><Check size={16} /> {actionPending(nodeActionKey(editingNode.id, "save")) ? "保存中" : "保存节点"}</button>
            </form>
            <section className="modalSection">
              <h3>中间层插件</h3>
              <div className="pluginStatus">
                <div>
                  <strong>mimic</strong>
                  <p className="muted">{editingNodeMimicStatus.detail}</p>
                  <small>状态：{editingNodeMimicStatus.label} / 安装来源：GitHub 最新发布版本</small>
                </div>
                <button
                  className="secondary"
                  disabled={!editingNodeMimicStatus.installable || actionPending(nodeActionKey(editingNode.id, "mimic-install"))}
                  onClick={() => void runAction(requestMimicInstall, nodeActionKey(editingNode.id, "mimic-install"))}
                >
                  <Upload size={16} /> {editingNodeMimicStatus.rebootRequired ? "需要重启后生效" : actionPending(nodeActionKey(editingNode.id, "mimic-install")) ? "安装中" : "安装最新版"}
                </button>
              </div>
            </section>
            <section className="modalSection">
              <h3>Agent 令牌</h3>
              {editingNode.agent_token_value ? (
                <pre className="tokenBox">{editingNode.agent_token_value}</pre>
              ) : (
                <div className="empty">该节点创建时未保存明文令牌，请轮换后查看。</div>
              )}
              <div className="empty">
                Agent {editingNode.agent_version || "未知版本"} / {nodeSystemLabel(editingNode)}
                <br />
                {(editingNode.agent_capabilities || []).join(", ") || "尚未上报能力"}
              </div>
              <pre className="tokenBox">{buildAgentCommand(editingNode, controllerUrl) || "轮换令牌后显示 Agent 启动命令。"}</pre>
              <div className="actionRow">
                <button className="secondary" onClick={() => void runAction(copyAgentCommand)}>复制启动命令</button>
                <button className="danger" disabled={actionPending(nodeActionKey(editingNode.id, "rotate-token"))} onClick={() => void runAction(rotateNodeToken, nodeActionKey(editingNode.id, "rotate-token"))}>轮换令牌</button>
              </div>
            </section>
            <section className="modalSection">
              <h3>Agent 升级</h3>
              {agentUpgradePlan ? (
                <>
                  <div className="empty">
                    当前版本：{agentUpgradePlan.current_version || editingNode.agent_version || "未知"}
                    <br />
                    目标版本：{agentUpgradePlan.target_version || "无可用版本"}
                    <br />
                    升级状态：{workflowStatusLabel(agentUpgradePlan.status || editingNode.agent_update_status || "未开始")}
                    {agentUpgradePlan.matched_platform && (
                      <>
                        <br />
                        匹配资产：{agentUpgradePlan.matched_platform}
                      </>
                    )}
                    {agentUpgradePlan.reason && (
                      <>
                        <br />
                        {translateApiDetail(agentUpgradePlan.reason)}
                      </>
                    )}
                  </div>
                  <div className="actionRow">
                    <button
                      className="secondary"
                      disabled={actionPending(nodeActionKey(editingNode.id, "refresh-upgrade-plan"))}
                      onClick={() => void runAction(() => refreshAgentUpgradePlan(editingNode.id), nodeActionKey(editingNode.id, "refresh-upgrade-plan"))}
                    >
                      <RefreshCw size={16} /> {actionPending(nodeActionKey(editingNode.id, "refresh-upgrade-plan")) ? "刷新中" : "刷新升级计划"}
                    </button>
                    {agentUpgradePlan.upgrade_mode === "self_upgrade" ? (
                      <button
                        disabled={actionPending(nodeActionKey(editingNode.id, "agent-upgrade")) || actionPending(nodeActionKey(editingNode.id, "agent-upgrade-task"))}
                        onClick={() => void runAction(requestAgentUpgrade, nodeActionKey(editingNode.id, "agent-upgrade"))}
                      >
                        <Upload size={16} /> {actionPending(nodeActionKey(editingNode.id, "agent-upgrade")) || actionPending(nodeActionKey(editingNode.id, "agent-upgrade-task")) ? "升级中" : "一键升级"}
                      </button>
                    ) : (
                      <button className="secondary" disabled={!agentUpgradePlan.manual_command} onClick={() => void runAction(copyAgentUpgradeCommand)}>
                        复制升级命令
                      </button>
                    )}
                  </div>
                  {agentUpgradePlan.manual_command && (
                    <pre className="tokenBox">{agentUpgradePlan.manual_command}</pre>
                  )}
                  {editingNode.agent_last_error && <div className="empty">上次错误：{translateTaskText(editingNode.agent_last_error)}</div>}
                </>
              ) : (
                <div className="empty">正在读取 Agent 升级计划。</div>
              )}
            </section>
            <section className="modalSection dangerZone">
              <h3>删除节点</h3>
              <p className="muted">只有节点下所有 WireGuard 配置都已删除时，才允许删除节点。</p>
              <button className="danger" disabled={actionPending(nodeActionKey(editingNode.id, "delete"))} onClick={() => void runAction(deleteEditingNode, nodeActionKey(editingNode.id, "delete"))}>
                删除节点
              </button>
            </section>
          </section>
        </div>
      )}

      {createDialog === "external" && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="manual-link-title">
            <header className="modalHeader">
              <div>
                <h2 id="manual-link-title"><Plus size={18} /> 手动创建连接</h2>
                <p className="muted">{selectedNode.name} 连接到非受管节点。可在创建时直接填写 Peer，随后生成部署计划。</p>
              </div>
              <button className="iconButton" onClick={() => setCreateDialog(null)}>
                <X size={18} />
              </button>
            </header>
            <form
              key={`create-config-modal-${selectedNode.id}`}
              onSubmit={(event) => void runAction(() => saveConfig(event, "create"), nodeActionKey(selectedNode.id, "create-config"))}
              className="gridForm describedForm"
            >
              <Field label="接口名称" hint="节点上的 wg-quick 接口名，例如 wg0。">
                <input name="name" placeholder="wg0" required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端隧道地址" hint="CIDR 格式，多个地址用逗号分隔。">
                <input name="tunnel_ips" placeholder="10.42.0.1/24" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="监听端口" hint="UDP 端口，留空表示不写 ListenPort。">
                <input name="listen_port" placeholder="51820" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="MTU" hint="链路 MTU，默认 1420。">
                <input name="mtu" placeholder="1420" defaultValue="1420" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                <RouteModeSelect disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端公钥" hint="可选；用于记录和展示，44 位 base64。">
                <input name="public_key" placeholder="粘贴本端公钥" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端私钥" hint="可选；可信面板会明文保存并渲染到本机配置。" wide>
                <textarea name="private_key" placeholder="粘贴本端私钥" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="接口高级配置" hint="逐行写入 [Interface] 后，例如 PostUp/PostDown。保存前请确认这些配置行能被 WireGuard 识别。" wide>
                <textarea name="interface_custom_config" placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端名称" hint="可选，仅用于界面识别。">
                <input name="peer_name" placeholder="对端名称" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端公钥" hint="可选；填写后会同时创建唯一 Peer。">
                <input name="peer_public_key" placeholder="粘贴对端公钥" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="允许路由" hint="写入 [Peer] 的允许路由字段（AllowedIPs）；dn42 常见为 172.20.0.0/14, fd00::/8。">
                <input name="peer_allowed_ips" placeholder="172.20.0.0/14, fd00::/8" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端入口地址" hint="对端公网 IP、内网 IP 或域名；可留空。">
                <input name="peer_endpoint_host" placeholder="203.0.113.20" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端入口端口" hint="对端 UDP 端口；入口地址留空时通常也留空。">
                <input name="peer_endpoint_port" placeholder="51820" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="保活间隔" hint="NAT 后常用 25；留空表示不写保活字段。">
                <input name="peer_persistent_keepalive" placeholder="25" inputMode="numeric" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="预共享密钥" hint="可选，填写后会渲染 PresharedKey。">
                <input name="peer_preshared_key" placeholder="粘贴预共享密钥" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端高级配置" hint="逐行写入 [Peer] 后。保存前请确认这些配置行能被 WireGuard 识别。" wide>
                <textarea name="peer_custom_config" placeholder="自定义对端配置行" disabled={!selectedNodeOnline} />
              </Field>
              <button type="submit" disabled={!selectedNodeOnline || actionPending(nodeActionKey(selectedNode.id, "create-config"))}><Plus size={16} /> {actionPending(nodeActionKey(selectedNode.id, "create-config")) ? "添加中" : "添加配置"}</button>
            </form>
          </section>
        </div>
      )}

      {createDialog === "managed-protocol" && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel protocolSelectModal" role="dialog" aria-modal="true" aria-labelledby="managed-protocol-title">
            <header className="modalHeader">
              <div>
                <h2 id="managed-protocol-title"><GitBranch size={18} /> 选择连接协议</h2>
                <p className="muted">先选择连接类型，下一步再填写对应参数。</p>
              </div>
              <button className="iconButton" onClick={closeCreateDialog}>
                <X size={18} />
              </button>
            </header>
            <div className="protocolChoice protocolChoiceModal" role="radiogroup" aria-label="连接协议">
              <button
                type="button"
                className="protocolCard"
                onClick={() => selectManagedCreateProtocol("wireguard")}
                disabled={!selectedNodeOnline || selectedPeerNodeOptions.length === 0}
              >
                <span className="protocolCardIcon"><ShieldCheck size={22} /></span>
                <span className="protocolCardBody">
                  <span className="protocolCardTitle">
                    <strong>WireGuard</strong>
                    <em>推荐</em>
                  </span>
                  <small>加密隧道，适合 NAT、移动公网和常规点对点互联。</small>
                  <span className="protocolCardMeta">支持中间层和自动密钥生成</span>
                </span>
              </button>
              <button
                type="button"
                className="protocolCard"
                onClick={() => selectManagedCreateProtocol("gre")}
                disabled={!nodeSupportsGre(selectedNode) || selectedGrePeerNodeOptions.length === 0}
              >
                <span className="protocolCardIcon"><Network size={22} /></span>
                <span className="protocolCardBody">
                  <span className="protocolCardTitle">
                    <strong>GRE</strong>
                    <em>IPv4</em>
                  </span>
                  <small>三层隧道，不加密，适合双方网络明确放行 IP protocol 47 的场景。</small>
                  <span className="protocolCardMeta">可从节点 IPv4 地址选择外层地址</span>
                </span>
              </button>
            </div>
            {selectedGrePeerNodeOptions.length === 0 && (
              <p className="protocolChoiceHint">GRE 需要当前节点和至少一个对端节点在线，并且双方 Agent 都支持 GRE。</p>
            )}
          </section>
        </div>
      )}

      {createDialog === "managed" && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel" role="dialog" aria-modal="true" aria-labelledby="managed-link-title">
            <header className="modalHeader">
              <div>
                <h2 id="managed-link-title"><GitBranch size={18} /> 创建{managedCreateProtocol === "gre" ? " GRE" : " WireGuard"} 受管连接</h2>
                <p className="muted">系统会根据所选协议生成双方配置，部署并启动连接，同时启用对应节点的服务或开机配置。</p>
              </div>
              <button
                className="iconButton"
                onClick={closeCreateDialog}
              >
                <X size={18} />
              </button>
            </header>
            <form
              key={`create-managed-link-modal-${selectedNode.id}-${managedCreateProtocol}`}
              onSubmit={(event) => void runAction(
                () => managedCreateProtocol === "gre" ? createGreConnection(event) : createManagedLink(event),
                nodeActionKey(selectedNode.id, managedCreateProtocol === "gre" ? "create-gre-link" : "create-managed-link"),
              )}
              className="gridForm describedForm"
            >
              {managedCreateProtocol === "wireguard" ? (
                <>
              <FormSection title="节点与导入" hint="选择对端节点；需要接管现有 wg-quick 配置时，在这里指定双方要替换的导入配置。">
              <Field label="对端节点" hint="只能选择当前在线的其它受管节点。">
                <select
                  name="peer_node_id"
                  required
                  disabled={!selectedNodeOnline}
                  onChange={(event) => {
                    setManagedPeerNodeId(Number(event.currentTarget.value) || null);
                    setReplacePeerConfigId(null);
                  }}
                >
                  <option value="">选择节点</option>
                  {managedCreatePeerNodeOptions.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </Field>
              <Field label="替换本端导入配置" hint="可选；用于把现有 wg-quick 配置替换为新的受管连接。">
                <select
                  value={replaceLocalConfigId || ""}
                  disabled={!selectedNodeOnline}
                  onChange={(event) => setReplaceLocalConfigId(Number(event.currentTarget.value) || null)}
                >
                  <option value="">不替换</option>
                  {configs.filter((item) => item.source === "imported" && !item.managed).map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </Field>
              <Field
                label="替换对端导入配置"
                hint={replaceLocalConfigId ? "必选；本端导入配置转受管时必须指定对端要覆盖的导入配置。" : "可选；选择后创建时会停用并删除旧配置文件。"}
              >
                <select
                  value={replacePeerConfigId || ""}
                  required={Boolean(replaceLocalConfigId)}
                  disabled={!selectedNodeOnline || !managedPeerNodeId}
                  onChange={(event) => setReplacePeerConfigId(Number(event.currentTarget.value) || null)}
                >
                  <option value="">不替换</option>
                  {replacePeerConfigOptions.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </Field>
              </FormSection>
              <FormSection title="接口与隧道地址" hint="接口名写入双方节点；隧道 IP 和允许路由支持多个 CIDR，用逗号分隔。">
              <Field label="本端接口名称" hint="当前节点上创建的接口名。">
                <input name="local_interface_name" placeholder="wg-node-a" defaultValue={replaceLocalConfig?.name || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端接口名称" hint="对端节点上创建的接口名；同机双 Agent 测试时必须不同。">
                <input name="peer_interface_name" placeholder="wg-node-b" defaultValue={replacePeerConfig?.name || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端隧道 IP" hint="本端 WireGuard Address；例如 10.42.0.1/32, fd42::1/64。">
                <input name="local_tunnel_ips" placeholder="10.42.0.1/32, fd42::1/64" defaultValue={replaceLocalConfig?.tunnel_ips.join(", ") || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端隧道 IP" hint="对端 WireGuard Address；例如 10.42.0.2/32, fd42::2/64。">
                <input name="peer_tunnel_ips" placeholder="10.42.0.2/32, fd42::2/64" defaultValue={replacePeerConfig?.tunnel_ips.join(", ") || ""} required disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端监听端口" hint="可选；留空表示本端 WireGuard 不写 ListenPort。udp2raw server 在本端时必须填写。">
                <input name="local_listen_port" placeholder="51820" defaultValue={replaceLocalConfig?.listen_port || ""} inputMode="numeric" required={mimicActive} disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端监听端口" hint="可选；留空表示对端 WireGuard 不写 ListenPort。udp2raw server 在对端时必须填写。">
                <input name="peer_listen_port" placeholder="51821" defaultValue={replacePeerConfig?.listen_port || ""} inputMode="numeric" required={mimicActive} disabled={!selectedNodeOnline} />
              </Field>
              </FormSection>
              <FormSection title="直连入口与路由" hint="本端或对端至少填写一个入口地址；NAT 或出入口不对称的一侧可以留空。启用 mimic 时双方入口都必填。">
              <Field label="本端入口地址" hint="对端连接本节点时使用；本端不可被拨入时可留空。" requiredMark={mimicActive && selectedNodeOnline}>
                <EndpointSelect
                  key={`managed-local-endpoint-${replacePeerConfigId || "none"}-${managedLocalEndpointDefault}`}
                  name="local_endpoint_host"
                  defaultValue={managedLocalEndpointDefault}
                  placeholder={selectedLocalEndpoints[0] || "203.0.113.10"}
                  options={managedLocalEndpointOptions}
                  disabled={!selectedNodeOnline}
                  locked={udp2rawActive}
                />
              </Field>
              <Field label="本端入口端口" hint="对端直连本节点时使用；留空则使用本端 ListenPort。udp2raw 启用时由中间层接管。">
                <input
                  name="local_endpoint_port"
                  placeholder="51820"
                  defaultValue={replaceLocalConfig?.listen_port || ""}
                  inputMode="numeric"
                  disabled={!selectedNodeOnline || udp2rawActive}
                />
              </Field>
              <Field label="对端入口地址" hint="本端连接对端节点时使用；对端不可被拨入时可留空。" requiredMark={mimicActive && selectedNodeOnline}>
                <EndpointSelect
                  key={`managed-peer-endpoint-${replaceLocalConfigId || "none"}-${managedPeerEndpointDefault}`}
                  name="peer_endpoint_host"
                  defaultValue={managedPeerEndpointDefault}
                  placeholder={selectedPeerEndpoints[0] || "203.0.113.20"}
                  options={managedPeerEndpointOptions}
                  disabled={!selectedNodeOnline}
                  locked={udp2rawActive}
                />
              </Field>
              <Field label="对端入口端口" hint="本端直连对端节点时使用；留空则使用对端 ListenPort。udp2raw 启用时由中间层接管。">
                <input
                  name="peer_endpoint_port"
                  placeholder="51821"
                  defaultValue={replacePeerConfig?.listen_port || ""}
                  inputMode="numeric"
                  disabled={!selectedNodeOnline || udp2rawActive}
                />
              </Field>
              <Field label="本端允许路由" hint="写入当前节点 [Peer] 的允许路由字段（AllowedIPs）；留空则使用对端隧道 IP。">
                <input
                  key={`managed-local-allowed-${replaceLocalConfigId || "none"}-${replacePeerConfigId || "none"}-${managedLocalAllowedIpsDefault}`}
                  name="local_allowed_ips"
                  placeholder="10.42.0.2/32, 192.168.20.0/24"
                  defaultValue={managedLocalAllowedIpsDefault}
                  disabled={!selectedNodeOnline}
                />
              </Field>
              <Field label="对端允许路由" hint="写入对端节点 [Peer] 的允许路由字段（AllowedIPs）；留空则使用本端隧道 IP。">
                <input
                  key={`managed-peer-allowed-${replaceLocalConfigId || "none"}-${replacePeerConfigId || "none"}-${managedPeerAllowedIpsDefault}`}
                  name="peer_allowed_ips"
                  placeholder="10.42.0.1/32, 192.168.10.0/24"
                  defaultValue={managedPeerAllowedIpsDefault}
                  disabled={!selectedNodeOnline}
                />
              </Field>
              </FormSection>
              <FormSection title="连接中间层" hint="udp2raw 通过本地代理接管入口地址；mimic 在网卡层透明处理真实入口流量。">
                <Field label="中间层类型" hint="OpenWrt 当前只支持 udp2raw；mimic 需要非 OpenWrt Linux kernel > 6.1 且已安装 mimic。">
                  <select
                    value={middlewareType}
                    disabled={!selectedNodeOnline}
                    onChange={(event) => {
                      const next = event.currentTarget.value as "none" | "udp2raw" | "mimic";
                      setMiddlewareType(next);
                      setUdp2rawEnabled(next === "udp2raw");
                      setMimicEnabled(next === "mimic");
                      if (next === "udp2raw") setManagedCreateMtu("1300");
                      if (next === "mimic") setManagedCreateMtu("1408");
                    }}
                  >
                    <option value="none">不使用中间层</option>
                    <option value="udp2raw">udp2raw</option>
                    <option value="mimic">mimic</option>
                  </select>
                </Field>
              </FormSection>
              {middlewareType === "udp2raw" && (
                <Udp2RawFields
                  enabled={udp2rawEnabled}
                  serverSide={udp2rawServerSide}
                  localListenPort={replaceLocalConfig?.listen_port}
                  peerListenPort={replacePeerConfig?.listen_port}
                  disabled={!selectedNodeOnline}
                  onEnabledChange={(enabled) => {
                    setUdp2rawEnabled(enabled);
                    if (enabled) setManagedCreateMtu("1300");
                  }}
                  onServerSideChange={setUdp2rawServerSide}
                />
              )}
              {middlewareType === "mimic" && (
                <MimicFields
                  enabled={mimicEnabled}
                  localNode={selectedNode}
                  peerNode={selectedManagedPeerNode}
                  disabled={!selectedNodeOnline}
                  onEnabledChange={(enabled) => {
                    setMimicEnabled(enabled);
                    if (enabled) setManagedCreateMtu("1408");
                  }}
                />
              )}
              <FormSection title="链路参数" hint="Table=off 是 DN42 常用默认值；启用中间层时 MTU 默认降到 1300，但仍可手动调整。">
              <Field label="MTU" hint={udp2rawActive ? "启用 udp2raw 时建议降低 MTU；已自动填入 1300，可手动修改。" : mimicActive ? "启用 mimic 时建议将 IPv6 WireGuard MTU 降到 1408，可手动修改。" : "双方链路 MTU，默认 1420。"}>
                <input
                  name="mtu"
                  placeholder="1420"
                  value={managedCreateMtu}
                  onChange={(event) => setManagedCreateMtu(event.currentTarget.value)}
                  inputMode="numeric"
                  disabled={!selectedNodeOnline}
                />
              </Field>
              <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                <RouteModeSelect defaultValue={replaceLocalConfig?.table_name || replacePeerConfig?.table_name || "off"} disabled={!selectedNodeOnline} />
              </Field>
              </FormSection>
              <FormSection title="高级配置" hint="这些内容会原样追加到对应的 [Interface] 或 [Peer] 区块，请只填写 WireGuard 支持的配置行。">
              <Field label="本端接口高级配置" hint="写入当前节点 [Interface] 后，例如 PostUp。不同节点可不同。" wide>
                <textarea name="local_interface_custom_config" defaultValue={replaceLocalConfig?.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
              </Field>
              <Field label="本端对端高级配置" hint="写入当前节点 [Peer] 后。" wide>
                <textarea name="local_peer_custom_config" placeholder="允许路由之外的自定义对端配置行" disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端接口高级配置" hint="写入对端节点 [Interface] 后，例如不同的 PostUp。" wide>
                <textarea name="peer_interface_custom_config" defaultValue={replacePeerConfig?.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
              </Field>
              <Field label="对端对端高级配置" hint="写入对端节点 [Peer] 后。" wide>
                <textarea name="peer_peer_custom_config" placeholder="允许路由之外的自定义对端配置行" disabled={!selectedNodeOnline} />
              </Field>
              </FormSection>
              {(replaceLocalConfigId || replacePeerConfigId) && (
                <label className="checkField wideField">
                  <input
                    type="checkbox"
                    checked={forceEndpointMismatch}
                    onChange={(event) => setForceEndpointMismatch(event.currentTarget.checked)}
                  />
                  <span>如果旧配置入口地址与所选节点地址不匹配，仍强制替换</span>
                </label>
              )}
              <button
                type="submit"
                disabled={
                  !selectedNodeOnline ||
                  managedCreatePeerNodeOptions.length === 0 ||
                  Boolean(replaceLocalConfigId && !replacePeerConfigId) ||
                  actionPending(nodeActionKey(selectedNode.id, "create-managed-link"))
                }
              >
                <GitBranch size={16} /> {actionPending(nodeActionKey(selectedNode.id, "create-managed-link")) ? "创建中" : "创建并启动双方连接"}
              </button>
                </>
              ) : (
                <>
              {!nodeSupportsGre(selectedNode) && (
                <div className="empty wideField">当前节点尚未上报 GRE 能力，请确认 Agent 已升级且系统支持 iproute2 GRE。</div>
              )}
              <FormSection title="基础" hint="GRE 连接会在两个在线受管节点之间创建 IPv4 L3 隧道。">
                <Field label="对端节点" hint="只显示已在线并上报 GRE 能力的节点。" requiredMark>
                  <select
                    name="peer_node_id"
                    required
                    disabled={!nodeSupportsGre(selectedNode)}
                    onChange={(event) => setManagedPeerNodeId(Number(event.currentTarget.value) || null)}
                  >
                    <option value="">选择节点</option>
                    {selectedGrePeerNodeOptions.map((item) => (
                      <option key={item.id} value={item.id}>{item.name}</option>
                    ))}
                  </select>
                </Field>
                <Field label="本端接口名称" hint="Linux 接口名不超过 15 个字符。" requiredMark>
                  <input name="local_interface_name" placeholder="gre-a-b" required disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <Field label="对端接口名称" hint="写入对端节点的 GRE 接口名。" requiredMark>
                  <input name="peer_interface_name" placeholder="gre-b-a" required disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
              </FormSection>
              <FormSection title="外层地址" hint="请选择节点地址中的 IPv4，或手动输入双方可互达的 IPv4；不支持域名。">
                <Field label="本端外层源 IP" requiredMark>
                  <EndpointSelect
                    key={`managed-gre-local-outer-${selectedNode.id}-${managedGreLocalOuterIpDefault}`}
                    name="local_outer_ip"
                    defaultValue={managedGreLocalOuterIpDefault}
                    placeholder={managedGreLocalOuterIpDefault || "203.0.113.10"}
                    options={managedGreLocalOuterIpOptions}
                    disabled={!nodeSupportsGre(selectedNode)}
                  />
                </Field>
                <Field label="对端外层源 IP" requiredMark>
                  <EndpointSelect
                    key={`managed-gre-peer-outer-${managedPeerNodeId || "none"}-${managedGrePeerOuterIpDefault}`}
                    name="peer_outer_ip"
                    defaultValue={managedGrePeerOuterIpDefault}
                    placeholder={managedGrePeerOuterIpDefault || "198.51.100.20"}
                    options={managedGrePeerOuterIpOptions}
                    disabled={!nodeSupportsGre(selectedNode) || !managedPeerNodeId}
                  />
                </Field>
              </FormSection>
              <FormSection title="隧道地址与路由" hint="路由字段表示经 GRE 到达的远端网段，不是 WireGuard AllowedIPs。">
                <Field label="本端隧道地址" hint="IPv4 CIDR，例如 10.42.8.1/30。" requiredMark>
                  <input name="local_tunnel_ips" placeholder="10.42.8.1/30" required disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <Field label="对端隧道地址" hint="IPv4 CIDR，例如 10.42.8.2/30。" requiredMark>
                  <input name="peer_tunnel_ips" placeholder="10.42.8.2/30" required disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <Field label="本端经隧道路由" hint="当前节点经 GRE 到达的对端网段，多个用逗号分隔。">
                  <input name="local_routes" placeholder="10.77.0.0/24" disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <Field label="对端经隧道路由" hint="对端节点经 GRE 到达的本网段，多个用逗号分隔。">
                  <input name="peer_routes" placeholder="10.88.0.0/24" disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
              </FormSection>
              <FormSection title="高级" hint="默认 MTU 1476；GRE Key 可选，填写后双方必须一致。">
                <Field label="MTU">
                  <input name="mtu" placeholder="1476" defaultValue="1476" inputMode="numeric" disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <Field label="GRE Key">
                  <input name="gre_key" placeholder="42" inputMode="numeric" disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <Field label="TTL">
                  <input name="ttl" placeholder="255" inputMode="numeric" disabled={!nodeSupportsGre(selectedNode)} />
                </Field>
                <label className="checkField">
                  <input name="pmtudisc" type="checkbox" defaultChecked disabled={!nodeSupportsGre(selectedNode)} />
                  <span>启用 PMTU discovery</span>
                </label>
              </FormSection>
              <label className="checkField wideField dangerCheck">
                <input name="risk_accepted" type="checkbox" required disabled={!nodeSupportsGre(selectedNode)} />
                <span>我已确认 GRE 不加密，且双方网络允许 IP protocol 47；普通 NAT 环境可能无法使用。</span>
              </label>
              <button
                type="submit"
                disabled={!nodeSupportsGre(selectedNode) || selectedGrePeerNodeOptions.length === 0 || actionPending(nodeActionKey(selectedNode.id, "create-gre-link"))}
              >
                <GitBranch size={16} /> {actionPending(nodeActionKey(selectedNode.id, "create-gre-link")) ? "创建中" : "创建并启动 GRE"}
              </button>
                </>
              )}
            </form>
          </section>
        </div>
      )}

      <section className="nodeBoard">
        <section className="nodeCreate">
          <div>
            <h2><Server size={18} /> 节点</h2>
            <p className="muted">先创建节点并填写可被其它节点访问的入口地址。</p>
          </div>
          <button type="button" onClick={() => setNodeCreateOpen(true)}><Plus size={16} /> 添加节点</button>
        </section>

        <section className="topologyPanel">
          <header className="topologyHeader">
            <div>
              <h2><GitBranch size={18} /> 拓扑图</h2>
              <p className="muted">根据受管节点连接自动生成；拖动节点可保存自定义位置。</p>
            </div>
            <div className="topologyToolbar">
              <span className="topologyMeta">{topology.nodes.length} 个节点 / {topology.edges.length} 条链路</span>
              <button
                className="secondary"
                type="button"
                onClick={() => setTopologyFullscreenOpen(true)}
              >
                <Maximize2 size={16} /> 全屏
              </button>
              <button
                className="secondary"
                type="button"
                disabled={actionPending("topology:reset")}
                onClick={() => setTopologyResetConfirmOpen(true)}
              >
                <RefreshCw size={16} /> {actionPending("topology:reset") ? "还原中" : "还原拓扑"}
              </button>
            </div>
          </header>
          {renderTopologyCanvas()}
        </section>

        <div className="nodeList" aria-label="按地域分组的节点列表">
          <div className="regionIndex" aria-label="地域快捷导航">
            {nodeRegionGroups.map((group) => (
              <button
                key={group.id}
                type="button"
                className="secondary"
                onClick={() => {
                  document.querySelector(`[data-region-id="${group.id}"]`)?.scrollIntoView({
                    behavior: "smooth",
                    block: "start",
                  });
                }}
              >
                <span>{group.region}</span>
                <small>{group.nodes.length}</small>
              </button>
            ))}
          </div>
          {nodeRegionGroups.map((group) => (
            <section key={group.id} className="regionGroup" data-region-id={group.id}>
              <header className="regionHeader">
                <div>
                  <h3>{group.region}</h3>
                  <p className="muted">{group.onlineCount} 个在线 / 共 {group.nodes.length} 个</p>
                </div>
              </header>
              <div className="regionNodeList">
                {group.nodes.map((node) => {
                  const expanded = node.id === selectedNodeId;
                  const online = isNodeSelectable(node);
                  return (
                    <section key={node.id} data-node-id={node.id} className={expanded ? "nodeCard expanded" : "nodeCard"}>
                      <div className="nodeBar">
                        <button
                          className="nodeHeader"
                          disabled={!online}
                          onClick={() => {
                            selectNodeId(expanded ? null : node.id);
                            selectConfigId(null);
                            selectConnectionRef(null);
                            setPlan(null);
                            setImportCandidatesExpanded(false);
                          }}
                        >
                          <span>
                            <strong>{node.name}</strong>
                            <small>{nodeEndpointOptions(node).join(", ") || node.hostname || "未配置入口地址"}</small>
                          </span>
                          <span className={online ? "statusBadge online" : "statusBadge"}>{nodeStatusLabel(node.status)}</span>
                        </button>
                        <button
                          className="iconButton nodeEditButton"
                          title="编辑节点"
                          onClick={() => setEditingNodeId(node.id)}
                        >
                          <Pencil size={16} />
                        </button>
                      </div>

                      {expanded && (
                        <div className="nodeDetails">
                          {!selectedNodeOnline && <div className="empty">Agent 已离线，当前节点暂不能修改或部署。</div>}
                          <section className="connectionActions" aria-label="创建连接">
                            <div>
                              <h3>创建连接</h3>
                              <p className="muted">WireGuard 适合加密和 NAT 场景；GRE 适合网络允许协议 47 的受管节点直连。</p>
                            </div>
                            <div className="actionRow">
                              <button
                                type="button"
                                disabled={!selectedNodeOnline}
                                onClick={() => setCreateDialog("external")}
                              >
                                <Plus size={16} /> 手动创建连接
                              </button>
                              <button
                                type="button"
                                disabled={!selectedNodeOnline || nodes.filter((item) => item.id !== node.id && isNodeSelectable(item)).length === 0}
                                onClick={() => openManagedCreateDialog()}
                              >
                                <GitBranch size={16} /> 创建受管连接
                              </button>
                            </div>
                          </section>

                          {selectedNodeSupportsWgQuickImport ? (
                            <div className="sectionActions">
                              <button
                                className="secondary"
                                disabled={!selectedNodeOnline || actionPending(nodeActionKey(selectedNodeId, "import-scan"))}
                                onClick={() => void runAction(requestImportScan, nodeActionKey(selectedNodeId, "import-scan"))}
                              >
                                <Upload size={16} /> {actionPending(nodeActionKey(selectedNodeId, "import-scan")) ? "扫描中" : "扫描现有 wg-quick"}
                              </button>
                            </div>
                          ) : (
                            <div className="empty">{importScanUnavailableMessage(selectedNode, selectedNodeOnline)}</div>
                          )}

                          {selectedNodeSupportsWgQuickImport && importCandidates.length > 0 && (
                            <div className="candidateList">
                              <button
                                type="button"
                                className="candidateToggle"
                                onClick={() => setImportCandidatesExpanded((value) => !value)}
                              >
                                <span>
                                  {importCandidatesExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                  <strong>扫描到的 wg-quick 配置</strong>
                                </span>
                                <small>{importCandidates.length} 个</small>
                              </button>
                              {importCandidatesExpanded && importCandidates.map((candidate) => (
                                <div key={candidate.id} className="candidate">
                                  <div>
                                    <strong>{candidate.interface_name}</strong>
                                    <span>{candidate.path}</span>
                                    {candidate.warnings.length > 0 && <small>{candidate.warnings.join("; ")}</small>}
                                  </div>
                                  <button
                                    disabled={candidate.imported || !selectedNodeOnline || actionPending(candidateActionKey(candidate.id))}
                                    onClick={() => void runAction(() => importCandidate(candidate.id), candidateActionKey(candidate.id))}
                                  >
                                    {candidate.imported ? "已导入" : actionPending(candidateActionKey(candidate.id)) ? "导入中" : "导入"}
                                  </button>
                                </div>
                              ))}
                            </div>
                          )}

                          <section className="nodePluginEntry" aria-label="节点插件">
                            <div>
                              <h3>节点插件</h3>
                              <p className="muted">
                                {availableNodePlugins.length > 0
                                  ? `${availableNodePlugins.length} 个可用插件`
                                  : selectedNodeOnline ? "当前节点暂无可用插件" : "节点在线后可使用插件"}
                              </p>
                            </div>
                            <button
                              type="button"
                              disabled={!selectedNodeOnline || nodePlugins.length === 0}
                              onClick={() => {
                                openNodePluginDialog();
                              }}
                            >
                              <Plug size={16} /> 打开插件
                            </button>
                          </section>

                          <div className="configList">
                            {connections.length === 0 ? (
                              <div className="empty">该节点还没有连接配置。</div>
                            ) : (
                              connections.map((item) => {
                                const nodeEndpoint = connectionEndpointForNode(item, selectedNodeId) || connectionEndpointByRole(item, "local");
                                const peerEndpoint = connectionPeerEndpointForNode(item, selectedNodeId) || connectionEndpointByRole(item, "peer");
                                const rowName = nodeEndpoint?.interface_name || item.name;
                                return (
                                  <button
                                    key={item.connection_ref}
                                    data-config-id={item.protocol_type === "wireguard" ? nodeEndpoint?.id : undefined}
                                    data-connection-ref={item.protocol_type === "gre" ? item.connection_ref : undefined}
                                    className="configRow protocolRow"
                                    onClick={() => {
                                      if (item.protocol_type === "wireguard") {
                                        selectConnectionRef(null);
                                        selectConfigId(nodeEndpoint?.id || item.id);
                                      } else {
                                        selectConfigId(null);
                                        selectConnectionRef(item.connection_ref);
                                      }
                                      setPlan(null);
                                    }}
                                  >
                                    <span>
                                      <strong>{rowName}</strong>
                                      <small>{protocolLabel(item)} / {nodeEndpoint?.interface_name || "本端"} → {peerEndpoint?.interface_name || "对端"}</small>
                                    </span>
                                    <span className="configRowMetrics">
                                      <span className="protocolBadge">{protocolLabel(item)}</span>
                                      <span className={`statusBadge ${item.status === "running" ? "online" : ""}`}>
                                        {statusLabel(item.status)}
                                      </span>
                                      <MonitorSummaryButton
                                        summary={nodeEndpoint?.monitor_summary || null}
                                        onClick={(event) => {
                                          event.stopPropagation();
                                          if (item.protocol_type === "wireguard") {
                                            setMonitorDialogEndpointRef(null);
                                            setMonitorDialogConfigId(nodeEndpoint?.id || item.id);
                                          } else if (nodeEndpoint) {
                                            setMonitorDialogConfigId(null);
                                            setMonitorDialogEndpointRef(nodeEndpoint.endpoint_ref);
                                          }
                                          setMonitorWindow("1h");
                                        }}
                                      />
                                    </span>
                                  </button>
                                );
                              })
                            )}
                          </div>
                        </div>
                      )}
                    </section>
                  );
                })}
              </div>
            </section>
          ))}
        </div>
      </section>

      {selectedGreConnection && selectedNode && selectedGreLocalEndpoint && selectedGrePeerEndpoint && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel" role="dialog" aria-modal="true" aria-labelledby="gre-config-title">
            <header className="modalHeader">
              <div>
                <h2 id="gre-config-title">GRE 连接配置</h2>
                <p className="muted">
                  {selectedGreNodeEndpoint?.node_name || selectedNode.name} / {selectedGreNodeEndpoint?.interface_name || selectedGreConnection.name}
                  {selectedGreNodePeerEndpoint ? ` → ${selectedGreNodePeerEndpoint.node_name || selectedGreNodePeerEndpoint.node_id}` : ""}
                  {" / "}{statusLabel(selectedGreConnection.status)}
                </p>
              </div>
              <button
                className="iconButton"
                onClick={() => {
                  selectConnectionRef(null);
                  setPlan(null);
                }}
              >
                <X size={18} />
              </button>
            </header>

            {!selectedGreAllNodesOnline && <div className="empty">双方节点都在线时才能修改、启动或删除 GRE 连接。</div>}
            {selectedGreConnection.warnings.length > 0 && (
              <div className="empty">
                {selectedGreConnection.warnings.map((warning) => (
                  <div key={warning}>{warning}</div>
                ))}
              </div>
            )}

            <section className="modalSection">
              <h3>受管 GRE</h3>
              <form
                key={`gre-edit-${selectedGreConnection.connection_ref}`}
                onSubmit={(event) => void runAction(() => saveGreConnection(event), connectionActionKey(selectedGreConnection.connection_ref, "save"))}
                className="gridForm describedForm"
              >
                <FormSection title="基础" hint="接口名会写入双方节点，保存后会重新下发并启动双方 GRE。">
                  <Field label="本端接口名称" hint={`节点：${selectedGreLocalEndpoint.node_name || selectedGreLocalEndpoint.node_id}`} requiredMark>
                    <input name="local_interface_name" defaultValue={selectedGreLocalEndpoint.interface_name} required disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <Field label="对端接口名称" hint={`节点：${selectedGrePeerEndpoint.node_name || selectedGrePeerEndpoint.node_id}`} requiredMark>
                    <input name="peer_interface_name" defaultValue={selectedGrePeerEndpoint.interface_name} required disabled={!selectedGreAllNodesOnline} />
                  </Field>
                </FormSection>
                <FormSection title="外层地址" hint="请选择节点地址中的 IPv4，或手动输入双方可互达的 IPv4；不支持域名。">
                  <Field label="本端外层源 IP" requiredMark>
                    <EndpointSelect
                      key={`edit-gre-local-outer-${selectedGreConnection.connection_ref}-${greProtocolString(selectedGreLocalEndpoint, "outer_local_ip")}`}
                      name="local_outer_ip"
                      defaultValue={greProtocolString(selectedGreLocalEndpoint, "outer_local_ip")}
                      placeholder={editGreLocalOuterIpOptions[0]?.value || "203.0.113.10"}
                      options={editGreLocalOuterIpOptions}
                      disabled={!selectedGreAllNodesOnline}
                    />
                  </Field>
                  <Field label="对端外层源 IP" requiredMark>
                    <EndpointSelect
                      key={`edit-gre-peer-outer-${selectedGreConnection.connection_ref}-${greProtocolString(selectedGrePeerEndpoint, "outer_local_ip")}`}
                      name="peer_outer_ip"
                      defaultValue={greProtocolString(selectedGrePeerEndpoint, "outer_local_ip")}
                      placeholder={editGrePeerOuterIpOptions[0]?.value || "198.51.100.20"}
                      options={editGrePeerOuterIpOptions}
                      disabled={!selectedGreAllNodesOnline}
                    />
                  </Field>
                </FormSection>
                <FormSection title="隧道地址与路由" hint="路由字段表示经 GRE 到达的远端网段。">
                  <Field label="本端隧道地址" requiredMark>
                    <input name="local_tunnel_ips" defaultValue={selectedGreLocalEndpoint.tunnel_ips.join(", ")} required disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <Field label="对端隧道地址" requiredMark>
                    <input name="peer_tunnel_ips" defaultValue={selectedGrePeerEndpoint.tunnel_ips.join(", ")} required disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <Field label="本端经隧道路由">
                    <input name="local_routes" defaultValue={selectedGreLocalEndpoint.routes.join(", ")} disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <Field label="对端经隧道路由">
                    <input name="peer_routes" defaultValue={selectedGrePeerEndpoint.routes.join(", ")} disabled={!selectedGreAllNodesOnline} />
                  </Field>
                </FormSection>
                <FormSection title="高级" hint="GRE Key、TTL 和 PMTU discovery 会同时下发到双方。">
                  <Field label="MTU">
                    <input name="mtu" defaultValue={selectedGreLocalEndpoint.mtu || 1476} inputMode="numeric" disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <Field label="GRE Key">
                    <input name="gre_key" defaultValue={greProtocolString(selectedGreLocalEndpoint, "key")} inputMode="numeric" disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <Field label="TTL">
                    <input name="ttl" defaultValue={greProtocolNumber(selectedGreLocalEndpoint, "ttl")} inputMode="numeric" disabled={!selectedGreAllNodesOnline} />
                  </Field>
                  <label className="checkField">
                    <input name="pmtudisc" type="checkbox" defaultChecked={greProtocolBoolean(selectedGreLocalEndpoint, "pmtudisc", true)} disabled={!selectedGreAllNodesOnline} />
                    <span>启用 PMTU discovery</span>
                  </label>
                </FormSection>
                <label className="checkField wideField dangerCheck">
                  <input name="risk_accepted" type="checkbox" required disabled={!selectedGreAllNodesOnline} />
                  <span>我已确认 GRE 不加密，且双方网络允许 IP protocol 47；普通 NAT 环境可能无法使用。</span>
                </label>
                <button
                  type="submit"
                  disabled={!selectedGreAllNodesOnline || actionPending(connectionActionKey(selectedGreConnection.connection_ref, "save"))}
                >
                  <Check size={16} /> {actionPending(connectionActionKey(selectedGreConnection.connection_ref, "save")) ? "下发中" : "保存并下发双方配置"}
                </button>
              </form>
            </section>

            <section className="modalSection">
              <h3>连接操作</h3>
              <div className="actionRow">
                <button
                  className="secondary"
                  disabled={!selectedGreAllNodesOnline || isGreBusy || isGreRunning || actionPending(connectionActionKey(selectedGreConnection.connection_ref, "start"))}
                  onClick={() => void runAction(startSelectedGreConnection, connectionActionKey(selectedGreConnection.connection_ref, "start"))}
                >
                  {actionPending(connectionActionKey(selectedGreConnection.connection_ref, "start")) || selectedGreConnection.status === "starting" ? "启动中" : "启动双方连接"}
                </button>
                <button
                  className="secondary"
                  disabled={!selectedGreAllNodesOnline || isGreBusy || isGreStopped || actionPending(connectionActionKey(selectedGreConnection.connection_ref, "stop"))}
                  onClick={() => void runAction(stopSelectedGreConnection, connectionActionKey(selectedGreConnection.connection_ref, "stop"))}
                >
                  {actionPending(connectionActionKey(selectedGreConnection.connection_ref, "stop")) || selectedGreConnection.status === "stopping" ? "断开中" : "断开双方连接"}
                </button>
                <button
                  className="danger"
                  disabled={!selectedGreAllNodesOnline || isGreBusy || !isGreStopped || actionPending(connectionActionKey(selectedGreConnection.connection_ref, "delete"))}
                  onClick={() => void runAction(deleteSelectedGreConnection, connectionActionKey(selectedGreConnection.connection_ref, "delete"))}
                >
                  {actionPending(connectionActionKey(selectedGreConnection.connection_ref, "delete")) ? "删除中" : "删除 GRE 连接"}
                </button>
              </div>
            </section>
          </section>
        </div>
      )}

      {selectedConfig && selectedNode && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel" role="dialog" aria-modal="true" aria-labelledby="peer-modal-title">
            <header className="modalHeader">
              <div>
                <h2 id="peer-modal-title">连接配置</h2>
                <p className="muted">{selectedNode.name} / {selectedConfig.name} / {statusLabel(selectedConfig.runtime_status)}</p>
              </div>
              <button
                className="iconButton"
                onClick={() => {
                  selectConfigId(null);
                  setPlan(null);
                }}
              >
                <X size={18} />
              </button>
            </header>

            {!selectedNodeOnline && <div className="empty">Agent 已离线，当前节点暂不能修改或部署。</div>}

            {selectedConfigIsUnmanagedImport ? (
              <section className="modalSection">
                <h3>导入观察记录</h3>
                <div className="empty">该配置来自节点现有 wg-quick 文件，尚未归属 Link42 管理。接管或导入为受管连接前，系统不会修改、启停或删除节点上的原始配置文件。</div>
              </section>
            ) : selectedConfigIsManagedLink && managedLink ? (
              <section className="modalSection">
                <h3>受管连接</h3>
                <form
                  key={`managed-edit-${selectedConfig.id}-${managedLink.peer_interface.id}`}
                  onSubmit={(event) => void runAction(() => saveManagedLink(event), configActionKey(selectedConfig.id, "save-managed-link"))}
                  className="gridForm describedForm"
                >
                  <FormSection title="接口与隧道地址" hint="这里决定双方 WireGuard 接口本身的名称、Address 和可选监听端口。">
                    <Field label="本端接口名称" hint={`当前节点：${selectedNode.name}`}>
                      <input name="local_interface_name" defaultValue={managedLink.local_interface.name} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端接口名称" hint={`对端节点：${selectedManagedLinkPeerNode?.name || managedLink.peer_interface.node_id}`}>
                      <input name="peer_interface_name" defaultValue={managedLink.peer_interface.name} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端隧道地址" hint="本端 WireGuard Address；支持多个 CIDR，用逗号分隔。">
                      <input name="local_tunnel_ips" defaultValue={managedLink.local_interface.tunnel_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端隧道地址" hint="对端 WireGuard Address；支持多个 CIDR，用逗号分隔。">
                      <input name="peer_tunnel_ips" defaultValue={managedLink.peer_interface.tunnel_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端监听端口" hint="可选；留空表示本端 WireGuard 不写 ListenPort。udp2raw server 在本端时必须填写。">
                      <input name="local_listen_port" defaultValue={managedLink.local_interface.listen_port || ""} inputMode="numeric" required={mimicActive} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端监听端口" hint="可选；留空表示对端 WireGuard 不写 ListenPort。udp2raw server 在对端时必须填写。">
                      <input name="peer_listen_port" defaultValue={managedLink.peer_interface.listen_port || ""} inputMode="numeric" required={mimicActive} disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <FormSection title="直连入口与路由" hint="本端或对端至少填写一个入口地址；NAT 或出入口不对称的一侧可以留空。启用 mimic 时双方入口都必填。">
                    <Field label="本端入口地址" hint="对端连接本节点时使用；本端不可被拨入时可留空。" requiredMark={mimicActive && selectedNodeOnline}>
                      <EndpointSelect
                        key={`edit-local-endpoint-${editLocalEndpointDefault}`}
                        name="local_endpoint_host"
                        defaultValue={editLocalEndpointDefault}
                        placeholder={selectedLocalEndpoints[0] || "203.0.113.10"}
                        options={editLocalEndpointOptions}
                        disabled={!selectedNodeOnline}
                        locked={udp2rawActive}
                      />
                    </Field>
                    <Field label="本端入口端口" hint="对端直连本节点时使用；留空则使用本端 ListenPort。">
                      <input
                        name="local_endpoint_port"
                        defaultValue={managedLink.peer_peer.endpoint_port || managedLink.local_interface.listen_port || ""}
                        inputMode="numeric"
                        disabled={!selectedNodeOnline || udp2rawActive}
                      />
                    </Field>
                    <Field label="对端入口地址" hint="本端连接对端节点时使用；对端不可被拨入时可留空。" requiredMark={mimicActive && selectedNodeOnline}>
                      <EndpointSelect
                        key={`edit-peer-endpoint-${editPeerEndpointDefault}`}
                        name="peer_endpoint_host"
                        defaultValue={editPeerEndpointDefault}
                        placeholder={selectedManagedLinkPeerEndpoints[0] || "203.0.113.20"}
                        options={editPeerEndpointOptions}
                        disabled={!selectedNodeOnline}
                        locked={udp2rawActive}
                      />
                    </Field>
                    <Field label="对端入口端口" hint="本端直连对端节点时使用；留空则使用对端 ListenPort。">
                      <input
                        name="peer_endpoint_port"
                        defaultValue={managedLink.local_peer.endpoint_port || managedLink.peer_interface.listen_port || ""}
                        inputMode="numeric"
                        disabled={!selectedNodeOnline || udp2rawActive}
                      />
                    </Field>
                    <Field label="本端允许路由" hint="写入当前节点 [Peer] 的允许路由字段（AllowedIPs）；声明经对端到达的地址段。">
                      <input name="local_allowed_ips" defaultValue={managedLink.local_peer.allowed_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端允许路由" hint="写入对端节点 [Peer] 的允许路由字段（AllowedIPs）；声明经本端到达的地址段。">
                      <input name="peer_allowed_ips" defaultValue={managedLink.peer_peer.allowed_ips.join(", ")} required disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <FormSection title="连接中间层" hint="udp2raw 通过本地代理接管入口地址；mimic 在网卡层透明处理真实入口流量。">
                    <Field label="中间层类型" hint="mimic 需要双方节点为非 OpenWrt Linux kernel > 6.1 且已安装 mimic。">
                      <select
                        value={middlewareType}
                        disabled={!selectedNodeOnline}
                        onChange={(event) => {
                          const next = event.currentTarget.value as "none" | "udp2raw" | "mimic";
                          setMiddlewareType(next);
                          setUdp2rawEnabled(next === "udp2raw");
                          setMimicEnabled(next === "mimic");
                        }}
                      >
                        <option value="none">不使用中间层</option>
                        <option value="udp2raw">udp2raw</option>
                        <option value="mimic">mimic</option>
                      </select>
                    </Field>
                  </FormSection>
                  {middlewareType === "udp2raw" && (
                    <Udp2RawFields
                      enabled={udp2rawEnabled}
                      serverSide={udp2rawServerSide}
                      localListenPort={managedLink.local_interface.listen_port}
                      peerListenPort={managedLink.peer_interface.listen_port}
                      defaults={managedLink.middleware?.type === "udp2raw" ? managedLink.middleware : null}
                      disabled={!selectedNodeOnline}
                      onEnabledChange={setUdp2rawEnabled}
                      onServerSideChange={setUdp2rawServerSide}
                    />
                  )}
                  {middlewareType === "mimic" && (
                    <MimicFields
                      enabled={mimicEnabled}
                      defaults={managedLink.middleware?.type === "mimic" ? managedLink.middleware : null}
                      localNode={selectedNode}
                      peerNode={selectedManagedLinkPeerNode}
                      disabled={!selectedNodeOnline}
                      onEnabledChange={setMimicEnabled}
                    />
                  )}
                  <FormSection title="链路参数" hint="Table=off 是 DN42 常用默认值；保活间隔会写入双方 [Peer]。">
                    <Field label="MTU" hint={udp2rawActive ? "启用 udp2raw 时建议降低 MTU；可手动修改。" : mimicActive ? "启用 mimic 时建议将 IPv6 WireGuard MTU 降到 1408，可手动修改。" : "双方链路 MTU，默认 1420。"}>
                      <input name="mtu" defaultValue={managedLink.local_interface.mtu || managedLink.peer_interface.mtu || 1420} inputMode="numeric" disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                      <RouteModeSelect defaultValue={managedLink.local_interface.table_name || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="保活间隔" hint="可选；NAT 场景常用 25。">
                      <input name="persistent_keepalive" placeholder="25" defaultValue={managedLink.local_peer.persistent_keepalive || ""} inputMode="numeric" disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <FormSection title="高级配置" hint="这些内容会原样追加到对应的 [Interface] 或 [Peer] 区块，请只填写 WireGuard 支持的配置行。">
                    <Field label="本端接口高级配置" hint="写入当前节点 [Interface] 后，例如 PostUp。不同节点可不同。" wide>
                      <textarea name="local_interface_custom_config" defaultValue={managedLink.local_interface.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端对端高级配置" hint="写入当前节点 [Peer] 后。" wide>
                      <textarea name="local_peer_custom_config" defaultValue={managedLink.local_peer.peer_custom_config || ""} placeholder="允许路由之外的自定义对端配置行" disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端接口高级配置" hint="写入对端节点 [Interface] 后，例如不同的 PostUp。" wide>
                      <textarea name="peer_interface_custom_config" defaultValue={managedLink.peer_interface.interface_custom_config || ""} placeholder="PostUp = ..." disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端对端高级配置" hint="写入对端节点 [Peer] 后。" wide>
                      <textarea name="peer_peer_custom_config" defaultValue={managedLink.peer_peer.peer_custom_config || ""} placeholder="允许路由之外的自定义对端配置行" disabled={!selectedNodeOnline} />
                    </Field>
                  </FormSection>
                  <button type="submit" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfig.id, "save-managed-link"))}>
                    <Check size={16} /> {actionPending(configActionKey(selectedConfig.id, "save-managed-link")) ? "下发中" : "保存并下发双方配置"}
                  </button>
                </form>
              </section>
            ) : (
              <>
                <section className="modalSection">
                  <h3>WireGuard 配置</h3>
                  <form
                    key={`edit-${selectedConfig.id}`}
                    onSubmit={(event) => void runAction(() => saveConfig(event, "update"), configActionKey(selectedConfig.id, "save-config"))}
                    className="gridForm describedForm"
                  >
                    <Field label="接口名称" hint="节点上的 wg-quick 接口名，例如 wg0。">
                      <input name="name" placeholder="wg0" defaultValue={selectedConfig.name} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端隧道地址" hint="CIDR 格式，多个地址用逗号分隔。">
                      <input name="tunnel_ips" placeholder="10.42.0.1/24" defaultValue={selectedConfig.tunnel_ips.join(", ")} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="监听端口" hint="UDP 端口，留空表示不写 ListenPort。">
                      <input name="listen_port" placeholder="51820" defaultValue={selectedConfig.listen_port || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="MTU" hint="链路 MTU，默认 1420。">
                      <input name="mtu" placeholder="1420" defaultValue={selectedConfig.mtu || 1420} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="自动路由" hint="Table=off 表示 wg-quick 不自动添加路由。">
                      <RouteModeSelect defaultValue={selectedConfig.table_name || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端公钥" hint="44 位 base64；受管连接会自动生成。">
                      <input name="public_key" placeholder="粘贴本端公钥" defaultValue={selectedConfig.public_key || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="本端私钥" hint="可信面板会明文保存并渲染到配置文件。" wide>
                      <textarea name="private_key" placeholder="粘贴本端私钥" defaultValue={selectedConfig.private_key_value || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="接口高级配置" hint="逐行写入 [Interface] 后，例如 PostUp/PostDown。保存前请确认这些配置行能被 WireGuard 识别。" wide>
                      <textarea name="interface_custom_config" placeholder="PostUp = ..." defaultValue={selectedConfig.interface_custom_config || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <button type="submit" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfig.id, "save-config"))}>
                      <Check size={16} /> {actionPending(configActionKey(selectedConfig.id, "save-config")) ? "保存中" : "保存配置修改"}
                    </button>
                  </form>
                </section>

                <section className="modalSection">
                  <h3>唯一对端</h3>
                  <form
                    key={`${selectedConfigId || "none"}-${peer?.id || "new"}`}
                    onSubmit={(event) => void runAction(() => savePeer(event), configActionKey(selectedConfig.id, "save-peer"))}
                    className="gridForm describedForm"
                  >
                    <Field label="对端名称" hint="可选，仅用于界面识别。">
                      <input name="name" placeholder="对端名称" defaultValue={peer?.name || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端公钥" hint="必填，44 位 base64。">
                      <input name="public_key" placeholder="粘贴对端公钥" defaultValue={peer?.public_key || ""} required disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="预共享密钥" hint="可选，填写后会渲染 PresharedKey。">
                      <input name="preshared_key" placeholder="粘贴预共享密钥" defaultValue={peer?.preshared_key_value || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="允许路由" hint="写入 [Peer] 的允许路由字段（AllowedIPs）；CIDR 格式，多个值用逗号分隔。">
                      <input name="allowed_ips" placeholder="10.42.0.2/32" defaultValue={peer?.allowed_ips.join(", ") || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端入口地址" hint="对端公网 IP、内网 IP 或域名；可留空。">
                      <input name="endpoint_host" placeholder="203.0.113.20" defaultValue={peer?.endpoint_host || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端入口端口" hint="对端 UDP 端口；入口地址留空时通常也留空。">
                      <input name="endpoint_port" placeholder="51820" defaultValue={peer?.endpoint_port || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="保活间隔" hint="常用 25；留空表示不写保活字段。">
                      <input name="persistent_keepalive" placeholder="25" defaultValue={peer?.persistent_keepalive || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <Field label="对端高级配置" hint="逐行写入 [Peer] 后。保存前请确认这些配置行能被 WireGuard 识别。" wide>
                      <textarea name="peer_custom_config" placeholder="自定义对端配置行" defaultValue={peer?.peer_custom_config || ""} disabled={!selectedNodeOnline} />
                    </Field>
                    <button type="submit" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfig.id, "save-peer"))}>
                      <Check size={16} /> {actionPending(configActionKey(selectedConfig.id, "save-peer")) ? "保存中" : "保存唯一对端"}
                    </button>
                  </form>
                  <div className="peerList">
                    {peer ? (
                      <div className="peer">
                        <strong>{peer.name || peer.public_key.slice(0, 12)}</strong>
                        <span>{peer.allowed_ips.join(", ") || "未配置允许路由"}</span>
                      </div>
                    ) : (
                      <div className="empty">尚未设置对端。每个 WireGuard 配置需要且只能有一个对端。</div>
                    )}
                  </div>
                </section>
              </>
            )}

            <section className="modalSection">
              <h3>部署与连接</h3>
              {!selectedConfigIsManagedLink && (
                <>
                  {selectedConfigIsUnmanagedImport && (
                    <>
                  <button className="secondary" disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfigId, "take-over"))} onClick={() => void runAction(takeOverConfig, configActionKey(selectedConfigId, "take-over"))}>
                    <Upload size={16} /> {actionPending(configActionKey(selectedConfigId, "take-over")) ? "接管中" : "接管导入配置"}
                      </button>
                      <button
                        className="secondary"
                        disabled={!selectedNodeOnline}
                        onClick={() => {
                          selectConfigId(null);
                          setPlan(null);
                          openManagedCreateDialog({ replaceLocalConfigId: selectedConfig.id });
                        }}
                      >
                        <GitBranch size={16} /> 导入为受管连接
                      </button>
                    </>
                  )}
                  {!selectedConfigIsUnmanagedImport && (
                    <button disabled={!selectedNodeOnline || actionPending(configActionKey(selectedConfigId, "create-plan"))} onClick={() => void runAction(createApplyPlan, configActionKey(selectedConfigId, "create-plan"))}>
                      <GitBranch size={16} /> {actionPending(configActionKey(selectedConfigId, "create-plan")) ? "生成中" : "生成部署计划"}
                    </button>
                  )}
                </>
              )}
              {selectedConfigIsManagedLink && (
                <div className="empty">受管连接由系统直接管理，保存修改会立即下发双方配置，不需要生成部署计划。</div>
              )}
              <div className="actionRow">
                {!selectedConfigIsManagedLink && !selectedConfigIsUnmanagedImport && (
                  <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || actionPending(configActionKey(selectedConfigId, "refresh-deployed"))} onClick={() => void runAction(refreshDeployedConfig, configActionKey(selectedConfigId, "refresh-deployed"))}>
                    <RefreshCw size={16} /> {actionPending(configActionKey(selectedConfigId, "refresh-deployed")) ? "同步中" : "同步节点配置"}
                  </button>
                )}
                {!selectedConfigIsUnmanagedImport && (
                  <>
                    <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || isConfigRunning || actionPending(configActionKey(selectedConfigId, "start"))} onClick={() => void runAction(startSelectedConfig, configActionKey(selectedConfigId, "start"))}>
                      {actionPending(configActionKey(selectedConfigId, "start")) || selectedConfig.runtime_status === "starting" ? "启动中" : selectedConfigIsManagedLink ? "启动双方连接" : "启动连接"}
                    </button>
                    <button className="secondary" disabled={!selectedNodeOnline || isConfigBusy || isConfigStopped || actionPending(configActionKey(selectedConfigId, "stop"))} onClick={() => void runAction(stopSelectedConfig, configActionKey(selectedConfigId, "stop"))}>
                      {actionPending(configActionKey(selectedConfigId, "stop")) || selectedConfig.runtime_status === "stopping" ? "断开中" : selectedConfigIsManagedLink ? "断开双方连接" : "断开连接"}
                    </button>
                  </>
                )}
                <button className="danger" disabled={selectedConfigIsUnmanagedImport ? selectedConfigAnyTaskPending : (!selectedNodeOnline || isConfigBusy || !isConfigStopped || selectedConfigAnyTaskPending)} onClick={() => void runAction(openDeleteDialog)}>
                  {selectedConfigIsManagedLink ? "删除双方配置" : selectedConfigIsUnmanagedImport ? "删除观察记录" : "删除配置"}
                </button>
              </div>
              {!selectedConfigIsManagedLink && plan && (
                <div className="plan">
                  <h3>{formatPlanTitle(plan.title)}</h3>
                  <p>{formatPlanSummary(plan.summary)}</p>
                  <p className="muted">
                    计划状态：{workflowStatusLabel(plan.status)}
                    {plan.task_status ? ` / 任务：${workflowStatusLabel(plan.task_status)}` : ""}
                  </p>
                  <pre>{plan.diff || "本次没有需要下发的配置变化。"}</pre>
                  {plan.task_result && (plan.status === "failed" || plan.task_status === "failed") && (
                    <pre>{formatTaskResultForUser(plan.task_result, "部署任务执行失败")}</pre>
                  )}
                  <button disabled={!selectedNodeOnline || plan.status !== "draft" || !hasDeployDiff || actionPending(configActionKey(selectedConfigId, "confirm-plan"))} onClick={() => void runAction(confirmPlan, configActionKey(selectedConfigId, "confirm-plan"))}>
                    <Check size={16} /> {actionPending(configActionKey(selectedConfigId, "confirm-plan")) ? "执行中" : "确认执行"}
                  </button>
                </div>
              )}
            </section>
          </section>
        </div>
      )}

      {(monitorDialogConfig || monitorDialogEndpoint) && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel monitorModal" role="dialog" aria-modal="true" aria-labelledby="monitor-title">
            <header className="modalHeader">
              <div>
                <h2 id="monitor-title"><LineChartIcon size={18} /> 链路延迟统计</h2>
                <p className="muted">{monitorDialogNodeName} / {monitorDialogSubjectName}</p>
              </div>
              <button
                className="iconButton"
                onClick={() => {
                  setMonitorDialogConfigId(null);
                  setMonitorDialogEndpointRef(null);
                  setMonitorDetail(null);
                }}
              >
                <X size={18} />
              </button>
            </header>
            <form
              key={`monitor-${monitorDialogActionTarget}-${monitorDetail?.monitor.id || "new"}`}
              className="gridForm describedForm"
              onSubmit={(event) => void runAction(() => saveLinkMonitor(event), monitorActionKey(monitorDialogActionTarget, "save"))}
            >
              <Field label="目标 IP" hint="从当前节点 Agent 发起 ping；建议填写对端隧道 IP。">
                <input
                  name="target_host"
                  placeholder="10.42.0.2"
                  defaultValue={monitorDetail?.monitor.target_host || monitorDialogTargetHint}
                  required
                />
              </Field>
              <Field label="刷新频率" hint="1-300 秒，默认 10 秒。">
                <input name="interval_seconds" inputMode="numeric" defaultValue={monitorDetail?.monitor.interval_seconds || 10} required />
              </Field>
              <Field label="保留时间" hint="历史样本保留天数，例如 1、7、30。">
                <select name="retention_days" defaultValue={monitorDetail?.monitor.retention_days || 7}>
                  <option value="1">1 天</option>
                  <option value="7">7 天</option>
                  <option value="30">30 天</option>
                  <option value="90">90 天</option>
                </select>
              </Field>
              <label className="checkField">
                <input name="enabled" type="checkbox" defaultChecked={monitorDetail?.monitor.enabled ?? true} />
                <span>启用监测</span>
              </label>
              <div className="actionRow wideField">
                <button type="submit" disabled={actionPending(monitorActionKey(monitorDialogActionTarget, "save"))}>
                  <Check size={16} /> {actionPending(monitorActionKey(monitorDialogActionTarget, "save")) ? "保存中" : "保存监测"}
                </button>
                {monitorDetail && (
                  <button
                    type="button"
                    className="danger"
                    disabled={actionPending(monitorActionKey(monitorDialogActionTarget, "delete"))}
                    onClick={() => void runAction(deleteLinkMonitor, monitorActionKey(monitorDialogActionTarget, "delete"))}
                  >
                    {actionPending(monitorActionKey(monitorDialogActionTarget, "delete")) ? "删除中" : "删除监测"}
                  </button>
                )}
              </div>
            </form>

            <div className="monitorToolbar">
              {["1h", "6h", "1d", "7d", "30d"].map((item) => (
                <button
                  key={item}
                  type="button"
                  className={monitorWindow === item ? "" : "secondary"}
                  onClick={() => setMonitorWindow(item)}
                >
                  {item}
                </button>
              ))}
            </div>

            {monitorDetail?.summary ? (
              <>
                <div className="monitorStats">
                  <span><strong>{formatLatency(monitorDetail.summary.last_latency_ms)}</strong><small>当前延迟</small></span>
                  <span><strong>{formatLatency(monitorDetail.summary.avg_latency_ms)}</strong><small>平均延迟</small></span>
                  <span><strong>{formatLatency(monitorDetail.summary.jitter_ms)}</strong><small>抖动</small></span>
                  <span><strong>{formatLoss(monitorDetail.summary.packet_loss)}</strong><small>丢包率</small></span>
                  <span><strong>{monitorDetail.summary.stability_score}</strong><small>稳定度</small></span>
                </div>
                <div className="monitorChart">
                  <ResponsiveContainer width="100%" height={280}>
                    <LineChart
                      data={monitorDetail.samples.map((sample) => ({
                        time: new Date(sample.checked_at).toLocaleString(),
                        latency: sample.success ? sample.latency_ms : null,
                        status: sample.success ? "ok" : sample.error || "loss",
                      }))}
                      margin={{ top: 10, right: 18, bottom: 4, left: 0 }}
                    >
                      <CartesianGrid stroke="#dce4e8" strokeDasharray="3 3" />
                      <XAxis dataKey="time" tick={{ fontSize: 11 }} minTickGap={42} />
                      <YAxis tick={{ fontSize: 11 }} unit="ms" />
                      <Tooltip />
                      <Line type="monotone" dataKey="latency" name="延迟" stroke="#216f86" strokeWidth={2} dot={false} connectNulls={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </>
            ) : (
              <div className="empty">尚无监测数据。保存监测后，Agent 会按刷新频率上报延迟样本。</div>
            )}
          </section>
        </div>
      )}

      {deleteDialogOpen && selectedConfig && (
        <div className="modalBackdrop" role="presentation">
          <section className="modalPanel compactModal" role="dialog" aria-modal="true" aria-labelledby="delete-config-title">
            <header className="modalHeader">
              <div>
                <h2 id="delete-config-title">删除配置</h2>
                <p className="muted">{selectedNode?.name || "节点"} / {selectedConfig.name}</p>
              </div>
              <button className="iconButton" onClick={() => setDeleteDialogOpen(false)}>
                <X size={18} />
              </button>
            </header>
            <div className="stack">
              <div className="empty">
                {selectedConfigIsManagedLink
                  ? "将从 Link42 中删除这条受管连接的双方记录。默认保留节点上的 WireGuard 配置和服务，之后仍可通过导入重新发现。"
                  : selectedConfigIsUnmanagedImport
                    ? "将只删除这条导入观察记录，不会修改节点上的原始配置文件或服务。"
                    : "将从 Link42 中删除这条 WireGuard 记录。默认保留节点上的配置文件和服务，之后仍可通过导入重新发现。"}
              </div>
              {!selectedConfigIsUnmanagedImport && (
                <label className="checkField dangerCheck">
                  <input
                    type="checkbox"
                    checked={deleteNodeConfig}
                    onChange={(event) => setDeleteNodeConfig(event.currentTarget.checked)}
                  />
                  <span>同时删除节点上的 WireGuard 配置文件和服务</span>
                </label>
              )}
              <div className="actionRow">
                <button className="secondary" onClick={() => setDeleteDialogOpen(false)}>取消</button>
                <button
                  className="danger"
                  disabled={actionPending(configActionKey(selectedConfig.id, "delete"))}
                  onClick={() => void runAction(deleteSelectedConfig, configActionKey(selectedConfig.id, "delete"))}
                >
                  {actionPending(configActionKey(selectedConfig.id, "delete"))
                    ? "删除中"
                    : deleteNodeConfig ? "删除记录并清理节点" : "仅删除 Link42 记录"}
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
