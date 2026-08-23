import type { FormFieldRule, FormRule, FormValidationIssue, FormValues } from "./formValidation";

type FieldValidator = NonNullable<FormFieldRule["validate"]>;

export type NodeFormContext = {
  endpointIps: string[];
};

export type ManagedWireGuardFormContext = {
  middlewareType: "none" | "udp2raw" | "mimic";
  requirePeerNode: boolean;
};

/** 读取字段的首个字符串值。 */
export function stringValue(value: FormDataEntryValue | FormDataEntryValue[] | undefined): string {
  const first = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" ? first.trim() : "";
}

/** 读取指定字段的去空字符串。 */
export function fieldString(values: FormValues, name: string): string {
  return stringValue(values[name]);
}

/** 判断指定复选框是否处于选中状态。 */
export function fieldChecked(values: FormValues, name: string): boolean {
  return fieldString(values, name) === "on";
}

/** 校验整数文本并返回用户可理解的错误。 */
function integerRule(label: string, minimum?: number, maximum?: number): FieldValidator {
  return (value) => {
    const text = stringValue(value);
    if (!/^-?\d+$/.test(text)) return `${label}必须是整数`;
    const parsed = Number(text);
    if (!Number.isSafeInteger(parsed)) return `${label}超出可支持范围`;
    if (minimum !== undefined && parsed < minimum) return `${label}不能小于 ${minimum}`;
    if (maximum !== undefined && parsed > maximum) return `${label}不能大于 ${maximum}`;
    return null;
  };
}

/** 校验端口字段。 */
function portRule(label: string): FieldValidator {
  return integerRule(label, 1, 65535);
}

/** 校验 MTU 字段。 */
function mtuRule(value: FormDataEntryValue | FormDataEntryValue[] | undefined): string | null {
  const text = stringValue(value);
  if (!/^\d+$/.test(text)) return "MTU 必须是整数";
  const parsed = Number(text);
  return Number.isSafeInteger(parsed) && parsed >= 576 && parsed <= 9000
    ? null
    : "MTU 必须在 576-9000 之间";
}

/** 校验 HTTP 或 HTTPS URL。 */
function httpUrlRule(label: string): FieldValidator {
  return (value) => {
    try {
      const parsed = new URL(stringValue(value));
      return ["http:", "https:"].includes(parsed.protocol) ? null : `${label}必须以 http:// 或 https:// 开头`;
    } catch {
      return `${label}格式不正确`;
    }
  };
}

/** 校验 IPv4 字面量。 */
function isIpv4Address(value: string): boolean {
  const octets = value.split(".");
  return octets.length === 4 && octets.every((item) => /^\d+$/.test(item) && Number(item) >= 0 && Number(item) <= 255);
}

/** 校验 IPv6 字面量。 */
function isIpv6Address(value: string): boolean {
  if (!value.includes(":")) return false;
  const [address, zone, ...rest] = value.split("%");
  if (rest.length || (zone !== undefined && !/^[A-Za-z0-9_.-]{1,15}$/.test(zone))) return false;
  try {
    new URL(`http://[${address}]/`);
    return true;
  } catch {
    return false;
  }
}

/** 判断文本是否为 IP 字面量。 */
export function isIpAddress(value: string): boolean {
  const text = value.trim();
  return isIpv4Address(text) || isIpv6Address(text);
}

/** 返回 IP 地址版本，非法地址返回 0。 */
export function ipVersion(value: string): 0 | 4 | 6 {
  if (isIpv4Address(value.trim())) return 4;
  if (isIpv6Address(value.trim())) return 6;
  return 0;
}

/** 校验 CIDR 列表文本。 */
export function isCidrList(value: string): boolean {
  const items = value.split(/[,\n]+/).map((item) => item.trim()).filter(Boolean);
  return items.every((item) => {
    const [address, prefix, ...rest] = item.split("/");
    if (!address || !prefix || rest.length || address.includes("%") || !/^\d+$/.test(prefix)) return false;
    const version = ipVersion(address);
    const number = Number(prefix);
    return version === 4 ? number <= 32 : version === 6 ? number <= 128 : false;
  });
}

/** 校验可选 CIDR 列表字段。 */
function cidrListRule(label: string): FieldValidator {
  return (value) => isCidrList(stringValue(value)) ? null : `${label}必须使用 CIDR 格式，多个地址请用逗号分隔`;
}

/** 判断 CIDR 列表中是否包含 IPv6 地址。 */
function containsIpv6Cidr(value: string): boolean {
  return value.split(/[,\n]+/).some((item) => item.split("/")[0]?.trim().includes(":"));
}

/** 校验包含 IPv6 隧道地址时的最小 MTU。 */
function validateWireGuardMtu(values: FormValues, tunnelFields: string[]): FormValidationIssue[] {
  const mtuText = fieldString(values, "mtu") || "1420";
  const hasIpv6 = tunnelFields.some((name) => containsIpv6Cidr(fieldString(values, name)));
  return hasIpv6 && Number(mtuText) < 1280
    ? [{ field: "mtu", message: "使用 IPv6 接口地址时，MTU 不能小于 1280" }]
    : [];
}

/** 校验 WireGuard 密钥的基础格式。 */
function wireGuardKeyRule(label: string): FieldValidator {
  return (value) => /^[A-Za-z0-9+/]{43}=$/.test(stringValue(value)) ? null : `${label}应为 44 位 base64 字符串`;
}

/** 校验 Linux WireGuard 接口名。 */
function linuxInterfaceRule(label: string): FieldValidator {
  return (value) => /^[\p{L}\p{N}_.-]{1,15}$/u.test(stringValue(value))
    ? null
    : `${label}最多 15 个字符，只能包含字母、数字、下划线、点和短横线`;
}

/** 校验上传 Logo 的类型和大小。 */
function siteLogoRule(value: FormDataEntryValue | FormDataEntryValue[] | undefined): string | null {
  const first = Array.isArray(value) ? value[0] : value;
  if (!(first instanceof File)) return "请选择有效的 Logo 文件";
  if (first.size > 3 * 1024 * 1024) return "Logo 文件不能超过 3 MiB";
  return ["image/png", "image/jpeg", "image/webp"].includes(first.type)
    ? null
    : "Logo 仅支持 PNG、JPEG 或 WebP 格式";
}

/** 校验 GRE 接口名。 */
function greInterfaceRule(label: string): FieldValidator {
  return (value) => /^[A-Za-z0-9_-]{1,15}$/.test(stringValue(value))
    ? null
    : `${label}最多 15 个字符，只能包含字母、数字、下划线和连字符`;
}

/** 校验 GRE Key。 */
function greKeyRule(value: FormDataEntryValue | FormDataEntryValue[] | undefined): string | null {
  const text = stringValue(value);
  if (!/^\d+$/.test(text)) return "GRE Key 必须是整数";
  const parsed = Number(text);
  return Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 4294967295
    ? null
    : "GRE Key 必须在 0-4294967295 之间";
}

/** 创建字段规则的简写。 */
function field<Context = unknown>(rule: FormFieldRule<Context>): FormFieldRule<Context> {
  return rule;
}

/** 校验 GRE 外层地址和高级映射地址之间的关系。 */
function validateGreOuterAddresses(values: FormValues, managed: boolean): FormValidationIssue[] {
  const localName = managed ? "local_outer_ip" : "outer_local_ip";
  const peerName = managed ? "peer_outer_ip" : "outer_remote_ip";
  const local = fieldString(values, localName);
  const peer = fieldString(values, peerName);
  const version = ipVersion(local);
  if (!version || ipVersion(peer) !== version) {
    return [{ field: peerName, message: "GRE 双方外层地址必须是同一版本的 IPv4 或 IPv6 地址" }];
  }
  if (local === peer) return [{ field: peerName, message: "GRE 双方外层地址不能相同" }];
  if (managed) {
    for (const name of ["local_bind_ip", "local_remote_ip", "peer_bind_ip", "peer_remote_ip"]) {
      const value = fieldString(values, name);
      if (value && ipVersion(value) !== version) {
        return [{ field: name, message: "GRE 高级外层映射地址必须与主外层地址使用相同 IP 版本" }];
      }
    }
  }
  if (version === 4 && fieldString(values, "ttl") && !fieldChecked(values, "pmtudisc")) {
    return [{ field: "pmtudisc", message: "填写 GRE TTL 时必须启用路径 MTU 探测" }];
  }
  if (version === 4 && fieldChecked(values, "encaplimit_enabled")) {
    return [{ field: "encaplimit_enabled", message: "IPv6 封装限制仅适用于 GRE over IPv6" }];
  }
  return [];
}

/** 校验 udp2raw 和同机 WireGuard 监听端口不会冲突。 */
function validateUdp2Raw(values: FormValues): FormValidationIssue[] {
  const enabled = fieldChecked(values, "udp2raw_enabled") || fieldString(values, "udp2raw_enabled_state") === "on";
  if (!enabled) return [];
  const serverSide = fieldString(values, "udp2raw_server_side") || "peer";
  const rawMode = fieldString(values, "udp2raw_raw_mode") || "faketcp";
  const localWireGuardPort = fieldString(values, "local_listen_port");
  const peerWireGuardPort = fieldString(values, "peer_listen_port");
  const serverWireGuardField = serverSide === "local" ? "local_listen_port" : "peer_listen_port";
  const clientWireGuardField = serverSide === "local" ? "peer_listen_port" : "local_listen_port";
  const serverWireGuardPort = serverSide === "local" ? localWireGuardPort : peerWireGuardPort;
  const clientWireGuardPort = serverSide === "local" ? peerWireGuardPort : localWireGuardPort;
  const serverSessionPort = fieldString(values, "udp2raw_server_listen_port");
  const clientListenPort = fieldString(values, "udp2raw_client_listen_port");
  const issues: FormValidationIssue[] = [];
  if (clientWireGuardPort && clientWireGuardPort === clientListenPort) {
    issues.push({ field: clientWireGuardField, message: "udp2raw 客户端本地监听端口不能与同机 WireGuard 监听端口相同" });
  }
  if (rawMode === "udp" && serverWireGuardPort && serverWireGuardPort === serverSessionPort) {
    issues.push({ field: serverWireGuardField, message: "UDP 模式下，udp2raw 服务端会话端口不能与同机 WireGuard 监听端口相同" });
  }
  return issues;
}

export const loginFormRule: FormRule = {
  fields: [field({ name: "username", label: "用户名", required: true }), field({ name: "password", label: "密码", required: true })],
};

export const settingsFormRule: FormRule = {
  fields: [
    field({ name: "controller_url", label: "主控访问地址", required: true, validate: httpUrlRule("主控访问地址") }),
    field({ name: "username", label: "用户名", required: true }),
    field({ name: "site_title", label: "站点标题", required: true }),
    field({ name: "site_logo_file", label: "Logo", validate: siteLogoRule }),
    field({ name: "new_password", label: "新密码", validate: (value) => stringValue(value).length >= 6 ? null : "新密码至少需要 6 个字符" }),
  ],
};

export const lookingGlassTokenFormRule: FormRule = {
  fields: [field({ name: "lg_name", label: "Token 名称", required: true })],
};

export const portInventoryEntryFormRule: FormRule = {
  fields: [
    field({ name: "protocol", label: "协议", required: true, validate: (value) => ["TCP", "UDP"].includes(stringValue(value)) ? null : "协议只能选择 TCP 或 UDP" }),
    field({ name: "port", label: "端口号", required: true, validate: portRule("端口号") }),
  ],
};

export const linkMonitorFormRule: FormRule = {
  fields: [
    field({ name: "target_host", label: "目标 IP", required: true, validate: (value) => isIpAddress(stringValue(value)) ? null : "目标必须填写 IPv4 或 IPv6 地址" }),
    field({ name: "interval_seconds", label: "检测间隔", required: true, validate: integerRule("检测间隔", 1, 300) }),
    field({ name: "retention_days", label: "保留时间", required: true, validate: (value) => ["1", "7", "30", "90"].includes(stringValue(value)) ? null : "请选择有效的历史保留时间" }),
  ],
};

export const nodeCreateFormRule: FormRule<NodeFormContext> = {
  fields: [
    field({ name: "name", label: "节点名称", required: true }),
    field({ name: "controller_url", label: "主控地址", required: true, validate: httpUrlRule("主控地址") }),
  ],
  validate: (_values, context) => context.endpointIps.length > 0 ? [] : [{ message: "请至少添加一个节点入口地址" }],
};

export const nodeEditFormRule: FormRule<NodeFormContext> = {
  fields: [field({ name: "name", label: "节点名称", required: true })],
  validate: (_values, context) => context.endpointIps.length > 0 ? [] : [{ message: "请至少保留一个节点入口地址" }],
};

export const wireGuardConfigFormRule: FormRule = {
  fields: [
    field({ name: "name", label: "接口名称", required: true, validate: linuxInterfaceRule("接口名称") }),
    field({ name: "tunnel_ips", label: "本端隧道地址", validate: cidrListRule("本端隧道地址") }),
    field({ name: "listen_port", label: "监听端口", validate: portRule("监听端口") }),
    field({ name: "mtu", label: "MTU", validate: mtuRule }),
    field({ name: "public_key", label: "本端公钥", validate: wireGuardKeyRule("本端公钥") }),
    field({ name: "private_key", label: "本端私钥", validate: wireGuardKeyRule("本端私钥") }),
    field({ name: "peer_public_key", label: "对端公钥", validate: wireGuardKeyRule("对端公钥") }),
    field({ name: "peer_preshared_key", label: "预共享密钥", validate: wireGuardKeyRule("预共享密钥") }),
    field({ name: "peer_allowed_ips", label: "经对端路由", validate: cidrListRule("经对端路由") }),
    field({ name: "peer_endpoint_port", label: "对端入口端口", validate: portRule("对端入口端口") }),
    field({ name: "peer_persistent_keepalive", label: "对端保活间隔", validate: integerRule("对端保活间隔", 0, 65535) }),
  ],
  validate: (values) => {
    const issues = validateWireGuardMtu(values, ["tunnel_ips"]);
    const peerFields = [
      "peer_name",
      "peer_preshared_key",
      "peer_allowed_ips",
      "peer_endpoint_host",
      "peer_endpoint_port",
      "peer_persistent_keepalive",
      "peer_custom_config",
    ];
    if (peerFields.some((name) => fieldString(values, name)) && !fieldString(values, "peer_public_key")) {
      issues.push({ field: "peer_public_key", message: "填写对端信息时必须填写对端公钥" });
    }
    return issues;
  },
};

export const wireGuardPeerFormRule: FormRule = {
  fields: [
    field({ name: "public_key", label: "对端公钥", required: true, validate: wireGuardKeyRule("对端公钥") }),
    field({ name: "preshared_key", label: "预共享密钥", validate: wireGuardKeyRule("预共享密钥") }),
    field({ name: "allowed_ips", label: "经对端路由", validate: cidrListRule("经对端路由") }),
    field({ name: "endpoint_port", label: "对端入口端口", validate: portRule("对端入口端口") }),
    field({ name: "persistent_keepalive", label: "保活间隔", validate: integerRule("保活间隔", 0, 65535) }),
  ],
  validate: (values) => {
    const host = fieldString(values, "endpoint_host");
    const port = fieldString(values, "endpoint_port");
    if (host && !port) return [{ field: "endpoint_port", message: "填写对端入口地址时必须同时填写入口端口" }];
    if (!host && port) return [{ field: "endpoint_host", message: "填写对端入口端口时必须同时填写入口地址" }];
    return [];
  },
};

export const managedWireGuardFormRule: FormRule<ManagedWireGuardFormContext> = {
  fields: [
    field<ManagedWireGuardFormContext>({ name: "peer_node_id", label: "对端节点", required: (_values, context) => context.requirePeerNode }),
    field({ name: "local_interface_name", label: "本端接口名称", required: true, validate: linuxInterfaceRule("本端接口名称") }),
    field({ name: "peer_interface_name", label: "对端接口名称", required: true, validate: linuxInterfaceRule("对端接口名称") }),
    field({ name: "local_tunnel_ips", label: "本端隧道地址", required: true, validate: cidrListRule("本端隧道地址") }),
    field({ name: "peer_tunnel_ips", label: "对端隧道地址", required: true, validate: cidrListRule("对端隧道地址") }),
    field({ name: "local_allowed_ips", label: "本端经对端路由", validate: cidrListRule("本端经对端路由") }),
    field({ name: "peer_allowed_ips", label: "对端经本端路由", validate: cidrListRule("对端经本端路由") }),
    field<ManagedWireGuardFormContext>({
      name: "local_listen_port",
      label: "本端监听端口",
      required: (values, context) => context.middlewareType === "mimic"
        || (context.middlewareType === "udp2raw" && (fieldString(values, "udp2raw_server_side") || "peer") === "local"),
      validate: portRule("本端监听端口"),
    }),
    field<ManagedWireGuardFormContext>({
      name: "peer_listen_port",
      label: "对端监听端口",
      required: (values, context) => context.middlewareType === "mimic"
        || (context.middlewareType === "udp2raw" && (fieldString(values, "udp2raw_server_side") || "peer") === "peer"),
      validate: portRule("对端监听端口"),
    }),
    field<ManagedWireGuardFormContext>({ name: "local_endpoint_host", label: "本端入口地址", required: (_values, context) => context.middlewareType === "mimic" }),
    field<ManagedWireGuardFormContext>({ name: "peer_endpoint_host", label: "对端入口地址", required: (_values, context) => context.middlewareType === "mimic" }),
    field({ name: "local_endpoint_port", label: "本端入口端口", validate: portRule("本端入口端口") }),
    field({ name: "peer_endpoint_port", label: "对端入口端口", validate: portRule("对端入口端口") }),
    field({ name: "mtu", label: "MTU", validate: mtuRule }),
    field({ name: "persistent_keepalive", label: "保活间隔", validate: integerRule("保活间隔", 0, 65535) }),
    field({ name: "udp2raw_server_connect_host", label: "客户端连接服务端 IP", required: (_values, context) => context.middlewareType === "udp2raw", validate: (value) => isIpAddress(stringValue(value)) ? null : "客户端连接服务端地址必须是 IP，不能填写域名" }),
    field({ name: "udp2raw_server_listen_host", label: "服务端监听地址", required: (_values, context) => context.middlewareType === "udp2raw", validate: (value) => isIpAddress(stringValue(value)) ? null : "服务端监听地址必须是 IP" }),
    field<ManagedWireGuardFormContext>({ name: "udp2raw_server_listen_port", label: "服务端会话端口", required: (_values, context) => context.middlewareType === "udp2raw", validate: portRule("服务端会话端口") }),
    field({ name: "udp2raw_server_forward_host", label: "服务端转发到 IP", required: (_values, context) => context.middlewareType === "udp2raw", validate: (value) => isIpAddress(stringValue(value)) ? null : "服务端转发地址必须是 IP" }),
    field({ name: "udp2raw_server_forward_port", label: "服务端转发到端口", validate: portRule("服务端转发到端口") }),
    field({ name: "udp2raw_client_listen_host", label: "客户端本地监听地址", required: (_values, context) => context.middlewareType === "udp2raw", validate: (value) => isIpAddress(stringValue(value)) ? null : "客户端本地监听地址必须是 IP" }),
    field<ManagedWireGuardFormContext>({ name: "udp2raw_client_listen_port", label: "客户端本地监听端口", required: (_values, context) => context.middlewareType === "udp2raw", validate: portRule("客户端本地监听端口") }),
    field({ name: "mimic_padding", label: "mimic 填充长度", validate: integerRule("mimic 填充长度", 0, 16) }),
    field({ name: "mimic_handshake_interval", label: "mimic 握手间隔", validate: integerRule("mimic 握手间隔", 0) }),
    field({ name: "mimic_keepalive_interval", label: "mimic 保活时间", validate: integerRule("mimic 保活时间", 0) }),
    field<ManagedWireGuardFormContext>({ name: "mimic_local_bind_interface", label: "mimic 本端出口网卡", required: (_values, context) => context.middlewareType === "mimic" }),
    field<ManagedWireGuardFormContext>({ name: "mimic_peer_bind_interface", label: "mimic 对端出口网卡", required: (_values, context) => context.middlewareType === "mimic" }),
    field({ name: "mimic_xdp_mode", label: "mimic XDP 模式", validate: (value) => ["auto", "native", "skb"].includes(stringValue(value)) ? null : "mimic XDP 模式无效" }),
  ],
  validate: (values, context) => {
    const issues = validateWireGuardMtu(values, ["local_tunnel_ips", "peer_tunnel_ips"]);
    if (!fieldString(values, "local_endpoint_host") && !fieldString(values, "peer_endpoint_host")) {
      issues.push({ field: "local_endpoint_host", message: "本端或对端至少需要填写一个入口地址" });
    }
    if (context.middlewareType === "udp2raw") issues.push(...validateUdp2Raw(values));
    return issues;
  },
};

const greCommonFields: FormFieldRule[] = [
  field({ name: "local_interface_name", label: "本端接口名称", required: true, validate: greInterfaceRule("本端接口名称") }),
  field({ name: "peer_interface_name", label: "对端接口名称", required: true, validate: greInterfaceRule("对端接口名称") }),
  field({ name: "local_outer_ip", label: "本端外层地址", required: true, validate: (value) => isIpAddress(stringValue(value)) ? null : "本端外层地址必须是 IP" }),
  field({ name: "peer_outer_ip", label: "对端外层地址", required: true, validate: (value) => isIpAddress(stringValue(value)) ? null : "对端外层地址必须是 IP" }),
  field({ name: "local_bind_ip", label: "本端实际绑定 IP", validate: (value) => isIpAddress(stringValue(value)) ? null : "本端实际绑定地址必须是 IP" }),
  field({ name: "local_remote_ip", label: "本端实际连接 IP", validate: (value) => isIpAddress(stringValue(value)) ? null : "本端实际连接地址必须是 IP" }),
  field({ name: "peer_bind_ip", label: "对端实际绑定 IP", validate: (value) => isIpAddress(stringValue(value)) ? null : "对端实际绑定地址必须是 IP" }),
  field({ name: "peer_remote_ip", label: "对端实际连接 IP", validate: (value) => isIpAddress(stringValue(value)) ? null : "对端实际连接地址必须是 IP" }),
  field({ name: "local_tunnel_ips", label: "本端隧道地址", required: true, validate: cidrListRule("本端隧道地址") }),
  field({ name: "peer_tunnel_ips", label: "对端隧道地址", required: true, validate: cidrListRule("对端隧道地址") }),
  field({ name: "local_routes", label: "本端经隧道路由", validate: cidrListRule("本端经隧道路由") }),
  field({ name: "peer_routes", label: "对端经隧道路由", validate: cidrListRule("对端经隧道路由") }),
  field({ name: "mtu", label: "MTU", validate: mtuRule }),
  field({ name: "gre_key", label: "GRE Key", validate: greKeyRule }),
  field({ name: "ttl", label: "TTL", validate: integerRule("TTL", 1, 255) }),
  field({ name: "encaplimit", label: "IPv6 封装限制", validate: integerRule("IPv6 封装限制", 0, 255) }),
];

export const managedGreFormRule: FormRule = {
  fields: [...greCommonFields, field({ name: "risk_accepted", label: "GRE 风险确认", required: true })],
  validate: (values) => validateGreOuterAddresses(values, true),
};

export const managedGreCreateFormRule: FormRule = {
  fields: [
    field({ name: "peer_node_id", label: "对端节点", required: true }),
    ...managedGreFormRule.fields,
  ],
  validate: managedGreFormRule.validate,
};

export const manualGreFormRule: FormRule = {
  fields: [
    field({ name: "interface_name", label: "本端接口名称", required: true, validate: greInterfaceRule("本端接口名称") }),
    field({ name: "peer_interface_name", label: "对端接口名称", validate: greInterfaceRule("对端接口名称") }),
    field({ name: "outer_local_ip", label: "本端外层地址", required: true, validate: (value) => isIpAddress(stringValue(value)) ? null : "本端外层地址必须是 IP" }),
    field({ name: "outer_remote_ip", label: "对端外层地址", required: true, validate: (value) => isIpAddress(stringValue(value)) ? null : "对端外层地址必须是 IP" }),
    field({ name: "tunnel_ips", label: "本端隧道地址", required: true, validate: cidrListRule("本端隧道地址") }),
    field({ name: "peer_tunnel_ips", label: "对端隧道地址", validate: cidrListRule("对端隧道地址") }),
    field({ name: "routes", label: "经隧道路由", validate: cidrListRule("经隧道路由") }),
    field({ name: "mtu", label: "MTU", validate: mtuRule }),
    field({ name: "gre_key", label: "GRE Key", validate: greKeyRule }),
    field({ name: "ttl", label: "TTL", validate: integerRule("TTL", 1, 255) }),
    field({ name: "encaplimit", label: "IPv6 封装限制", validate: integerRule("IPv6 封装限制", 0, 255) }),
    field({ name: "risk_accepted", label: "GRE 风险确认", required: true }),
  ],
  validate: (values) => validateGreOuterAddresses(values, false),
};
