import { describe, expect, it } from "vitest";
import { validateFormData } from "./formValidation";
import {
  loginFormRule,
  managedGreFormRule,
  managedWireGuardFormRule,
  nodeCreateFormRule,
  settingsFormRule,
} from "./formRules";

/** 根据普通对象构造浏览器 FormData，便于纯规则测试。 */
function formData(values: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(values)) data.set(name, value);
  return data;
}

describe("统一表单规则", () => {
  it("会聚合登录表单的必填错误", () => {
    const issues = validateFormData(formData({}), loginFormRule, undefined);

    expect(issues.map((issue) => issue.field)).toEqual(["username", "password"]);
  });

  it("允许设置表单的新密码留空，但拒绝过短密码", () => {
    const base = {
      controller_url: "https://link42.example.com",
      username: "pmman",
      site_title: "Link42",
    };

    expect(validateFormData(formData(base), settingsFormRule, undefined)).toEqual([]);
    expect(validateFormData(formData({ ...base, new_password: "12345" }), settingsFormRule, undefined)[0]?.field).toBe("new_password");
  });

  it("节点创建要求至少有一个入口地址", () => {
    const data = formData({ name: "node-a", controller_url: "https://link42.example.com" });

    expect(validateFormData(data, nodeCreateFormRule, { endpointIps: [] })[0]?.message).toContain("入口地址");
    expect(validateFormData(data, nodeCreateFormRule, { endpointIps: ["203.0.113.10"] })).toEqual([]);
  });

  it("WireGuard IPv6 隧道地址要求 MTU 不小于 1280", () => {
    const data = managedWireGuardData({
      local_tunnel_ips: "fd42::1/64",
      peer_tunnel_ips: "fd42::2/64",
      mtu: "1200",
    });

    const issues = validateFormData(data, managedWireGuardFormRule, { middlewareType: "udp2raw", requirePeerNode: true });

    expect(issues).toContainEqual({ field: "mtu", message: "使用 IPv6 接口地址时，MTU 不能小于 1280" });
  });

  it("udp2raw 服务端在对端时要求对端 WireGuard 监听端口", () => {
    const data = managedWireGuardData({ peer_listen_port: "" });

    const issues = validateFormData(data, managedWireGuardFormRule, { middlewareType: "udp2raw", requirePeerNode: true });

    expect(issues).toContainEqual({
      field: "peer_listen_port",
      message: "对端监听端口为必填项",
    });
  });

  it("udp2raw 客户端监听端口不能与同机 WireGuard 端口相同", () => {
    const data = managedWireGuardData({ local_listen_port: "23001" });

    const issues = validateFormData(data, managedWireGuardFormRule, { middlewareType: "udp2raw", requirePeerNode: true });

    expect(issues.some((issue) => issue.message.includes("客户端本地监听端口不能与同机"))).toBe(true);
  });

  it("udp2raw UDP 模式拒绝服务端与 WireGuard 共用 UDP 端口", () => {
    const data = managedWireGuardData({
      udp2raw_raw_mode: "udp",
      udp2raw_server_listen_port: "51821",
    });

    const issues = validateFormData(data, managedWireGuardFormRule, { middlewareType: "udp2raw", requirePeerNode: true });

    expect(issues.some((issue) => issue.message.includes("UDP 模式下"))).toBe(true);
  });

  it("udp2raw ICMP 模式允许服务端会话值与 WireGuard 端口数字相同", () => {
    const data = managedWireGuardData({
      udp2raw_raw_mode: "icmp",
      udp2raw_server_listen_port: "51821",
    });

    const issues = validateFormData(data, managedWireGuardFormRule, { middlewareType: "udp2raw", requirePeerNode: true });

    expect(issues).toEqual([]);
  });

  it("GRE IPv4 填写 TTL 时要求启用 PMTU", () => {
    const data = formData({
      local_interface_name: "gre_a",
      peer_interface_name: "gre_b",
      local_outer_ip: "203.0.113.10",
      peer_outer_ip: "198.51.100.20",
      local_tunnel_ips: "10.42.0.1/30",
      peer_tunnel_ips: "10.42.0.2/30",
      mtu: "1476",
      ttl: "63",
      risk_accepted: "on",
    });

    const issues = validateFormData(data, managedGreFormRule, undefined);

    expect(issues).toContainEqual({ field: "pmtudisc", message: "填写 GRE TTL 时必须启用路径 MTU 探测" });
  });
});

/** 构造一份默认合法的受管 WireGuard + udp2raw 表单。 */
function managedWireGuardData(overrides: Record<string, string> = {}): FormData {
  return formData({
    peer_node_id: "2",
    local_interface_name: "wg_a",
    peer_interface_name: "wg_b",
    local_tunnel_ips: "10.42.0.1/32",
    peer_tunnel_ips: "10.42.0.2/32",
    local_endpoint_host: "203.0.113.10",
    peer_endpoint_host: "198.51.100.20",
    peer_listen_port: "51821",
    mtu: "1300",
    udp2raw_enabled: "on",
    udp2raw_server_side: "peer",
    udp2raw_server_connect_host: "198.51.100.20",
    udp2raw_server_listen_host: "0.0.0.0",
    udp2raw_server_listen_port: "23002",
    udp2raw_server_forward_host: "127.0.0.1",
    udp2raw_server_forward_port: "51821",
    udp2raw_client_listen_host: "127.0.0.1",
    udp2raw_client_listen_port: "23001",
    udp2raw_raw_mode: "faketcp",
    ...overrides,
  });
}
