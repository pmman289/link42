/** 节点必须能访问此地址；与主控设置保持一致，不支持路径前缀。 */
export function normalizeControllerUrl(value: string): string | null {
  const text = value.trim();
  if (!/^https?:\/\/[^/?#]+\/?$/.test(text) || /[\s\u0000-\u001f\u007f'"\\]/.test(text)) return null;
  try {
    const url = new URL(text);
    if (!url.hostname || url.username || url.password || (url.port && Number(url.port) < 1)) return null;
    return text.replace(/\/$/, "");
  } catch {
    return null;
  }
}

function shellArg(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export function buildAgentInstallCommand(controllerUrl: string, nodeId: number, token: string, openwrt: boolean): string {
  const baseUrl = normalizeControllerUrl(controllerUrl);
  if (!baseUrl || !token) return "";
  return [
    `curl -fsSL ${shellArg(`${baseUrl}/sh/link42-agent.sh`)}`,
    "|", openwrt ? "env" : "sudo env",
    `LINK42_SERVER_URL=${shellArg(baseUrl)}`,
    `LINK42_NODE_ID=${shellArg(String(nodeId))}`,
    `LINK42_AGENT_TOKEN=${shellArg(token)}`, "sh",
  ].join(" ");
}
