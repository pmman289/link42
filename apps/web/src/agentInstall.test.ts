import { describe, expect, it } from "vitest";
import { buildAgentInstallCommand, normalizeControllerUrl } from "./agentInstall";

describe("controller hosted Agent installation", () => {
  it.each(["https://panel.example:8443", "http://192.0.2.1:8000", "http://[2001:db8::1]:8000"])("uses %s for both downloads and Agent API", (base) => {
    const command = buildAgentInstallCommand(`${base}/`, 2, "token'with quote", false);
    expect(command).toContain(`curl -fsSL '${base}/sh/link42-agent.sh'`);
    expect(command).toContain(`LINK42_SERVER_URL='${base}'`);
    expect(command).toContain("LINK42_AGENT_TOKEN='token'\\''with quote'");
    expect(command).toContain("| sudo env ");
  });
  it.each(["", "/api", "https://host/path", "https://host/../", "https://user@host", "https://host?q=1", "https://host/#x", "https://host:0", "https://host:65536", "https://ho st", "https://host\\evil", "https://ho'st"])("rejects invalid address %s", (url) => {
    expect(normalizeControllerUrl(url)).toBeNull();
    expect(buildAgentInstallCommand(url, 1, "secret", false)).toBe("");
  });
  it("requires a token and preserves OpenWrt command privileges", () => {
    expect(buildAgentInstallCommand("http://host", 1, "", false)).toBe("");
    expect(buildAgentInstallCommand("http://host", 1, "token", true)).toContain("| env ");
  });
});
