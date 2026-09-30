import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite 开发服务器配置；API 请求在开发环境代理到 FastAPI。
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // 将大体积第三方库拆分，登录页不必和编辑器、图表、拓扑一起加载。
        manualChunks(id: string) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("@codemirror") || id.includes("@uiw") || id.includes("@lezer")) return "editor";
          if (id.includes("recharts") || id.includes("d3-")) return "charts";
          if (id.includes("@xyflow")) return "flow";
          if (id.includes("react-select") || id.includes("react-arborist")) return "select";
          if (id.includes("react-dom") || id.includes("/react/") || id.includes("scheduler")) return "react";
          return "vendor";
        },
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/third-party-api": "http://127.0.0.1:8000",
    },
  },
  preview: {
    host: "127.0.0.1",
  },
});
