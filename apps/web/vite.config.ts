import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite 开发服务器配置；API 请求在开发环境代理到 FastAPI。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
});

