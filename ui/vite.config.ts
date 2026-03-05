import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.VITE_CONTROL_PLANE_PROXY || "http://localhost:8080";

  return {
    server: {
      port: 5173,
      proxy: {
        "/v1": target,
        "/auth": target,
        "/healthz": target,
        "/readyz": target
      }
    },
    build: {
      outDir: "dist"
    }
  };
});
