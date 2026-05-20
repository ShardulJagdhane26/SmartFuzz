/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the SmartFuzz backend (REST + WebSocket). Set in Vercel's
   *  project settings to point at the deployed Render backend. Falls back to
   *  http://localhost:5000 for local development. */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
