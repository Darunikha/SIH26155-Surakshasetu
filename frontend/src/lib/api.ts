import axios, { AxiosError } from "axios";
import { useAuthStore } from "./auth-store";
import type {
  ApiEnvelope,
  AssetContext,
  AttackGraphResult,
  BlockchainStatus,
  BlockchainTransaction,
  ComplianceResult,
  ConfigurationSummary,
  ConfigurationVersion,
  Device,
  Finding,
  OptimizerRun,
  Project,
  RemediationPlan,
  ReportMeta,
  RiskResult,
  Scan,
  ToolDefinition,
  UnknownPattern,
  VerifyResult,
} from "./types";

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const http = axios.create({ baseURL: API_BASE_URL });

http.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export class ApiError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** True only for the backend's explicit AI_UNAVAILABLE error (Ollama
 * unreachable/model not pulled) -- callers should show AiUnavailableNotice
 * only for this, never for auth/validation/network errors that happen to
 * occur on an AI-backed action. */
export function isAiUnavailableError(err: unknown): err is ApiError {
  return err instanceof ApiError && err.code === "AI_UNAVAILABLE";
}

// A JWT_EXPIRES_MINUTES=60 token going stale mid-session (see backend/.env)
// used to surface as whatever ad-hoc error UI the current page happened to
// have -- e.g. the AI Assistant showing "AI not connected" for what was
// actually an expired-token 401. Clearing auth here means AppShell's
// `!token` effect (src/components/layout/app-shell.tsx) takes over and
// bounces to /login uniformly, regardless of which page/action hit the 401.
http.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiEnvelope<unknown>>) => {
    const code = error.response?.data?.error?.code;
    if (error.response?.status === 401 || code === "UNAUTHORIZED") {
      useAuthStore.getState().logout();
    }
    return Promise.reject(error);
  }
);

async function unwrap<T>(promise: Promise<{ data: ApiEnvelope<T> }>): Promise<T> {
  try {
    const res = await promise;
    if (!res.data.success || res.data.data === null) {
      throw new ApiError(res.data.error?.code || "UNKNOWN", res.data.error?.message || "Unknown error");
    }
    return res.data.data;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    const axErr = err as AxiosError<ApiEnvelope<unknown>>;
    const envelope = axErr.response?.data;
    throw new ApiError(envelope?.error?.code || "NETWORK_ERROR", envelope?.error?.message || axErr.message);
  }
}

// --- Auth ---
export const authApi = {
  login: (email: string, password: string) =>
    unwrap<{ token: string; user: { user_id: string; email: string; full_name: string; role: string } }>(
      http.post("/api/auth/login", { email, password })
    ),
  register: (body: { email: string; password: string; full_name: string; role: string }) =>
    unwrap<{ token: string; user: { user_id: string; email: string; full_name: string; role: string } }>(
      http.post("/api/auth/register", body)
    ),
};

// --- Projects ---
export const projectsApi = {
  list: () => unwrap<Project[]>(http.get("/api/projects")),
  create: (body: { name: string; description?: string }) => unwrap<Project>(http.post("/api/projects", body)),
};

// --- Devices ---
export const devicesApi = {
  list: (projectId?: string) => unwrap<Device[]>(http.get("/api/devices", { params: { project_id: projectId } })),
  get: (deviceId: string) => unwrap<Device>(http.get(`/api/devices/${deviceId}`)),
  create: (body: { project_id: string; name: string; asset_context?: Partial<AssetContext> }) =>
    unwrap<Device>(http.post("/api/devices", body)),
  updateAssetContext: (deviceId: string, assetContext: AssetContext) =>
    unwrap<{ device_id: string; updated: boolean }>(
      http.put(`/api/devices/${deviceId}/asset-context`, { asset_context: assetContext })
    ),
};

// --- Configurations ---
export const configurationsApi = {
  list: (projectId?: string) => unwrap<ConfigurationSummary[]>(http.get("/api/configurations", { params: { project_id: projectId } })),
  get: (configurationId: string) => unwrap<ConfigurationSummary>(http.get(`/api/configurations/${configurationId}`)),
  versions: (configurationId: string) => unwrap<ConfigurationVersion[]>(http.get(`/api/configurations/${configurationId}/versions`)),
  getVersion: (configurationId: string, version: number) =>
    unwrap<ConfigurationVersion>(http.get(`/api/configurations/${configurationId}/versions/${version}`)),
  upload: (params: { projectId: string; deviceId?: string; deviceName?: string; file: File }) => {
    const form = new FormData();
    form.append("file", params.file);
    const query = new URLSearchParams({ project_id: params.projectId });
    if (params.deviceId) query.set("device_id", params.deviceId);
    if (params.deviceName) query.set("device_name", params.deviceName);
    return unwrap<ConfigurationVersion & { device_id: string }>(
      http.post(`/api/configurations/upload?${query.toString()}`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      })
    );
  },
  bulkUpload: (projectId: string, files: File[]) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    return unwrap<{ uploaded: number; results: Record<string, unknown>[] }>(
      http.post(`/api/configurations/bulk?project_id=${projectId}`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      })
    );
  },
  confirmVendor: (configurationId: string, version: number, vendor: string) =>
    unwrap<Record<string, unknown>>(
      http.post(`/api/configurations/${configurationId}/versions/${version}/confirm-vendor?vendor=${vendor}`)
    ),
};

// --- Scans ---
export const scansApi = {
  list: (params?: { deviceId?: string; projectId?: string }) =>
    unwrap<Scan[]>(http.get("/api/scans", { params: { device_id: params?.deviceId, project_id: params?.projectId } })),
  start: (deviceId: string) => unwrap<Scan>(http.post("/api/scans", { device_id: deviceId })),
  get: (scanId: string) => unwrap<Scan>(http.get(`/api/scans/${scanId}`)),
  status: (scanId: string) => unwrap<{ scan_id: string; status: string; error_message: string | null }>(http.get(`/api/scans/${scanId}/status`)),
  compliance: (scanId: string) => unwrap<ComplianceResult>(http.get(`/api/scans/${scanId}/compliance`)),
  findings: (scanId: string) => unwrap<Finding[]>(http.get(`/api/scans/${scanId}/findings`)),
  risk: (scanId: string) => unwrap<RiskResult>(http.get(`/api/scans/${scanId}/risk`)),
  attackPaths: (scanId: string) => unwrap<AttackGraphResult>(http.get(`/api/scans/${scanId}/attack-paths`)),
  riskAiSummary: (scanId: string) => unwrap<AiSummary>(http.post(`/api/scans/${scanId}/risk/ai-summary`)),
};

// --- Optimizer ---
export const optimizerApi = {
  run: (scanId: string, budget?: number) => unwrap<OptimizerRun>(http.post("/api/optimizer/run", { scan_id: scanId, budget })),
  get: (optimizerRunId: string) => unwrap<OptimizerRun>(http.get(`/api/optimizer/${optimizerRunId}`)),
  aiSummary: (optimizerRunId: string) => unwrap<AiSummary>(http.post(`/api/optimizer/${optimizerRunId}/ai-summary`)),
};

export interface AiSummary {
  summary: string;
  model: string;
  ai_available: boolean;
}

// --- Findings ---
export const findingsApi = {
  get: (findingId: string) =>
    unwrap<Finding & { device: Device | null; related_attack_paths: unknown[]; remediation: RemediationPlan | null }>(
      http.get(`/api/findings/${findingId}`)
    ),
};

// --- Remediation ---
export const remediationApi = {
  generate: (findingId: string) => unwrap<RemediationPlan>(http.post("/api/remediation/generate", { finding_id: findingId })),
  approve: (remediationId: string) => unwrap<{ remediation_id: string; status: string }>(http.post(`/api/remediation/${remediationId}/approve`)),
  validate: (remediationId: string) =>
    unwrap<{ remediation_id: string; status: string; simulation_passed: boolean; note: string }>(
      http.post(`/api/remediation/validate?remediation_id=${remediationId}`)
    ),
  get: (remediationId: string) => unwrap<RemediationPlan>(http.get(`/api/remediation/${remediationId}`)),
};

// --- Training ---
export const trainingApi = {
  unknown: (vendor?: string) => unwrap<UnknownPattern[]>(http.get("/api/training/unknown", { params: { vendor } })),
  suggest: (vendor: string, rawLine: string) =>
    unwrap<{ category: string; meaning: string; confidence: number }>(
      http.post("/api/training/suggest", { vendor, raw_line: rawLine })
    ),
  confirmMapping: (body: { vendor: string; raw_line: string; category: string; ir_field_path: string; meaning: string; decision: string }) =>
    unwrap<Record<string, unknown>>(http.post("/api/training/mapping", body)),
};

// --- Blockchain ---
export const blockchainApi = {
  status: () => unwrap<BlockchainStatus>(http.get("/api/blockchain/status")),
  verify: (auditId: string) => unwrap<VerifyResult>(http.post("/api/blockchain/verify", { audit_id: auditId })),
  auditHistory: (auditId: string) => unwrap<BlockchainTransaction[]>(http.get(`/api/blockchain/audit/${auditId}`)),
  deviceHistory: (deviceId: string) => unwrap<BlockchainTransaction[]>(http.get(`/api/blockchain/history/${deviceId}`)),
};

// --- Reports ---
export const reportsApi = {
  generate: (scanId: string) => unwrap<ReportMeta>(http.post("/api/reports/generate", { scan_id: scanId })),
  get: (reportId: string) => unwrap<ReportMeta>(http.get(`/api/reports/${reportId}`)),
  // The download route requires the same Bearer-token auth as every other
  // endpoint, but a plain `<a href>` navigation can't attach a header --
  // fetching it through the authenticated `http` client and returning a
  // blob (see downloadBlob() in lib/utils.ts) is what actually works.
  download: (reportId: string) => http.get(`/api/reports/${reportId}/download`, { responseType: "blob" }),
};

// --- Dashboard ---
export interface DashboardSummary {
  total_devices: number;
  total_configurations: number;
  total_audits: number;
  average_compliance_percent: number | null;
  average_risk_score: number | null;
  findings_by_severity: Record<string, number>;
  potential_attack_paths: number;
  remediation_progress_percent: number | null;
  blockchain_verification_rate_percent: number | null;
  compliance_by_framework: Record<string, number>;
}

export interface RiskTrendPoint {
  scan_id: string;
  device_id: string;
  created_at: string;
  risk_score: number | null;
  compliance_score: number | null;
}

export const dashboardApi = {
  summary: (projectId?: string) => unwrap<DashboardSummary>(http.get("/api/dashboard/summary", { params: { project_id: projectId } })),
  riskTrend: (projectId?: string) => unwrap<RiskTrendPoint[]>(http.get("/api/dashboard/risk-trend", { params: { project_id: projectId } })),
};

// --- Assistant ---
export const assistantApi = {
  tools: () => unwrap<ToolDefinition[]>(http.get("/api/assistant/tools")),
  chat: (messages: { role: string; content: string }[]) =>
    unwrap<{ role: string; content: string }>(http.post("/api/assistant/chat", { messages })),
  invokeTool: (toolName: string, args: Record<string, unknown>, approved = false) =>
    unwrap<{ status: string; tool_name: string; result?: unknown; message?: string }>(
      http.post("/api/assistant/tools/invoke", { tool_name: toolName, arguments: args, approved })
    ),
};
