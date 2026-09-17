export interface ApiEnvelope<T> {
  success: boolean;
  data: T | null;
  error: { code: string; message: string } | null;
  request_id: string;
}

export interface Project {
  project_id: string;
  name: string;
  description: string;
  owner_id: string;
  created_at: string;
}

export interface AssetContext {
  criticality: "low" | "medium" | "high" | "critical";
  business_role: string;
  data_sensitivity: string;
  internet_exposure: boolean;
  environment: string;
  owner: string;
  department: string;
}

export interface Device {
  device_id: string;
  project_id: string;
  name: string;
  vendor: string | null;
  platform: string | null;
  asset_context: AssetContext;
  created_at: string;
  updated_at: string;
}

export interface ConfigurationVersion {
  configuration_id: string;
  device_id: string;
  project_id: string;
  version: number;
  original_filename: string;
  vendor: string | null;
  platform: string | null;
  vendor_confidence: number | null;
  vendor_detection_method: string | null;
  software_version: string | null;
  file_size: number;
  uploaded_at: string;
  configuration_hash: string;
  ir_hash: string | null;
  secret_findings: string[];
  status: string;
  error_message: string | null;
  security_ir?: Record<string, unknown> | null;
}

export interface ConfigurationSummary {
  configuration_id: string;
  device_id: string;
  project_id: string;
  latest_version: number;
  created_at: string;
  latest?: ConfigurationVersion;
}

export interface Scan {
  scan_id: string;
  device_id: string;
  project_id: string;
  configuration_id: string;
  configuration_version: number;
  configuration_hash: string;
  ir_hash: string | null;
  status: string;
  triggered_by: string;
  created_at: string;
  updated_at: string;
  error_message: string | null;
  compliance_score?: number | null;
  risk_score?: number | null;
  optimizer_run_id?: string | null;
  blockchain_status?: string | null;
}

export interface ComplianceControl {
  control_id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  framework_mappings: { framework: string; control_id: string }[];
  status: string;
  evidence: Record<string, unknown>;
  notes: string;
}

export interface FrameworkCoverage {
  framework: string;
  implemented_controls: number;
  total_controls: number | null;
  coverage_percent: number | null;
  note: string;
}

export interface ComplianceResult {
  scan_id: string;
  device_id: string;
  controls: ComplianceControl[];
  framework_coverage: Record<string, FrameworkCoverage>;
  status_counts: Record<string, number>;
  failures_by_severity: Record<string, number>;
  compliance_score: number | null;
  compliance_hash: string;
}

export interface Finding {
  finding_id: string;
  scan_id: string;
  device_id: string;
  control_id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  status: string;
  evidence: Record<string, unknown>;
  notes: string;
  framework_mappings: { framework: string; control_id: string }[];
  created_at: string;
}

export interface RiskResult {
  scan_id: string;
  device_id: string;
  risk_score: number;
  risk_level: string;
  risk_factors: Record<string, { score: number; weight: number }>;
  calculation_version: string;
  risk_hash: string;
  timestamp: string;
}

export interface AttackPath {
  path: string[];
  steps: string[];
  hop_count: number;
  exposed_services: string[];
  risk_contribution: number;
  label: string;
}

export interface AttackGraphResult {
  scan_id: string;
  device_id: string;
  graph: { nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] };
  potential_attack_paths: AttackPath[];
  attack_graph_hash: string;
}

export interface OptimizerStrategyMetrics {
  sequence: string[];
  full_sequence: string[];
  residual_risk: number;
  risk_reduced: number;
  risk_reduction_percent: number;
  operational_cost: number;
  disruption_estimate: number;
  attack_paths_removed: number;
  total_potential_paths: number;
  runtime_ms: number;
  objective_score: number;
}

export interface OptimizerRun {
  optimizer_run_id: string;
  scan_id: string;
  device_id: string;
  budget: number;
  strategies: Record<string, OptimizerStrategyMetrics>;
  created_at: string;
}

export interface UnknownPattern {
  vendor: string;
  raw_line: string;
  line_number: number | null;
  device_id: string;
  configuration_id: string;
  version: number;
  status: string;
  ai_suggestion: { category: string; meaning: string; confidence: number } | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface BlockchainTransaction {
  event_id: string;
  audit_id: string;
  device_id: string;
  actor_id: string;
  event_type: string;
  status: string;
  transaction_id: string | null;
  block_number: number | null;
  configuration_hash: string | null;
  compliance_hash: string | null;
  risk_hash: string | null;
  report_hash?: string | null;
  reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface VerifyResult {
  verified: boolean;
  status?: string;
  audit_id?: string;
  algorithm?: string;
  mismatched_fields?: string[];
  database_hashes?: Record<string, string | null>;
  blockchain_hashes?: Record<string, string | null>;
  transaction_id?: string | null;
  reason?: string;
}

export interface BlockchainStatus {
  fabric_reachable: boolean;
  total_audits: number;
  confirmed_transactions: number;
  pending_transactions: number;
}

export interface ReportMeta {
  report_id: string;
  scan_id: string;
  device_id: string;
  report_hash: string;
  generated_by: string;
  generated_at: string;
  size_bytes: number;
}

export interface RemediationPlan {
  remediation_id: string;
  finding_id: string;
  device_id: string;
  vendor: string;
  platform: string;
  explanation: string;
  suggested_commands: string[];
  validation_results: { command: string; valid: boolean; reason: string | null }[];
  status: string;
  created_by: string;
  created_at: string;
  approved_by: string | null;
  approved_at: string | null;
}

export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: Record<string, string>;
  output_schema: Record<string, string>;
  risk_level: string;
  requires_approval: boolean;
}
