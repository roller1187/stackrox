export interface CVERecord {
  priority: string;
  action: string;
  cve: string;
  severity: string;
  cvss: string;
  nvd_cvss: string;
  epss_pct: string;
  product: string;
  image_short: string;
  image_full: string;
  cluster: string;
  namespaces: string;
  deployments: string;
  component: string;
  component_version: string;
  fixed_in: string;
  rhsa_advisory: string;
  advisory_link: string;
  primary_link: string;
  remediation_path: string;
  triage_reasoning: string;
  osv_verification: string;
  osv_affected_range: string;
  poam_justification: string;
  discovered: string;
  rox_status: string;
  rox_fix_version: string;
  secondary_link: string;
  tertiary_link: string;
  rh_cvss: string;
  rh_severity: string;
  rh_vector: string;
  fix_status: string;
  fix_latest_ref: string;
  fix_latest_tag: string;
  fix_catalog_url: string;
  rhsa_description: string;
  rh_mitigation: string;
  rh_statement: string;
  kev_date_added: string;
  kev_due_date: string;
  fix_scan_error: string;
  sla_deadline: string;
  sla_tier: string;
  cve_published: string;
  fix_published_date: string;
  image_catalog_url: string;
  key: string;
}

export interface Report {
  id: string;
  name: string;
  filename: string;
  status: string;
  step: string;
  created_at: string;
  record_count: number | null;
  warnings?: string[];
  completed_at?: string;
  regenerated_at?: string;
  error?: string;
}

export interface Settings {
  rox_endpoint: string;
  rox_api_token: string;
  pull_secret: string;
  ocp_target_version: string;
  ocp_current_version: string;
  skip_tls_verify: boolean;
  scan_workers: number;
  auto_regenerate_enabled: boolean;
  auto_regenerate_schedule: string;
  auto_regenerate_timezone: string;
  max_concurrent_pipelines: number;
}

export interface UpdateEntry {
  fields: Record<string, { old: string; new: string }>;
  detected_at: string;
  acknowledged: boolean;
}

export type UpdatesMap = Record<string, UpdateEntry>;

export interface PreflightResult {
  warnings: string[];
}
