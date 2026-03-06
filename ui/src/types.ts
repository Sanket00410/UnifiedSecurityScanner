export type RouteKey =
  | "dashboard"
  | "findings"
  | "assets"
  | "policies"
  | "approvals"
  | "remediations"
  | "operations"
  | "reports";

export type ListResponse<T> = {
  items: T[];
};

export type Session = {
  principal?: {
    display_name?: string;
    email?: string;
    role?: string;
    organization_name?: string;
    scopes?: string[];
  };
  bootstrap_token?: boolean;
  sso_enabled?: boolean;
};

export type Finding = {
  finding_id: string;
  title?: string;
  category?: string;
  description?: string;
  severity?: string;
  status?: string;
  tags?: string[];
  source?: {
    layer?: string;
    tool?: string;
  };
  asset?: {
    asset_id?: string;
    asset_name?: string;
    asset_type?: string;
    environment?: string;
    exposure?: string;
    owner_team?: string;
  };
  risk?: {
    priority?: string;
    overall_score?: number;
    overdue?: boolean;
    sla_class?: string;
    sla_due_at?: string;
  };
};

export type Asset = {
  asset_id: string;
  asset_type?: string;
  exposure?: string;
  criticality?: number;
  finding_count?: number;
  compensating_control_count?: number;
};

export type Policy = {
  id: string;
  name: string;
  scope?: string;
  mode?: string;
  enabled?: boolean;
  version_number?: number;
  updated_by?: string;
  updated_at?: string;
  rules?: any[];
};

export type PolicyApproval = {
  id: string;
  action?: string;
  status?: string;
  policy_id?: string;
  requested_by?: string;
  reason?: string;
  created_at?: string;
};

export type Remediation = {
  id: string;
  finding_id?: string;
  title?: string;
  status?: string;
  owner?: string;
  due_at?: string;
  notes?: string;
};

export type Notification = {
  id: string;
  category?: string;
  severity?: string;
  status?: string;
  recipient?: string;
  subject?: string;
  body?: string;
  created_at?: string;
};

export type AuditEvent = {
  id: string;
  action?: string;
  resource_type?: string;
  resource_id?: string;
  actor_email?: string;
  status?: string;
  created_at?: string;
};

export type ScanJob = {
  id: string;
  target_kind?: string;
  target?: string;
  profile?: string;
  tools?: string[];
  status?: string;
  approval_mode?: string;
};

export type ScanPreset = {
  id: string;
  name: string;
  description?: string;
  target_kind: string;
  profile: string;
  tools: string[];
};

export type ScanTarget = {
  id: string;
  tenant_id?: string;
  name: string;
  target_kind: string;
  target: string;
  profile: string;
  tools: string[];
  labels?: Record<string, any>;
  created_by?: string;
  last_run_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type IngestionSource = {
  id: string;
  tenant_id?: string;
  name: string;
  provider?: string;
  enabled?: boolean;
  signature_required?: boolean;
  target_kind: string;
  target: string;
  profile: string;
  tools: string[];
  labels?: Record<string, any>;
  created_by?: string;
  updated_by?: string;
  last_event_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type IngestionEvent = {
  id: string;
  source_id?: string;
  event_type?: string;
  external_id?: string;
  status?: string;
  error_message?: string;
  created_scan_job_id?: string;
  created_at?: string;
};

export type CreatedIngestionSource = {
  source: IngestionSource;
  ingest_token: string;
};

export type RotatedIngestionSourceToken = {
  source: IngestionSource;
  ingest_token: string;
};

export type RotatedIngestionSourceWebhookSecret = {
  source: IngestionSource;
  webhook_secret: string;
};

export type RiskSummary = {
  overdue_findings?: number;
  priority_counts?: Record<string, number>;
  aging_buckets?: Record<string, number>;
};

export type ReportSummary = {
  generated_at?: string;
  sample_size?: number;
  filter?: {
    severity?: string;
    priority?: string;
    layer?: string;
    status?: string;
    search?: string;
    overdue?: boolean;
  };
  filtered?: {
    total_findings?: number;
    overdue?: number;
    priority?: Record<string, number>;
    severity?: Record<string, number>;
    layer?: Record<string, number>;
  };
  risk_summary?: RiskSummary;
};
