import { FormEvent, useEffect, useState } from "react";
import { clearToken, deleteJSON, getBlob, getJSON, postJSON, putJSON, readToken, saveToken } from "./api";
import {
  Asset,
  AuditEvent,
  CreatedIngestionSource,
  Finding,
  IngestionEvent,
  IngestionSource,
  ListResponse,
  Notification,
  Policy,
  PolicyApproval,
  ReportSummary,
  Remediation,
  RotatedIngestionSourceToken,
  RotatedIngestionSourceWebhookSecret,
  RiskSummary,
  RouteKey,
  ScanJob,
  ScanEngineControl,
  ScanPreset,
  ScanTarget,
  Session
} from "./types";

type StatusState = {
  message: string;
  error: boolean;
};

type RouteDefinition = {
  key: RouteKey;
  label: string;
  anyScope: string[];
};

const ROUTES: RouteDefinition[] = [
  { key: "dashboard", label: "Dashboard", anyScope: ["findings:read", "assets:read", "policies:read", "remediations:read", "scan_jobs:read"] },
  { key: "findings", label: "Findings", anyScope: ["findings:read"] },
  { key: "assets", label: "Assets", anyScope: ["assets:read"] },
  { key: "policies", label: "Policies", anyScope: ["policies:read"] },
  { key: "approvals", label: "Approvals", anyScope: ["policies:read", "remediations:read"] },
  { key: "remediations", label: "Remediation", anyScope: ["remediations:read"] },
  { key: "operations", label: "Operations", anyScope: ["scan_jobs:read", "remediations:read", "audit:read"] },
  { key: "reports", label: "Reports", anyScope: ["findings:read"] }
];

const ROUTE_TITLES: Record<RouteKey, string> = {
  dashboard: "Executive Dashboard",
  findings: "Findings Explorer",
  assets: "Asset Inventory",
  policies: "Policy Governance",
  approvals: "Approval Queues",
  remediations: "Remediation Workflows",
  operations: "Operations Console",
  reports: "Reporting and Export"
};

const PRIORITY_WEIGHT: Record<string, number> = { p0: 0, p1: 1, p2: 2, p3: 3, p4: 4 };

const WILDCARD_SCOPE = "*";

function fmtDate(value?: string) {
  if (!value) return "n/a";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "n/a" : date.toLocaleDateString();
}

function fmtDateTime(value?: string) {
  if (!value) return "n/a";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "n/a" : date.toLocaleString();
}

function toItems<T>(payload: ListResponse<T> | undefined | null) {
  if (!payload || !Array.isArray(payload.items)) {
    return [] as T[];
  }
  return payload.items;
}

function splitCSV(raw: FormDataEntryValue | null) {
  return String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseNumber(raw: FormDataEntryValue | null, fallback = 0) {
  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

function parseRulesJSON(raw: FormDataEntryValue | null) {
  const value = String(raw || "").trim();
  if (!value) return [] as any[];
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("rules_json must be an array");
  return parsed;
}

function normalizedScopes(session: Session | null) {
  return (session?.principal?.scopes || [])
    .map((scope) => String(scope || "").trim().toLowerCase())
    .filter(Boolean);
}

function sessionHasScope(session: Session | null, scope: string) {
  const scopes = normalizedScopes(session);
  if (scopes.includes(WILDCARD_SCOPE)) return true;
  return scopes.includes(scope.toLowerCase());
}

function sessionHasAnyScope(session: Session | null, scopes: string[]) {
  if (!scopes.length) return true;
  return scopes.some((scope) => sessionHasScope(session, scope));
}

function downloadJSON(name: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  downloadBlob(name, blob);
}

function downloadBlob(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const node = document.createElement("a");
  node.href = url;
  node.download = name;
  document.body.appendChild(node);
  node.click();
  document.body.removeChild(node);
  URL.revokeObjectURL(url);
}

export function App() {
  const [route, setRoute] = useState<RouteKey>("dashboard");
  const [status, setStatus] = useState<StatusState>({ message: "Ready.", error: false });
  const [tokenInput, setTokenInput] = useState(readToken());

  const [session, setSession] = useState<Session | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policyApprovals, setPolicyApprovals] = useState<PolicyApproval[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [scanPresets, setScanPresets] = useState<ScanPreset[]>([]);
  const [scanEngineControls, setScanEngineControls] = useState<ScanEngineControl[]>([]);
  const [scanTargets, setScanTargets] = useState<ScanTarget[]>([]);
  const [ingestionSources, setIngestionSources] = useState<IngestionSource[]>([]);
  const [ingestionEvents, setIngestionEvents] = useState<IngestionEvent[]>([]);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);

  const [selectedFindingID, setSelectedFindingID] = useState("");
  const [selectedAssetID, setSelectedAssetID] = useState("");
  const [selectedPolicyID, setSelectedPolicyID] = useState("");
  const [selectedRemediationID, setSelectedRemediationID] = useState("");
  const [selectedPresetID, setSelectedPresetID] = useState("");
  const [selectedScanTargetID, setSelectedScanTargetID] = useState("");
  const [selectedIngestionSourceID, setSelectedIngestionSourceID] = useState("");

  const [findingSearch, setFindingSearch] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("");
  const [findingPriority, setFindingPriority] = useState("");
  const [findingLayer, setFindingLayer] = useState("");
  const [findingOverdueOnly, setFindingOverdueOnly] = useState(false);
  const [remediationStatusFilter, setRemediationStatusFilter] = useState("");
  const [scanEngineTargetKindFilter, setScanEngineTargetKindFilter] = useState("");

  const [assetProfile, setAssetProfile] = useState<any>(null);
  const [assetControls, setAssetControls] = useState<any[]>([]);
  const [policyVersions, setPolicyVersions] = useState<any[]>([]);
  const [remediationDetails, setRemediationDetails] = useState({
    activity: [] as any[],
    verifications: [] as any[],
    evidence: [] as any[],
    exceptions: [] as any[],
    tickets: [] as any[],
    assignments: [] as any[]
  });
  const [pendingAssignmentRequests, setPendingAssignmentRequests] = useState<any[]>([]);
  const [pendingExceptionRequests, setPendingExceptionRequests] = useState<any[]>([]);
  const [reportPreview, setReportPreview] = useState<ReportSummary | Record<string, any> | null>(null);
  const [scanJobResult, setScanJobResult] = useState("");
  const [latestIngestionToken, setLatestIngestionToken] = useState("");
  const [latestWebhookSecret, setLatestWebhookSecret] = useState("");
  const [reportExportFormat, setReportExportFormat] = useState<"json" | "csv">("json");

  const selectedFinding = findings.find((item) => item.finding_id === selectedFindingID) || null;
  const selectedPolicy = policies.find((item) => item.id === selectedPolicyID) || null;
  const selectedRemediation = remediations.find((item) => item.id === selectedRemediationID) || null;
  const selectedPreset = scanPresets.find((item) => item.id === selectedPresetID) || null;
  const selectedScanTarget = scanTargets.find((item) => item.id === selectedScanTargetID) || null;
  const selectedIngestionSource = ingestionSources.find((item) => item.id === selectedIngestionSourceID) || null;
  const visibleRoutes = ROUTES.filter((item) => sessionHasAnyScope(session, item.anyScope));
  const visibleRouteKeys = visibleRoutes.map((item) => item.key);

  const canReadFindings = sessionHasScope(session, "findings:read");
  const canReadScanJobs = sessionHasScope(session, "scan_jobs:read");

  const canWriteAssets = sessionHasScope(session, "assets:write");
  const canWritePolicies = sessionHasScope(session, "policies:write");
  const canWriteRemediations = sessionHasScope(session, "remediations:write");
  const canWriteScanJobs = sessionHasScope(session, "scan_jobs:write");

  async function refreshAllData() {
    setStatus({ message: "Loading tenant data...", error: false });
    let nextSession: Session;
    try {
      nextSession = await getJSON<Session>("/v1/auth/me");
      setSession(nextSession);
    } catch (error: any) {
      setSession(null);
      const code = error?.status ?? 0;
      setStatus({
        message: code === 401 ? "Authentication required. Use SSO or token." : `Session load failed: ${error.message}`,
        error: true
      });
      return;
    }

    const sessionCanReadFindings = sessionHasScope(nextSession, "findings:read");
    const sessionCanReadAssets = sessionHasScope(nextSession, "assets:read");
    const sessionCanReadPolicies = sessionHasScope(nextSession, "policies:read");
    const sessionCanReadRemediations = sessionHasScope(nextSession, "remediations:read");
    const sessionCanReadAudit = sessionHasScope(nextSession, "audit:read");
    const sessionCanReadScanJobs = sessionHasScope(nextSession, "scan_jobs:read");

    const tasks = await Promise.allSettled([
      sessionCanReadFindings ? getJSON<ListResponse<Finding>>("/v1/findings") : Promise.resolve({ items: [] }),
      sessionCanReadAssets ? getJSON<ListResponse<Asset>>("/v1/assets") : Promise.resolve({ items: [] }),
      sessionCanReadPolicies ? getJSON<ListResponse<Policy>>("/v1/policies") : Promise.resolve({ items: [] }),
      sessionCanReadPolicies ? getJSON<ListResponse<PolicyApproval>>("/v1/policy-approvals") : Promise.resolve({ items: [] }),
      sessionCanReadRemediations ? getJSON<ListResponse<Remediation>>("/v1/remediations") : Promise.resolve({ items: [] }),
      sessionCanReadRemediations ? getJSON<ListResponse<Notification>>("/v1/notifications") : Promise.resolve({ items: [] }),
      sessionCanReadAudit ? getJSON<ListResponse<AuditEvent>>("/v1/audit-events") : Promise.resolve({ items: [] }),
      sessionCanReadScanJobs ? getJSON<ListResponse<ScanJob>>("/v1/scan-jobs") : Promise.resolve({ items: [] }),
      sessionCanReadScanJobs ? getJSON<ListResponse<ScanPreset>>("/v1/scan-presets") : Promise.resolve({ items: [] }),
      sessionCanReadScanJobs ? getJSON<ListResponse<ScanEngineControl>>("/v1/scan-engine-controls?limit=500") : Promise.resolve({ items: [] }),
      sessionCanReadScanJobs ? getJSON<ListResponse<ScanTarget>>("/v1/scan-targets") : Promise.resolve({ items: [] }),
      sessionCanReadScanJobs ? getJSON<ListResponse<IngestionSource>>("/v1/ingestion/sources") : Promise.resolve({ items: [] }),
      sessionCanReadScanJobs ? getJSON<ListResponse<IngestionEvent>>("/v1/ingestion/events?limit=100") : Promise.resolve({ items: [] }),
      sessionCanReadFindings ? getJSON<RiskSummary>("/v1/risk/summary") : Promise.resolve(null)
    ]);

    const [findingsRes, assetsRes, policiesRes, approvalsRes, remediationsRes, notificationsRes, auditRes, jobsRes, presetsRes, controlsRes, targetsRes, sourcesRes, eventsRes, riskRes] = tasks;

    const nextFindings = findingsRes.status === "fulfilled" ? toItems(findingsRes.value) : [];
    const nextAssets = assetsRes.status === "fulfilled" ? toItems(assetsRes.value) : [];
    const nextPolicies = policiesRes.status === "fulfilled" ? toItems(policiesRes.value) : [];
    const nextApprovals = approvalsRes.status === "fulfilled" ? toItems(approvalsRes.value) : [];
    const nextRemediations = remediationsRes.status === "fulfilled" ? toItems(remediationsRes.value) : [];
    const nextNotifications = notificationsRes.status === "fulfilled" ? toItems(notificationsRes.value) : [];
    const nextAudit = auditRes.status === "fulfilled" ? toItems(auditRes.value) : [];
    const nextJobs = jobsRes.status === "fulfilled" ? toItems(jobsRes.value) : [];
    const nextPresets = presetsRes.status === "fulfilled" ? toItems(presetsRes.value) : [];
    const nextScanEngineControls = controlsRes.status === "fulfilled" ? toItems(controlsRes.value) : [];
    const nextTargets = targetsRes.status === "fulfilled" ? toItems(targetsRes.value) : [];
    const nextIngestionSources = sourcesRes.status === "fulfilled" ? toItems(sourcesRes.value) : [];
    const nextIngestionEvents = eventsRes.status === "fulfilled" ? toItems(eventsRes.value) : [];
    const nextRisk = riskRes.status === "fulfilled" ? riskRes.value : null;

    setFindings(nextFindings);
    setAssets(nextAssets);
    setPolicies(nextPolicies);
    setPolicyApprovals(nextApprovals);
    setRemediations(nextRemediations);
    setNotifications(nextNotifications);
    setAuditEvents(nextAudit);
    setScanJobs(nextJobs);
    setScanPresets(nextPresets);
    setScanEngineControls(nextScanEngineControls);
    setScanTargets(nextTargets);
    setIngestionSources(nextIngestionSources);
    setIngestionEvents(nextIngestionEvents);
    setRiskSummary(nextRisk);

    if (!selectedFindingID && nextFindings.length) setSelectedFindingID(nextFindings[0].finding_id);
    if (!selectedAssetID && nextAssets.length) setSelectedAssetID(nextAssets[0].asset_id);
    if (!selectedPolicyID && nextPolicies.length) setSelectedPolicyID(nextPolicies[0].id);
    if (!selectedRemediationID && nextRemediations.length) setSelectedRemediationID(nextRemediations[0].id);
    if (nextPresets.length > 0) {
      const hasSelectedPreset = nextPresets.some((item) => item.id === selectedPresetID);
      if (!hasSelectedPreset) setSelectedPresetID(nextPresets[0].id);
    } else {
      setSelectedPresetID("");
    }
    if (nextTargets.length > 0) {
      const hasSelectedTarget = nextTargets.some((item) => item.id === selectedScanTargetID);
      if (!hasSelectedTarget) setSelectedScanTargetID(nextTargets[0].id);
    } else {
      setSelectedScanTargetID("");
    }
    if (nextIngestionSources.length > 0) {
      const hasSelectedSource = nextIngestionSources.some((item) => item.id === selectedIngestionSourceID);
      if (!hasSelectedSource) setSelectedIngestionSourceID(nextIngestionSources[0].id);
    } else {
      setSelectedIngestionSourceID("");
    }

    setReportPreview({
      generated_at: new Date().toISOString(),
      counts: {
        findings: nextFindings.length,
        assets: nextAssets.length,
        policies: nextPolicies.length,
        remediations: nextRemediations.length,
        notifications: nextNotifications.length,
        scan_engine_controls: nextScanEngineControls.length,
        scan_targets: nextTargets.length,
        ingestion_sources: nextIngestionSources.length
      },
      risk_summary: nextRisk
    });
    setStatus({ message: "Data refreshed.", error: false });
  }

  async function loadSelectedAsset(assetID: string) {
    if (!assetID) return;
    try {
      const [profile, controls] = await Promise.all([
        getJSON<any>(`/v1/assets/${encodeURIComponent(assetID)}`),
        getJSON<ListResponse<any>>(`/v1/assets/${encodeURIComponent(assetID)}/controls`)
      ]);
      setAssetProfile(profile);
      setAssetControls(toItems(controls));
    } catch (error: any) {
      setStatus({ message: `Asset detail load failed: ${error.message}`, error: true });
    }
  }

  async function loadSelectedRemediation(remediationID: string) {
    if (!remediationID) return;
    try {
      const [activity, verifications, evidence, exceptions, tickets, assignments] = await Promise.all([
        getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(remediationID)}/activity`),
        getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(remediationID)}/verifications`),
        getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(remediationID)}/evidence`),
        getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(remediationID)}/exceptions`),
        getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(remediationID)}/tickets`),
        getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(remediationID)}/assignment-requests`)
      ]);
      setRemediationDetails({
        activity: toItems(activity),
        verifications: toItems(verifications),
        evidence: toItems(evidence),
        exceptions: toItems(exceptions),
        tickets: toItems(tickets),
        assignments: toItems(assignments)
      });
    } catch (error: any) {
      setStatus({ message: `Remediation detail load failed: ${error.message}`, error: true });
    }
  }

  async function loadApprovalQueues() {
    if (!remediations.length) {
      setPendingAssignmentRequests([]);
      setPendingExceptionRequests([]);
      return;
    }

    const assignmentItems: any[] = [];
    const exceptionItems: any[] = [];
    await Promise.all(
      remediations.map(async (item) => {
        const [assignments, exceptions] = await Promise.all([
          getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(item.id)}/assignment-requests`).catch(() => ({ items: [] })),
          getJSON<ListResponse<any>>(`/v1/remediations/${encodeURIComponent(item.id)}/exceptions`).catch(() => ({ items: [] }))
        ]);
        assignmentItems.push(...toItems(assignments).filter((x: any) => String(x.status || "").toLowerCase() === "pending"));
        exceptionItems.push(...toItems(exceptions).filter((x: any) => String(x.status || "").toLowerCase() === "pending"));
      })
    );
    setPendingAssignmentRequests(assignmentItems);
    setPendingExceptionRequests(exceptionItems);
  }

  useEffect(() => {
    setTokenInput(readToken());
    refreshAllData();
  }, []);

  useEffect(() => {
    if (selectedAssetID) loadSelectedAsset(selectedAssetID);
  }, [selectedAssetID]);

  useEffect(() => {
    if (selectedRemediationID) loadSelectedRemediation(selectedRemediationID);
  }, [selectedRemediationID]);

  useEffect(() => {
    if (route === "approvals") loadApprovalQueues();
  }, [route, remediations]);

  useEffect(() => {
    if (!visibleRoutes.length) return;
    if (!visibleRoutes.some((item) => item.key === route)) {
      setRoute(visibleRoutes[0].key);
    }
  }, [route, visibleRouteKeys.join(",")]);

  const filteredFindings = [...findings]
    .sort((a, b) => {
      const ap = PRIORITY_WEIGHT[(a.risk?.priority || "p4").toLowerCase()] ?? 9;
      const bp = PRIORITY_WEIGHT[(b.risk?.priority || "p4").toLowerCase()] ?? 9;
      if (ap !== bp) return ap - bp;
      return Number(b.risk?.overall_score || 0) - Number(a.risk?.overall_score || 0);
    })
    .filter((item) => {
      const search = findingSearch.trim().toLowerCase();
      const title = String(item.title || item.category || "").toLowerCase();
      const asset = String(item.asset?.asset_name || item.asset?.asset_id || "").toLowerCase();
      if (search && !title.includes(search) && !asset.includes(search)) return false;
      if (findingSeverity && String(item.severity || "").toLowerCase() !== findingSeverity) return false;
      if (findingPriority && String(item.risk?.priority || "").toLowerCase() !== findingPriority) return false;
      if (findingLayer && String(item.source?.layer || "").toLowerCase() !== findingLayer) return false;
      if (findingOverdueOnly && !item.risk?.overdue) return false;
      return true;
    });

  const filteredRemediations = !remediationStatusFilter
    ? remediations
    : remediations.filter((item) => String(item.status || "").toLowerCase() === remediationStatusFilter);

  const filteredIngestionEvents = ingestionEvents.filter((item) => {
    if (!selectedIngestionSourceID) return true;
    return String(item.source_id || "") === selectedIngestionSourceID;
  });

  const filteredScanEngineControls = scanEngineControls.filter((item) => {
    const filterValue = scanEngineTargetKindFilter.trim().toLowerCase();
    if (!filterValue) return true;
    return String(item.target_kind || "").toLowerCase() === filterValue;
  });

  async function withRefresh(action: () => Promise<void>, successMessage: string) {
    try {
      await action();
      await refreshAllData();
      setStatus({ message: successMessage, error: false });
    } catch (error: any) {
      setStatus({ message: error.message || "Operation failed", error: true });
    }
  }

  function requirePermission(allowed: boolean, message: string) {
    if (!allowed) {
      setStatus({ message, error: true });
      return false;
    }
    return true;
  }

  function handleSaveToken() {
    if (!tokenInput.trim()) {
      setStatus({ message: "Token is required.", error: true });
      return;
    }
    saveToken(tokenInput);
    refreshAllData();
  }

  function handleClearToken() {
    clearToken();
    setTokenInput("");
    refreshAllData();
  }

  function handleCreateRemediationFromFinding() {
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    if (!selectedFinding) {
      setStatus({ message: "Select a finding first.", error: true });
      return;
    }
    withRefresh(
      async () => {
        const created = await postJSON<Remediation>("/v1/remediations", {
          finding_id: selectedFinding.finding_id,
          title: `Mitigate: ${selectedFinding.title || selectedFinding.category || selectedFinding.finding_id}`,
          status: "open",
          notes: `Created from finding ${selectedFinding.finding_id}`
        });
        setSelectedRemediationID(created.id);
        setRoute("remediations");
      },
      "Remediation created."
    );
  }

  function handleSubmitAssetProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteAssets, "Permission denied: assets:write scope is required.")) return;
    if (!selectedAssetID) {
      setStatus({ message: "Select an asset first.", error: true });
      return;
    }
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        await putJSON(`/v1/assets/${encodeURIComponent(selectedAssetID)}`, {
          asset_type: String(formData.get("asset_type") || "").trim(),
          asset_name: String(formData.get("asset_name") || "").trim(),
          environment: String(formData.get("environment") || "").trim(),
          exposure: String(formData.get("exposure") || "").trim(),
          criticality: parseNumber(formData.get("criticality"), 0),
          owner_team: String(formData.get("owner_team") || "").trim(),
          owner_hierarchy: splitCSV(formData.get("owner_hierarchy")),
          service_name: String(formData.get("service_name") || "").trim(),
          service_tier: String(formData.get("service_tier") || "").trim(),
          service_criticality_class: String(formData.get("service_criticality_class") || "").trim(),
          external_source: String(formData.get("external_source") || "").trim(),
          external_reference: String(formData.get("external_reference") || "").trim(),
          tags: splitCSV(formData.get("tags"))
        });
      },
      "Asset profile updated."
    );
  }

  function handleCreatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWritePolicies, "Permission denied: policies:write scope is required.")) return;
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        const created = await postJSON<Policy>("/v1/policies", {
          name: String(formData.get("name") || "").trim(),
          scope: String(formData.get("scope") || "").trim(),
          mode: String(formData.get("mode") || "enforced"),
          enabled: formData.get("enabled") === "on",
          global: formData.get("global") === "on",
          rules: parseRulesJSON(formData.get("rules_json"))
        });
        setSelectedPolicyID(created.id);
      },
      "Policy created."
    );
  }

  function handleUpdatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWritePolicies, "Permission denied: policies:write scope is required.")) return;
    if (!selectedPolicyID) {
      setStatus({ message: "Select a policy first.", error: true });
      return;
    }
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        await putJSON(`/v1/policies/${encodeURIComponent(selectedPolicyID)}`, {
          name: String(formData.get("name") || "").trim(),
          scope: String(formData.get("scope") || "").trim(),
          mode: String(formData.get("mode") || "monitor"),
          enabled: formData.get("enabled") === "on",
          rules: parseRulesJSON(formData.get("rules_json"))
        });
      },
      "Policy updated."
    );
  }

  function handleTransitionRemediation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    if (!selectedRemediationID) {
      setStatus({ message: "Select a remediation first.", error: true });
      return;
    }
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        await postJSON(`/v1/remediations/${encodeURIComponent(selectedRemediationID)}/transition`, {
          status: String(formData.get("status") || "").trim(),
          notes: String(formData.get("notes") || "").trim()
        });
      },
      "Remediation transitioned."
    );
  }

  function handleRetest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    if (!selectedRemediationID) {
      setStatus({ message: "Select a remediation first.", error: true });
      return;
    }
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        const result = await postJSON<any>(`/v1/remediations/${encodeURIComponent(selectedRemediationID)}/retest`, {
          notes: String(formData.get("notes") || "").trim()
        });
        if (result?.scan_job?.id) setScanJobResult(`Retest scan job ${result.scan_job.id} created.`);
      },
      "Retest requested."
    );
  }

  function handleComment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    if (!selectedRemediationID) {
      setStatus({ message: "Select a remediation first.", error: true });
      return;
    }
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        await postJSON(`/v1/remediations/${encodeURIComponent(selectedRemediationID)}/comments`, {
          comment: String(formData.get("comment") || "").trim()
        });
      },
      "Comment added."
    );
  }

  function handleDecidePolicyApproval(approvalID: string, approved: boolean) {
    if (!requirePermission(canWritePolicies, "Permission denied: policies:write scope is required.")) return;
    const reason = window.prompt(approved ? "Approval reason" : "Denial reason", "") || "";
    withRefresh(
      async () => {
        await postJSON(`/v1/policy-approvals/${encodeURIComponent(approvalID)}/${approved ? "approve" : "deny"}`, { reason });
      },
      `Policy approval ${approved ? "approved" : "denied"}.`
    );
  }

  function handleDecideAssignment(requestID: string, approved: boolean) {
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    const reason = window.prompt(approved ? "Assignment approval note" : "Assignment denial note", "") || "";
    withRefresh(
      async () => {
        await postJSON(`/v1/remediation-assignments/${encodeURIComponent(requestID)}/${approved ? "approve" : "deny"}`, { reason });
      },
      `Assignment request ${approved ? "approved" : "denied"}.`
    );
  }

  function handleDecideException(exceptionID: string, approved: boolean) {
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    const reason = window.prompt(approved ? "Exception approval note" : "Exception denial note", "") || "";
    withRefresh(
      async () => {
        await postJSON(`/v1/remediation-exceptions/${encodeURIComponent(exceptionID)}/${approved ? "approve" : "deny"}`, { reason });
      },
      `Exception request ${approved ? "approved" : "denied"}.`
    );
  }

  function handleAcknowledgeNotification(id: string) {
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    withRefresh(
      async () => {
        await postJSON(`/v1/notifications/${encodeURIComponent(id)}/ack`, {});
      },
      "Notification acknowledged."
    );
  }

  function handleSweepEscalations() {
    if (!requirePermission(canWriteRemediations, "Permission denied: remediations:write scope is required.")) return;
    withRefresh(
      async () => {
        await postJSON("/v1/remediation-escalations/sweep", {});
      },
      "Escalation sweep complete."
    );
  }

  function handleCreateScanJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    const formData = new FormData(event.currentTarget);
    const selectedPresetForJob = scanPresets.find((item) => item.id === String(formData.get("preset_id") || "").trim()) || null;
    withRefresh(
      async () => {
        const targetKind = String(formData.get("target_kind") || "").trim() || selectedPresetForJob?.target_kind || "";
        const target = String(formData.get("target") || "").trim();
        const profile = String(formData.get("profile") || "").trim() || selectedPresetForJob?.profile || "balanced";
        let tools = splitCSV(formData.get("tools"));
        if (!tools.length && selectedPresetForJob?.tools?.length) {
          tools = selectedPresetForJob.tools;
        }

        if (!targetKind || !target || !profile) {
          throw new Error("target_kind, target, and profile are required.");
        }

        const job = await postJSON<ScanJob>("/v1/scan-jobs", {
          target_kind: targetKind,
          target,
          profile,
          tools
        });
        setScanJobResult(`Created ${job.id} (${job.status}) with ${job.approval_mode || "standard"} approval mode.`);
      },
      "Scan job created."
    );
  }

  function handleCreateScanTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    const formData = new FormData(event.currentTarget);
    const selectedPresetForTarget = scanPresets.find((item) => item.id === String(formData.get("preset_id") || "").trim()) || null;
    withRefresh(
      async () => {
        const targetKind = String(formData.get("target_kind") || "").trim() || selectedPresetForTarget?.target_kind || "";
        const target = String(formData.get("target") || "").trim();
        const profile = String(formData.get("profile") || "").trim() || selectedPresetForTarget?.profile || "balanced";
        let tools = splitCSV(formData.get("tools"));
        if (!tools.length && selectedPresetForTarget?.tools?.length) {
          tools = selectedPresetForTarget.tools;
        }
        if (!targetKind || !target) {
          throw new Error("target_kind and target are required.");
        }

        const created = await postJSON<ScanTarget>("/v1/scan-targets", {
          name: String(formData.get("name") || "").trim(),
          target_kind: targetKind,
          target,
          profile,
          tools
        });
        setSelectedScanTargetID(created.id);
      },
      "Scan target saved."
    );
  }

  function handleRunSelectedScanTarget() {
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    if (!selectedScanTargetID) {
      setStatus({ message: "Select a saved scan target first.", error: true });
      return;
    }

    withRefresh(
      async () => {
        const response = await postJSON<{ target: ScanTarget; job: ScanJob }>(
          `/v1/scan-targets/${encodeURIComponent(selectedScanTargetID)}/run`,
          {
            profile: selectedPreset?.profile || "",
            tools: selectedPreset?.tools || []
          }
        );
        setScanJobResult(
          `Created ${response.job.id} (${response.job.status}) from ${response.target.name || response.target.id} with ${response.job.approval_mode || "standard"} approval mode.`
        );
      },
      "Saved target scan started."
    );
  }

  function handleDeleteScanTarget() {
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    if (!selectedScanTargetID) {
      setStatus({ message: "Select a saved scan target first.", error: true });
      return;
    }

    withRefresh(
      async () => {
        await deleteJSON<void>(`/v1/scan-targets/${encodeURIComponent(selectedScanTargetID)}`);
      },
      "Scan target deleted."
    );
  }

  function handleCreateIngestionSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        const targetKind = String(formData.get("target_kind") || "").trim();
        const target = String(formData.get("target") || "").trim();
        if (!targetKind || !target) {
          throw new Error("target_kind and target are required.");
        }

        const created = await postJSON<CreatedIngestionSource>("/v1/ingestion/sources", {
          name: String(formData.get("name") || "").trim(),
          provider: String(formData.get("provider") || "").trim() || "generic",
          enabled: String(formData.get("enabled") || "true") === "true",
          signature_required: String(formData.get("signature_required") || "false") === "true",
          webhook_secret: String(formData.get("webhook_secret") || "").trim(),
          target_kind: targetKind,
          target,
          profile: String(formData.get("profile") || "").trim() || "balanced",
          tools: splitCSV(formData.get("tools"))
        });

        setLatestIngestionToken(created.ingest_token || "");
        setSelectedIngestionSourceID(created.source?.id || "");
      },
      "Ingestion source created."
    );
  }

  function handleRotateIngestionSourceToken() {
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    if (!selectedIngestionSourceID) {
      setStatus({ message: "Select an ingestion source first.", error: true });
      return;
    }

    withRefresh(
      async () => {
        const rotated = await postJSON<RotatedIngestionSourceToken>(
          `/v1/ingestion/sources/${encodeURIComponent(selectedIngestionSourceID)}/rotate-token`,
          {}
        );
        setLatestIngestionToken(rotated.ingest_token || "");
      },
      "Ingestion token rotated."
    );
  }

  function handleRotateIngestionSourceWebhookSecret() {
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    if (!selectedIngestionSourceID) {
      setStatus({ message: "Select an ingestion source first.", error: true });
      return;
    }

    withRefresh(
      async () => {
        const rotated = await postJSON<RotatedIngestionSourceWebhookSecret>(
          `/v1/ingestion/sources/${encodeURIComponent(selectedIngestionSourceID)}/rotate-webhook-secret`,
          {}
        );
        setLatestWebhookSecret(rotated.webhook_secret || "");
      },
      "Webhook secret rotated."
    );
  }

  function handleDeleteIngestionSource() {
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    if (!selectedIngestionSourceID) {
      setStatus({ message: "Select an ingestion source first.", error: true });
      return;
    }

    withRefresh(
      async () => {
        await deleteJSON<void>(`/v1/ingestion/sources/${encodeURIComponent(selectedIngestionSourceID)}`);
        setLatestIngestionToken("");
        setLatestWebhookSecret("");
      },
      "Ingestion source deleted."
    );
  }

  function handleUpsertScanEngineControl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!requirePermission(canWriteScanJobs, "Permission denied: scan_jobs:write scope is required.")) return;
    const formData = new FormData(event.currentTarget);
    const adapterID = String(formData.get("adapter_id") || "").trim().toLowerCase();
    if (!adapterID) {
      setStatus({ message: "adapter_id is required.", error: true });
      return;
    }

    const request: Record<string, any> = {
      target_kind: String(formData.get("target_kind") || "").trim().toLowerCase(),
      enabled: String(formData.get("enabled") || "true").trim().toLowerCase() === "true",
      rulepack_version: String(formData.get("rulepack_version") || "").trim()
    };
    const maxRuntimeRaw = String(formData.get("max_runtime_seconds") || "").trim();
    if (maxRuntimeRaw) {
      const parsed = Number(maxRuntimeRaw);
      if (!Number.isFinite(parsed) || parsed < 0) {
        setStatus({ message: "max_runtime_seconds must be a positive number or zero.", error: true });
        return;
      }
      request.max_runtime_seconds = Math.floor(parsed);
    }

    withRefresh(
      async () => {
        await putJSON<ScanEngineControl>(`/v1/scan-engine-controls/${encodeURIComponent(adapterID)}`, request);
      },
      "Scan engine control saved."
    );
  }

  function buildReportQuery() {
    const query = new URLSearchParams();
    if (findingSeverity) query.set("severity", findingSeverity);
    if (findingPriority) query.set("priority", findingPriority);
    if (findingLayer) query.set("layer", findingLayer);
    if (findingSearch.trim()) query.set("search", findingSearch.trim());
    if (findingOverdueOnly) query.set("overdue", "true");
    return query.toString();
  }

  async function handleLoadReportSummary() {
    if (!requirePermission(canReadFindings, "Permission denied: findings:read scope is required.")) return;
    try {
      const query = buildReportQuery();
      const path = query ? `/v1/reports/summary?${query}` : "/v1/reports/summary";
      const summary = await getJSON<ReportSummary>(path);
      setReportPreview(summary);
      setStatus({ message: "Server report summary loaded.", error: false });
    } catch (error: any) {
      setStatus({ message: `Report summary failed: ${error.message}`, error: true });
    }
  }

  async function handleExportReportFindings(format: "json" | "csv") {
    if (!requirePermission(canReadFindings, "Permission denied: findings:read scope is required.")) return;
    try {
      const query = buildReportQuery();
      const suffix = query ? `&${query}` : "";
      const path = `/v1/reports/findings/export?format=${format}${suffix}`;
      if (format === "json") {
        const payload = await getJSON<any>(path);
        downloadJSON(`uss-findings-${Date.now()}.json`, payload);
      } else {
        const response = await getBlob(path);
        downloadBlob(`uss-findings-${Date.now()}.csv`, response.blob);
      }
      setStatus({ message: `Findings ${format.toUpperCase()} export ready.`, error: false });
    } catch (error: any) {
      setStatus({ message: `Export failed: ${error.message}`, error: true });
    }
  }

  const sessionLabel = session?.principal
    ? `${session.principal.display_name || session.principal.email} (${session.principal.role || "unknown"})`
    : "Signed out";

  return (
    <div className="page">
      <aside className="sidebar">
        <div className="brand">
          <strong>Unified Security Scanner</strong>
          <span>Enterprise Console (TypeScript UI)</span>
        </div>
        <nav className="nav">
          {visibleRoutes.map((item) => (
            <button key={item.key} className={route === item.key ? "active" : ""} onClick={() => setRoute(item.key)}>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="session">
          <strong>{sessionLabel}</strong>
          <span>{session?.principal?.organization_name || "No organization"}</span>
          <span>{(session?.principal?.scopes || []).length} scopes</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="header">
          <div>
            <p className="eyebrow">Phase 6 Dedicated UI</p>
            <h1>{ROUTE_TITLES[route]}</h1>
          </div>
          <div className="actions">
            <input value={tokenInput} onChange={(event) => setTokenInput(event.target.value)} placeholder="API token" type="password" />
            <button onClick={handleSaveToken}>Use Token</button>
            <button className="ghost" onClick={handleClearToken}>Clear</button>
            {session?.sso_enabled && <button className="ghost" onClick={() => (window.location.href = "/auth/oidc/start")}>SSO</button>}
            <button className="ghost" onClick={() => (window.location.href = "/auth/logout")}>Sign Out</button>
            <button onClick={() => refreshAllData()}>Refresh</button>
          </div>
        </header>

        <div className={`status ${status.error ? "error" : ""}`}>{status.message}</div>

        {route === "dashboard" && (
          <section className="grid metrics">
            <article><span>Findings</span><strong>{findings.length}</strong></article>
            <article><span>Overdue</span><strong>{riskSummary?.overdue_findings || 0}</strong></article>
            <article><span>Assets</span><strong>{assets.length}</strong></article>
            <article><span>Policies</span><strong>{policies.length}</strong></article>
            <article><span>Remediations</span><strong>{remediations.length}</strong></article>
            <article><span>Open Jobs</span><strong>{scanJobs.filter((item) => item.status !== "completed" && item.status !== "failed").length}</strong></article>
          </section>
        )}

        {route === "findings" && (
          <section className="panel">
            <div className="toolbar">
              <input placeholder="Search findings" value={findingSearch} onChange={(event) => setFindingSearch(event.target.value)} />
              <select value={findingSeverity} onChange={(event) => setFindingSeverity(event.target.value)}>
                <option value="">All severities</option>
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
              <select value={findingPriority} onChange={(event) => setFindingPriority(event.target.value)}>
                <option value="">All priorities</option>
                <option value="p0">p0</option><option value="p1">p1</option><option value="p2">p2</option><option value="p3">p3</option><option value="p4">p4</option>
              </select>
              <select value={findingLayer} onChange={(event) => setFindingLayer(event.target.value)}>
                <option value="">All layers</option>
                <option value="sast">sast</option><option value="sca">sca</option><option value="secrets">secrets</option><option value="iac">iac</option><option value="dast">dast</option><option value="pentest">pentest</option>
              </select>
              <label><input type="checkbox" checked={findingOverdueOnly} onChange={(event) => setFindingOverdueOnly(event.target.checked)} /> Overdue only</label>
            </div>
            <table>
              <thead><tr><th>Priority</th><th>Severity</th><th>Title</th><th>Layer</th><th>Asset</th><th>SLA</th></tr></thead>
              <tbody>
                {filteredFindings.map((item) => (
                  <tr key={item.finding_id} className={selectedFindingID === item.finding_id ? "selected" : ""} onClick={() => setSelectedFindingID(item.finding_id)}>
                    <td>{(item.risk?.priority || "p4").toUpperCase()}</td>
                    <td>{item.severity || "unknown"}</td>
                    <td>{item.title || item.category || "untitled"}</td>
                    <td>{item.source?.layer || "unknown"}</td>
                    <td>{item.asset?.asset_name || item.asset?.asset_id || "unknown"}</td>
                    <td>{item.risk?.sla_class || "n/a"} ({fmtDate(item.risk?.sla_due_at)})</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="actions left"><button disabled={!selectedFinding || !canWriteRemediations} onClick={handleCreateRemediationFromFinding}>Create Remediation</button></div>
          </section>
        )}

        {route === "assets" && (
          <section className="panel">
            <table>
              <thead><tr><th>ID</th><th>Type</th><th>Exposure</th><th>Criticality</th><th>Findings</th></tr></thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.asset_id} className={selectedAssetID === asset.asset_id ? "selected" : ""} onClick={() => setSelectedAssetID(asset.asset_id)}>
                    <td>{asset.asset_id}</td><td>{asset.asset_type || "unknown"}</td><td>{asset.exposure || "unknown"}</td>
                    <td>{Number(asset.criticality || 0).toFixed(1)}</td><td>{asset.finding_count || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <form className="form" onSubmit={handleSubmitAssetProfile}>
              <h3>Asset Profile</h3>
              <input name="asset_type" placeholder="asset_type" defaultValue={assetProfile?.asset_type || ""} required />
              <input name="asset_name" placeholder="asset_name" defaultValue={assetProfile?.asset_name || ""} required />
              <input name="environment" placeholder="environment" defaultValue={assetProfile?.environment || ""} />
              <input name="exposure" placeholder="exposure" defaultValue={assetProfile?.exposure || ""} />
              <input name="criticality" placeholder="criticality" type="number" step="0.1" defaultValue={assetProfile?.criticality ?? 0} />
              <input name="owner_team" placeholder="owner_team" defaultValue={assetProfile?.owner_team || ""} />
              <input name="owner_hierarchy" placeholder="owner_hierarchy csv" defaultValue={(assetProfile?.owner_hierarchy || []).join(",")} />
              <input name="service_name" placeholder="service_name" defaultValue={assetProfile?.service_name || ""} />
              <input name="service_tier" placeholder="service_tier" defaultValue={assetProfile?.service_tier || ""} />
              <input name="service_criticality_class" placeholder="service_criticality_class" defaultValue={assetProfile?.service_criticality_class || ""} />
              <input name="external_source" placeholder="external_source" defaultValue={assetProfile?.external_source || ""} />
              <input name="external_reference" placeholder="external_reference" defaultValue={assetProfile?.external_reference || ""} />
              <input name="tags" placeholder="tags csv" defaultValue={(assetProfile?.tags || []).join(",")} />
              <button type="submit" disabled={!canWriteAssets}>Save Profile</button>
              <div className="muted">Controls: {assetControls.length}</div>
            </form>
          </section>
        )}

        {route === "policies" && (
          <section className="panel split">
            <div>
              <table>
                <thead><tr><th>Name</th><th>Scope</th><th>Mode</th><th>Enabled</th><th>Version</th></tr></thead>
                <tbody>
                  {policies.map((policy) => (
                    <tr key={policy.id} className={selectedPolicyID === policy.id ? "selected" : ""} onClick={() => setSelectedPolicyID(policy.id)}>
                      <td>{policy.name}</td><td>{policy.scope || "global"}</td><td>{policy.mode || "monitor"}</td><td>{policy.enabled ? "yes" : "no"}</td><td>v{policy.version_number || 1}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="actions left">
                <button onClick={async () => {
                  if (!selectedPolicyID) return;
                  try {
                    const response = await getJSON<ListResponse<any>>(`/v1/policies/${encodeURIComponent(selectedPolicyID)}/versions`);
                    setPolicyVersions(toItems(response));
                    setStatus({ message: "Policy versions loaded.", error: false });
                  } catch (error: any) {
                    setStatus({ message: `Policy versions load failed: ${error.message}`, error: true });
                  }
                }}>Load Versions</button>
              </div>
              <ul className="list">
                {policyVersions.map((item) => (
                  <li key={item.id}>
                    v{item.version_number} ({item.change_type || "change"}) by {item.created_by || "unknown"}
                    {selectedPolicy && item.version_number !== selectedPolicy.version_number && (
                      <button disabled={!canWritePolicies} onClick={() => withRefresh(async () => {
                        await postJSON(`/v1/policies/${encodeURIComponent(selectedPolicy.id)}/rollback`, { version_number: item.version_number });
                      }, `Policy rolled back to v${item.version_number}.`)}>Rollback</button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
            <div className="forms-col">
              <form className="form" onSubmit={handleCreatePolicy}>
                <h3>Create Policy</h3>
                <input name="name" placeholder="name" required />
                <input name="scope" placeholder="scope" />
                <select name="mode"><option value="enforced">enforced</option><option value="monitor">monitor</option></select>
                <label><input type="checkbox" name="enabled" defaultChecked /> enabled</label>
                <label><input type="checkbox" name="global" /> global</label>
                <textarea name="rules_json" rows={4} placeholder='[{"effect":"allow","field":"tool","match":"exact","values":["semgrep"]}]'></textarea>
                <button type="submit" disabled={!canWritePolicies}>Create</button>
              </form>
              <form className="form" onSubmit={handleUpdatePolicy}>
                <h3>Update Selected</h3>
                <input name="name" placeholder="name" defaultValue={selectedPolicy?.name || ""} required />
                <input name="scope" placeholder="scope" defaultValue={selectedPolicy?.scope || ""} />
                <select name="mode" defaultValue={selectedPolicy?.mode || "monitor"}><option value="enforced">enforced</option><option value="monitor">monitor</option></select>
                <label><input type="checkbox" name="enabled" defaultChecked={!!selectedPolicy?.enabled} /> enabled</label>
                <textarea name="rules_json" rows={4} defaultValue={JSON.stringify(selectedPolicy?.rules || [], null, 2)}></textarea>
                <button type="submit" disabled={!selectedPolicyID || !canWritePolicies}>Update</button>
              </form>
            </div>
          </section>
        )}

        {route === "approvals" && (
          <section className="panel split">
            <div>
              <h3>Policy Approvals</h3>
              <ul className="list">
                {policyApprovals.map((item) => (
                  <li key={item.id}>
                    {item.action || "approval"} | {item.status || "pending"} | {item.policy_id || "no-policy"}
                    {item.status === "pending" && (
                      <div className="inline-actions">
                        <button disabled={!canWritePolicies} onClick={() => handleDecidePolicyApproval(item.id, true)}>Approve</button>
                        <button className="ghost" disabled={!canWritePolicies} onClick={() => handleDecidePolicyApproval(item.id, false)}>Deny</button>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Assignment Requests</h3>
              <ul className="list">
                {pendingAssignmentRequests.map((item) => (
                  <li key={item.id}>
                    {item.requested_owner || "unassigned"} | {item.remediation_id || "n/a"}
                    <div className="inline-actions">
                      <button disabled={!canWriteRemediations} onClick={() => handleDecideAssignment(item.id, true)}>Approve</button>
                      <button className="ghost" disabled={!canWriteRemediations} onClick={() => handleDecideAssignment(item.id, false)}>Deny</button>
                    </div>
                  </li>
                ))}
              </ul>
              <h3>Exception Requests</h3>
              <ul className="list">
                {pendingExceptionRequests.map((item) => (
                  <li key={item.id}>
                    reduction {Number(item.reduction || 0).toFixed(1)} | {item.remediation_id || "n/a"}
                    <div className="inline-actions">
                      <button disabled={!canWriteRemediations} onClick={() => handleDecideException(item.id, true)}>Approve</button>
                      <button className="ghost" disabled={!canWriteRemediations} onClick={() => handleDecideException(item.id, false)}>Deny</button>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </section>
        )}

        {route === "remediations" && (
          <section className="panel split">
            <div>
              <div className="toolbar">
                <select value={remediationStatusFilter} onChange={(event) => setRemediationStatusFilter(event.target.value)}>
                  <option value="">All statuses</option>
                  <option value="open">open</option><option value="assigned">assigned</option><option value="in_progress">in_progress</option>
                  <option value="blocked">blocked</option><option value="ready_for_verify">ready_for_verify</option><option value="verified">verified</option>
                  <option value="accepted_risk">accepted_risk</option><option value="closed">closed</option>
                </select>
              </div>
              <table>
                <thead><tr><th>Status</th><th>Title</th><th>Owner</th><th>Due</th></tr></thead>
                <tbody>
                  {filteredRemediations.map((item) => (
                    <tr key={item.id} className={selectedRemediationID === item.id ? "selected" : ""} onClick={() => setSelectedRemediationID(item.id)}>
                      <td>{item.status || "open"}</td><td>{item.title || "untitled"}</td><td>{item.owner || "unassigned"}</td><td>{fmtDate(item.due_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="forms-col">
              <form className="form" onSubmit={handleTransitionRemediation}>
                <h3>Transition</h3>
                <select name="status"><option value="assigned">assigned</option><option value="in_progress">in_progress</option><option value="blocked">blocked</option><option value="ready_for_verify">ready_for_verify</option><option value="verified">verified</option><option value="accepted_risk">accepted_risk</option><option value="closed">closed</option></select>
                <textarea name="notes" rows={2} placeholder="notes"></textarea>
                <button type="submit" disabled={!selectedRemediation || !canWriteRemediations}>Transition</button>
              </form>
              <form className="form" onSubmit={handleRetest}>
                <h3>Request Retest</h3>
                <textarea name="notes" rows={2} placeholder="retest notes"></textarea>
                <button type="submit" disabled={!selectedRemediation || !canWriteRemediations}>Request</button>
              </form>
              <form className="form" onSubmit={handleComment}>
                <h3>Add Comment</h3>
                <textarea name="comment" rows={2} placeholder="comment" required></textarea>
                <button type="submit" disabled={!selectedRemediation || !canWriteRemediations}>Add</button>
              </form>
              <div className="meta">
                <strong>Activity:</strong> {remediationDetails.activity.length} | <strong>Verifications:</strong> {remediationDetails.verifications.length} | <strong>Evidence:</strong> {remediationDetails.evidence.length}
              </div>
            </div>
          </section>
        )}

        {route === "operations" && (
          <section className="panel split">
            <div>
              <h3>Notifications</h3>
              <div className="actions left"><button disabled={!canWriteRemediations} onClick={handleSweepEscalations}>Run SLA Sweep</button></div>
              <ul className="list">
                {notifications.map((item) => (
                  <li key={item.id}>
                    {item.category || "notification"} | {item.status || "open"} | {fmtDateTime(item.created_at)}
                    {item.status !== "acknowledged" && <button disabled={!canWriteRemediations} onClick={() => handleAcknowledgeNotification(item.id)}>Acknowledge</button>}
                  </li>
                ))}
              </ul>
            </div>
            <div className="forms-col">
              <form className="form" onSubmit={handleCreateScanJob} key={`guided-run-${selectedPreset?.id || "none"}`}>
                <h3>Guided Quick Run</h3>
                <select name="preset_id" value={selectedPresetID} onChange={(event) => setSelectedPresetID(event.target.value)}>
                  <option value="">No preset</option>
                  {scanPresets.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name} ({item.target_kind}/{item.profile})
                    </option>
                  ))}
                </select>
                <input name="target_kind" defaultValue={selectedPreset?.target_kind || "repo"} required />
                <input name="target" placeholder="c:/repo or https://app.example.com" required />
                <input name="profile" defaultValue={selectedPreset?.profile || "balanced"} required />
                <input
                  name="tools"
                  placeholder="semgrep,trivy,gitleaks"
                  defaultValue={(selectedPreset?.tools || []).join(",")}
                />
                <button type="submit" disabled={!canWriteScanJobs}>Start Guided Scan</button>
              </form>

              <form className="form" onSubmit={handleCreateScanTarget} key={`save-target-${selectedPreset?.id || "none"}`}>
                <h3>Save Scan Target</h3>
                <select name="preset_id" defaultValue={selectedPresetID}>
                  <option value="">No preset</option>
                  {scanPresets.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name} ({item.target_kind}/{item.profile})
                    </option>
                  ))}
                </select>
                <input name="name" placeholder="name (example: Core API Repo)" />
                <input name="target_kind" defaultValue={selectedPreset?.target_kind || "repo"} required />
                <input name="target" placeholder="c:/repo or https://app.example.com" required />
                <input name="profile" defaultValue={selectedPreset?.profile || "balanced"} />
                <input name="tools" placeholder="optional csv tools" defaultValue={(selectedPreset?.tools || []).join(",")} />
                <button type="submit" disabled={!canWriteScanJobs}>Save Target</button>
              </form>

              <div className="meta">
                Saved targets: {scanTargets.length} | Selected: {selectedScanTarget?.name || "none"}
              </div>
              <table>
                <thead><tr><th>Name</th><th>Kind</th><th>Target</th><th>Profile</th><th>Last Run</th></tr></thead>
                <tbody>
                  {scanTargets.slice(0, 30).map((item) => (
                    <tr key={item.id} className={selectedScanTargetID === item.id ? "selected" : ""} onClick={() => setSelectedScanTargetID(item.id)}>
                      <td>{item.name || item.id}</td>
                      <td>{item.target_kind || "unknown"}</td>
                      <td>{item.target || "n/a"}</td>
                      <td>{item.profile || "balanced"}</td>
                      <td>{fmtDateTime(item.last_run_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="actions left">
                <button disabled={!selectedScanTargetID || !canWriteScanJobs} onClick={handleRunSelectedScanTarget}>Run Selected Target</button>
                <button className="ghost" disabled={!selectedScanTargetID || !canWriteScanJobs} onClick={handleDeleteScanTarget}>Delete Target</button>
              </div>
              <div className="meta">{scanJobResult || "No scan jobs created in this session."}</div>
              <h3>Scan Engine Controls</h3>
              {!canReadScanJobs && <div className="meta">scan_jobs:read scope is required to view scan engine controls.</div>}
              <form className="form" onSubmit={handleUpsertScanEngineControl}>
                <h3>Upsert Engine Control</h3>
                <input name="adapter_id" placeholder="adapter_id (example: semgrep)" required />
                <input name="target_kind" placeholder="target kind (blank = all kinds)" />
                <select name="enabled" defaultValue="true">
                  <option value="true">enabled</option>
                  <option value="false">disabled</option>
                </select>
                <input name="rulepack_version" placeholder="rulepack version (optional)" />
                <input name="max_runtime_seconds" type="number" min={0} step={1} placeholder="max runtime seconds (optional)" />
                <button type="submit" disabled={!canWriteScanJobs}>Save Engine Control</button>
              </form>
              <div className="toolbar">
                <input
                  placeholder="Filter target kind (repo/webapp/api)"
                  value={scanEngineTargetKindFilter}
                  onChange={(event) => setScanEngineTargetKindFilter(event.target.value)}
                />
              </div>
              <div className="meta">Engine controls: {filteredScanEngineControls.length}</div>
              <table>
                <thead><tr><th>Adapter</th><th>Target Kind</th><th>Enabled</th><th>Rulepack</th><th>Max Runtime</th><th>Updated</th></tr></thead>
                <tbody>
                  {filteredScanEngineControls.slice(0, 100).map((item) => (
                    <tr key={`${item.adapter_id}:${item.target_kind || "*"}`}>
                      <td>{item.adapter_id}</td>
                      <td>{item.target_kind || "*"}</td>
                      <td>{item.enabled ? "yes" : "no"}</td>
                      <td>{item.rulepack_version || "default"}</td>
                      <td>{Number(item.max_runtime_seconds || 0) > 0 ? `${item.max_runtime_seconds}s` : "default"}</td>
                      <td>{fmtDateTime(item.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <form className="form" onSubmit={handleCreateIngestionSource}>
                <h3>Automation Ingestion Source</h3>
                <input name="name" placeholder="name (example: GitHub Core Repo)" />
                <input name="provider" defaultValue="github" placeholder="provider (github/gitlab/jenkins/generic)" />
                <select name="enabled" defaultValue="true">
                  <option value="true">enabled</option>
                  <option value="false">disabled</option>
                </select>
                <select name="signature_required" defaultValue="false">
                  <option value="false">signature not required</option>
                  <option value="true">signature required</option>
                </select>
                <input name="webhook_secret" placeholder="optional webhook signing secret" />
                <input name="target_kind" defaultValue="repo" required />
                <input name="target" placeholder="https://github.com/org/repo or c:/repo" required />
                <input name="profile" defaultValue="balanced" />
                <input name="tools" placeholder="optional csv tools" />
                <button type="submit" disabled={!canWriteScanJobs}>Create Ingestion Source</button>
              </form>

              <div className="meta">
                Ingestion sources: {ingestionSources.length} | Selected: {selectedIngestionSource?.name || "none"}
              </div>
              <table>
                <thead><tr><th>Name</th><th>Provider</th><th>Kind</th><th>Target</th><th>Last Event</th></tr></thead>
                <tbody>
                  {ingestionSources.slice(0, 30).map((item) => (
                    <tr key={item.id} className={selectedIngestionSourceID === item.id ? "selected" : ""} onClick={() => setSelectedIngestionSourceID(item.id)}>
                      <td>{item.name || item.id}</td>
                      <td>{item.provider || "generic"}</td>
                      <td>{item.target_kind || "unknown"}</td>
                      <td>{item.target || "n/a"}</td>
                      <td>{fmtDateTime(item.last_event_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="actions left">
                <button disabled={!selectedIngestionSourceID || !canWriteScanJobs} onClick={handleRotateIngestionSourceToken}>Rotate Ingestion Token</button>
                <button disabled={!selectedIngestionSourceID || !canWriteScanJobs} onClick={handleRotateIngestionSourceWebhookSecret}>Rotate Webhook Secret</button>
                <button className="ghost" disabled={!selectedIngestionSourceID || !canWriteScanJobs} onClick={handleDeleteIngestionSource}>Delete Ingestion Source</button>
              </div>
              <div className="meta">
                {selectedIngestionSource
                  ? `Webhook path: /ingest/webhooks/${selectedIngestionSource.id} | Signature required: ${selectedIngestionSource.signature_required ? "yes" : "no"}`
                  : "Select an ingestion source to view webhook details."}
              </div>
              {latestIngestionToken && <pre className="code">Newest ingest token (store securely): {latestIngestionToken}</pre>}
              {latestWebhookSecret && <pre className="code">Newest webhook secret (store securely): {latestWebhookSecret}</pre>}
              <h3>Ingestion Events</h3>
              <ul className="list compact">
                {filteredIngestionEvents.slice(0, 30).map((item) => (
                  <li key={item.id}>
                    {item.event_type || "event"} | {item.status || "unknown"} | job {item.created_scan_job_id || "n/a"} | {fmtDateTime(item.created_at)}
                  </li>
                ))}
              </ul>

              <h3>Audit Events</h3>
              <ul className="list compact">
                {auditEvents.slice(0, 30).map((item) => (
                  <li key={item.id}>{item.action || "action"} | {item.resource_type || "resource"} {item.resource_id || ""} | {item.actor_email || "system"} | {fmtDateTime(item.created_at)}</li>
                ))}
              </ul>
            </div>
          </section>
        )}

        {route === "reports" && (
          <section className="panel split">
            <div>
              <div className="actions left">
                <button onClick={handleLoadReportSummary} disabled={!canReadFindings}>Load Server Summary</button>
                <select value={reportExportFormat} onChange={(event) => setReportExportFormat(event.target.value as "json" | "csv")}>
                  <option value="json">json</option>
                  <option value="csv">csv</option>
                </select>
                <button onClick={() => handleExportReportFindings(reportExportFormat)} disabled={!canReadFindings}>
                  Export Findings {reportExportFormat.toUpperCase()}
                </button>
              </div>
              <div className="muted">
                Uses current finding filters (search/severity/priority/layer/overdue) for report scope.
              </div>
            </div>
            <pre className="code">{JSON.stringify(reportPreview, null, 2)}</pre>
          </section>
        )}
      </main>
    </div>
  );
}
