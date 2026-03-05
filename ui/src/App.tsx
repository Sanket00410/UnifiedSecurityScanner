import { FormEvent, useEffect, useState } from "react";
import { clearToken, getJSON, postJSON, putJSON, readToken, saveToken } from "./api";
import {
  Asset,
  AuditEvent,
  Finding,
  ListResponse,
  Notification,
  Policy,
  PolicyApproval,
  Remediation,
  RiskSummary,
  RouteKey,
  ScanJob,
  Session
} from "./types";

type StatusState = {
  message: string;
  error: boolean;
};

const ROUTES: { key: RouteKey; label: string }[] = [
  { key: "dashboard", label: "Dashboard" },
  { key: "findings", label: "Findings" },
  { key: "assets", label: "Assets" },
  { key: "policies", label: "Policies" },
  { key: "approvals", label: "Approvals" },
  { key: "remediations", label: "Remediation" },
  { key: "operations", label: "Operations" },
  { key: "reports", label: "Reports" }
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

function downloadJSON(name: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
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
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);

  const [selectedFindingID, setSelectedFindingID] = useState("");
  const [selectedAssetID, setSelectedAssetID] = useState("");
  const [selectedPolicyID, setSelectedPolicyID] = useState("");
  const [selectedRemediationID, setSelectedRemediationID] = useState("");

  const [findingSearch, setFindingSearch] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("");
  const [findingPriority, setFindingPriority] = useState("");
  const [findingLayer, setFindingLayer] = useState("");
  const [findingOverdueOnly, setFindingOverdueOnly] = useState(false);
  const [remediationStatusFilter, setRemediationStatusFilter] = useState("");

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
  const [reportPreview, setReportPreview] = useState<any>(null);
  const [scanJobResult, setScanJobResult] = useState("");

  const selectedFinding = findings.find((item) => item.finding_id === selectedFindingID) || null;
  const selectedPolicy = policies.find((item) => item.id === selectedPolicyID) || null;
  const selectedRemediation = remediations.find((item) => item.id === selectedRemediationID) || null;

  async function refreshAllData() {
    setStatus({ message: "Loading tenant data...", error: false });
    const tasks = await Promise.allSettled([
      getJSON<Session>("/v1/auth/me"),
      getJSON<ListResponse<Finding>>("/v1/findings"),
      getJSON<ListResponse<Asset>>("/v1/assets"),
      getJSON<ListResponse<Policy>>("/v1/policies"),
      getJSON<ListResponse<PolicyApproval>>("/v1/policy-approvals"),
      getJSON<ListResponse<Remediation>>("/v1/remediations"),
      getJSON<ListResponse<Notification>>("/v1/notifications"),
      getJSON<ListResponse<AuditEvent>>("/v1/audit-events"),
      getJSON<ListResponse<ScanJob>>("/v1/scan-jobs"),
      getJSON<RiskSummary>("/v1/risk/summary")
    ]);

    const [sessionRes, findingsRes, assetsRes, policiesRes, approvalsRes, remediationsRes, notificationsRes, auditRes, jobsRes, riskRes] = tasks;
    if (sessionRes.status === "fulfilled") {
      setSession(sessionRes.value);
    } else {
      setSession(null);
      const code = (sessionRes.reason as any)?.status ?? 0;
      setStatus({
        message: code === 401 ? "Authentication required. Use SSO or token." : `Session load failed: ${sessionRes.reason.message}`,
        error: true
      });
      return;
    }

    const nextFindings = findingsRes.status === "fulfilled" ? toItems(findingsRes.value) : [];
    const nextAssets = assetsRes.status === "fulfilled" ? toItems(assetsRes.value) : [];
    const nextPolicies = policiesRes.status === "fulfilled" ? toItems(policiesRes.value) : [];
    const nextApprovals = approvalsRes.status === "fulfilled" ? toItems(approvalsRes.value) : [];
    const nextRemediations = remediationsRes.status === "fulfilled" ? toItems(remediationsRes.value) : [];
    const nextNotifications = notificationsRes.status === "fulfilled" ? toItems(notificationsRes.value) : [];
    const nextAudit = auditRes.status === "fulfilled" ? toItems(auditRes.value) : [];
    const nextJobs = jobsRes.status === "fulfilled" ? toItems(jobsRes.value) : [];
    const nextRisk = riskRes.status === "fulfilled" ? riskRes.value : null;

    setFindings(nextFindings);
    setAssets(nextAssets);
    setPolicies(nextPolicies);
    setPolicyApprovals(nextApprovals);
    setRemediations(nextRemediations);
    setNotifications(nextNotifications);
    setAuditEvents(nextAudit);
    setScanJobs(nextJobs);
    setRiskSummary(nextRisk);

    if (!selectedFindingID && nextFindings.length) setSelectedFindingID(nextFindings[0].finding_id);
    if (!selectedAssetID && nextAssets.length) setSelectedAssetID(nextAssets[0].asset_id);
    if (!selectedPolicyID && nextPolicies.length) setSelectedPolicyID(nextPolicies[0].id);
    if (!selectedRemediationID && nextRemediations.length) setSelectedRemediationID(nextRemediations[0].id);

    setReportPreview({
      generated_at: new Date().toISOString(),
      counts: {
        findings: nextFindings.length,
        assets: nextAssets.length,
        policies: nextPolicies.length,
        remediations: nextRemediations.length,
        notifications: nextNotifications.length
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

  async function withRefresh(action: () => Promise<void>, successMessage: string) {
    try {
      await action();
      await refreshAllData();
      setStatus({ message: successMessage, error: false });
    } catch (error: any) {
      setStatus({ message: error.message || "Operation failed", error: true });
    }
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
    const reason = window.prompt(approved ? "Approval reason" : "Denial reason", "") || "";
    withRefresh(
      async () => {
        await postJSON(`/v1/policy-approvals/${encodeURIComponent(approvalID)}/${approved ? "approve" : "deny"}`, { reason });
      },
      `Policy approval ${approved ? "approved" : "denied"}.`
    );
  }

  function handleDecideAssignment(requestID: string, approved: boolean) {
    const reason = window.prompt(approved ? "Assignment approval note" : "Assignment denial note", "") || "";
    withRefresh(
      async () => {
        await postJSON(`/v1/remediation-assignments/${encodeURIComponent(requestID)}/${approved ? "approve" : "deny"}`, { reason });
      },
      `Assignment request ${approved ? "approved" : "denied"}.`
    );
  }

  function handleDecideException(exceptionID: string, approved: boolean) {
    const reason = window.prompt(approved ? "Exception approval note" : "Exception denial note", "") || "";
    withRefresh(
      async () => {
        await postJSON(`/v1/remediation-exceptions/${encodeURIComponent(exceptionID)}/${approved ? "approve" : "deny"}`, { reason });
      },
      `Exception request ${approved ? "approved" : "denied"}.`
    );
  }

  function handleAcknowledgeNotification(id: string) {
    withRefresh(
      async () => {
        await postJSON(`/v1/notifications/${encodeURIComponent(id)}/ack`, {});
      },
      "Notification acknowledged."
    );
  }

  function handleSweepEscalations() {
    withRefresh(
      async () => {
        await postJSON("/v1/remediation-escalations/sweep", {});
      },
      "Escalation sweep complete."
    );
  }

  function handleCreateScanJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    withRefresh(
      async () => {
        const job = await postJSON<ScanJob>("/v1/scan-jobs", {
          target_kind: String(formData.get("target_kind") || "").trim(),
          target: String(formData.get("target") || "").trim(),
          profile: String(formData.get("profile") || "").trim(),
          tools: splitCSV(formData.get("tools"))
        });
        setScanJobResult(`Created ${job.id} (${job.status}) with ${job.approval_mode || "standard"} approval mode.`);
      },
      "Scan job created."
    );
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
          {ROUTES.map((item) => (
            <button key={item.key} className={route === item.key ? "active" : ""} onClick={() => setRoute(item.key)}>
              {item.label}
            </button>
          ))}
        </nav>
        <div className="session">
          <strong>{sessionLabel}</strong>
          <span>{session?.principal?.organization_name || "No organization"}</span>
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
            <button className="ghost" onClick={() => (window.location.href = "/auth/oidc/start")}>SSO</button>
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
            <div className="actions left"><button disabled={!selectedFinding} onClick={handleCreateRemediationFromFinding}>Create Remediation</button></div>
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
              <button type="submit">Save Profile</button>
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
                      <button onClick={() => withRefresh(async () => {
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
                <button type="submit">Create</button>
              </form>
              <form className="form" onSubmit={handleUpdatePolicy}>
                <h3>Update Selected</h3>
                <input name="name" placeholder="name" defaultValue={selectedPolicy?.name || ""} required />
                <input name="scope" placeholder="scope" defaultValue={selectedPolicy?.scope || ""} />
                <select name="mode" defaultValue={selectedPolicy?.mode || "monitor"}><option value="enforced">enforced</option><option value="monitor">monitor</option></select>
                <label><input type="checkbox" name="enabled" defaultChecked={!!selectedPolicy?.enabled} /> enabled</label>
                <textarea name="rules_json" rows={4} defaultValue={JSON.stringify(selectedPolicy?.rules || [], null, 2)}></textarea>
                <button type="submit" disabled={!selectedPolicyID}>Update</button>
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
                        <button onClick={() => handleDecidePolicyApproval(item.id, true)}>Approve</button>
                        <button className="ghost" onClick={() => handleDecidePolicyApproval(item.id, false)}>Deny</button>
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
                      <button onClick={() => handleDecideAssignment(item.id, true)}>Approve</button>
                      <button className="ghost" onClick={() => handleDecideAssignment(item.id, false)}>Deny</button>
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
                      <button onClick={() => handleDecideException(item.id, true)}>Approve</button>
                      <button className="ghost" onClick={() => handleDecideException(item.id, false)}>Deny</button>
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
                <button type="submit" disabled={!selectedRemediation}>Transition</button>
              </form>
              <form className="form" onSubmit={handleRetest}>
                <h3>Request Retest</h3>
                <textarea name="notes" rows={2} placeholder="retest notes"></textarea>
                <button type="submit" disabled={!selectedRemediation}>Request</button>
              </form>
              <form className="form" onSubmit={handleComment}>
                <h3>Add Comment</h3>
                <textarea name="comment" rows={2} placeholder="comment" required></textarea>
                <button type="submit" disabled={!selectedRemediation}>Add</button>
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
              <div className="actions left"><button onClick={handleSweepEscalations}>Run SLA Sweep</button></div>
              <ul className="list">
                {notifications.map((item) => (
                  <li key={item.id}>
                    {item.category || "notification"} | {item.status || "open"} | {fmtDateTime(item.created_at)}
                    {item.status !== "acknowledged" && <button onClick={() => handleAcknowledgeNotification(item.id)}>Acknowledge</button>}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <form className="form" onSubmit={handleCreateScanJob}>
                <h3>Create Scan Job</h3>
                <input name="target_kind" defaultValue="repo" required />
                <input name="target" placeholder="c:/repo" required />
                <input name="profile" defaultValue="balanced" required />
                <input name="tools" placeholder="semgrep,trivy,gitleaks" />
                <button type="submit">Create Job</button>
              </form>
              <div className="meta">{scanJobResult || "No scan jobs created in this session."}</div>
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
            <div className="actions left">
              <button onClick={() => downloadJSON(`uss-summary-${Date.now()}.json`, reportPreview || {})}>Export Summary JSON</button>
              <button onClick={() => {
                const payload = { generated_at: new Date().toISOString(), count: filteredFindings.length, items: filteredFindings };
                setReportPreview(payload);
                downloadJSON(`uss-findings-${Date.now()}.json`, payload);
              }}>Export Findings JSON</button>
            </div>
            <pre className="code">{JSON.stringify(reportPreview, null, 2)}</pre>
          </section>
        )}
      </main>
    </div>
  );
}
