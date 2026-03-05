"use strict";

const TOKEN_STORAGE_KEY = "uss_api_token";
const ROUTES = [
  "dashboard",
  "findings",
  "assets",
  "policies",
  "approvals",
  "remediations",
  "operations",
  "reports"
];

const ROUTE_TITLES = {
  dashboard: "Dashboard",
  findings: "Findings Explorer",
  assets: "Asset Inventory",
  policies: "Policy Governance",
  approvals: "Approval Work Queues",
  remediations: "Remediation Workflows",
  operations: "Operations",
  reports: "Reporting & Export"
};

const REMEDIATION_STATUS_FLOW = {
  open: "assigned",
  assigned: "in_progress",
  in_progress: "ready_for_verify",
  blocked: "in_progress",
  ready_for_verify: "verified",
  verified: "closed",
  accepted_risk: "closed",
  closed: "closed"
};

const state = {
  route: "dashboard",
  session: null,
  findings: [],
  assets: [],
  policies: [],
  policyApprovals: [],
  remediations: [],
  notifications: [],
  scanJobs: [],
  riskSummary: null,
  selectedFindingID: "",
  selectedAssetID: "",
  selectedPolicyID: "",
  selectedRemediationID: "",
  assetProfilesByID: {},
  assetControlsByID: {},
  policyVersionsByID: {},
  remediationActivityByID: {},
  remediationVerificationsByID: {},
  remediationEvidenceByID: {},
  remediationExceptionsByID: {},
  remediationTicketsByID: {},
  remediationAssignmentsByID: {},
  pendingAssignmentRequests: [],
  pendingExceptionRequests: []
};

function currentToken() {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

function setToken(value) {
  window.localStorage.setItem(TOKEN_STORAGE_KEY, value);
}

function clearToken() {
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

function setStatus(message, isError = false) {
  const node = document.getElementById("status-strip");
  if (!node) {
    return;
  }
  node.textContent = message;
  node.classList.toggle("error", isError);
}

function formatDateTime(value) {
  if (!value) {
    return "n/a";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "n/a";
  }
  return date.toLocaleString();
}

function formatDate(value) {
  if (!value) {
    return "n/a";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "n/a";
  }
  return date.toLocaleDateString();
}

function listItems(payload) {
  if (!payload || !Array.isArray(payload.items)) {
    return [];
  }
  return payload.items;
}

function authHeaders(base = {}) {
  const headers = { ...base };
  const token = currentToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: authHeaders(options.headers || {})
  });

  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  let payload = null;
  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else {
    const text = await response.text();
    if (text) {
      payload = { message: text };
    }
  }

  if (!response.ok) {
    const message = payload && payload.message ? payload.message : `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return payload;
}

function getJSON(path) {
  return apiRequest(path, { method: "GET" });
}

function postJSON(path, body) {
  return apiRequest(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
}

function putJSON(path, body) {
  return apiRequest(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
}

function pill(value, className) {
  const span = document.createElement("span");
  span.className = `pill ${className || ""}`.trim();
  span.textContent = value;
  return span;
}

function card(title, description, metaValues) {
  const node = document.createElement("article");
  node.className = "card";

  const heading = document.createElement("strong");
  heading.textContent = title;
  node.appendChild(heading);

  const body = document.createElement("p");
  body.textContent = description;
  node.appendChild(body);

  if (Array.isArray(metaValues) && metaValues.length) {
    const meta = document.createElement("div");
    meta.className = "meta-line";
    metaValues.filter(Boolean).forEach((value) => {
      const span = document.createElement("span");
      span.textContent = String(value);
      meta.appendChild(span);
    });
    node.appendChild(meta);
  }

  return node;
}

function clearNode(node) {
  if (node) {
    node.innerHTML = "";
  }
}

function emptyNode() {
  const template = document.getElementById("empty-state-template");
  if (!template) {
    const fallback = document.createElement("article");
    fallback.className = "empty-box";
    fallback.textContent = "No records.";
    return fallback;
  }
  return template.content.cloneNode(true);
}

function upsertMetric(id, value) {
  const node = document.getElementById(id);
  if (node) {
    node.textContent = String(value);
  }
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value ?? "");
  row.appendChild(cell);
}

function severityClass(severity) {
  const normalized = String(severity || "").toLowerCase();
  switch (normalized) {
    case "critical":
      return "pill-critical";
    case "high":
      return "pill-high";
    case "medium":
      return "pill-medium";
    default:
      return "pill-low";
  }
}

function sortFindings(items) {
  const priorityWeight = { p0: 0, p1: 1, p2: 2, p3: 3, p4: 4 };
  return [...items].sort((a, b) => {
    const ap = priorityWeight[(a.risk && a.risk.priority) || "p4"] ?? 9;
    const bp = priorityWeight[(b.risk && b.risk.priority) || "p4"] ?? 9;
    if (ap !== bp) {
      return ap - bp;
    }
    const as = Number((a.risk && a.risk.overall_score) || 0);
    const bs = Number((b.risk && b.risk.overall_score) || 0);
    return bs - as;
  });
}

function setRoute(route, updateHash = true) {
  if (!ROUTES.includes(route)) {
    route = "dashboard";
  }
  state.route = route;
  if (updateHash) {
    window.location.hash = `#/${route}`;
  }
  renderRoute();
  if (route === "approvals") {
    refreshApprovalWorkQueues();
  }
}

function routeFromHash() {
  const hash = (window.location.hash || "").replace(/^#\/?/, "").trim().toLowerCase();
  if (ROUTES.includes(hash)) {
    return hash;
  }
  return "dashboard";
}

function updateSession(session) {
  const userNode = document.getElementById("session-user");
  const metaNode = document.getElementById("session-meta");
  if (!userNode || !metaNode) {
    return;
  }

  if (!session || !session.principal) {
    userNode.textContent = "Signed out";
    metaNode.textContent = "Sign in with SSO or use an API token.";
    return;
  }

  userNode.textContent = `${session.principal.display_name} (${session.principal.role})`;
  const extras = [
    session.principal.organization_name,
    session.principal.email,
    session.principal.auth_provider
  ].filter(Boolean);
  if (session.bootstrap_token) {
    extras.push("bootstrap token");
  }
  if (session.sso_enabled) {
    extras.push("sso enabled");
  }
  metaNode.textContent = extras.join(" | ");
}

function renderRoute() {
  const titleNode = document.getElementById("route-title");
  if (titleNode) {
    titleNode.textContent = ROUTE_TITLES[state.route] || "Dashboard";
  }

  document.querySelectorAll("#route-nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.route === state.route);
  });

  document.querySelectorAll(".view").forEach((view) => {
    view.classList.remove("active");
  });
  const active = document.getElementById(`view-${state.route}`);
  if (active) {
    active.classList.add("active");
  }
}

function applyFindingFilters() {
  const search = (document.getElementById("findings-search")?.value || "").trim().toLowerCase();
  const severity = (document.getElementById("filter-severity")?.value || "").trim().toLowerCase();
  const priority = (document.getElementById("filter-priority")?.value || "").trim().toLowerCase();
  const layer = (document.getElementById("filter-layer")?.value || "").trim().toLowerCase();
  const overdueOnly = Boolean(document.getElementById("filter-overdue")?.checked);

  return sortFindings(state.findings).filter((item) => {
    const title = String(item.title || "").toLowerCase();
    const category = String(item.category || "").toLowerCase();
    const assetName = String((item.asset && (item.asset.asset_name || item.asset.asset_id)) || "").toLowerCase();
    const textMatch = !search || title.includes(search) || category.includes(search) || assetName.includes(search);
    if (!textMatch) {
      return false;
    }

    if (severity && String(item.severity || "").toLowerCase() !== severity) {
      return false;
    }
    if (priority && String(item.risk?.priority || "").toLowerCase() !== priority) {
      return false;
    }
    if (layer && String(item.source?.layer || "").toLowerCase() !== layer) {
      return false;
    }
    if (overdueOnly && !item.risk?.overdue) {
      return false;
    }

    return true;
  });
}

function renderDashboard() {
  upsertMetric("metric-findings", state.findings.length);
  upsertMetric("metric-overdue", Number(state.riskSummary?.overdue_findings || 0));
  upsertMetric("metric-remediations", state.remediations.length);
  upsertMetric("metric-assets", state.assets.length);
  upsertMetric("metric-policies", state.policies.length);
  upsertMetric("metric-approvals", state.policyApprovals.filter((item) => item.status === "pending").length);
  upsertMetric("metric-notifications", state.notifications.filter((item) => item.status !== "acknowledged").length);
  upsertMetric("metric-jobs", state.scanJobs.filter((item) => item.status !== "completed" && item.status !== "failed").length);

  const priorityBars = document.getElementById("priority-bars");
  const agingBars = document.getElementById("aging-bars");
  const hotFindings = document.getElementById("hot-findings");
  clearNode(priorityBars);
  clearNode(agingBars);
  clearNode(hotFindings);

  const priorityCounts = state.riskSummary?.priority_counts || {};
  const priorities = ["p0", "p1", "p2", "p3", "p4"];
  const totalPriority = priorities.reduce((sum, key) => sum + Number(priorityCounts[key] || 0), 0) || 1;
  priorities.forEach((key) => {
    const value = Number(priorityCounts[key] || 0);
    if (!priorityBars) {
      return;
    }
    const row = document.createElement("div");
    row.className = "bar-row";
    const labels = document.createElement("div");
    labels.className = "bar-labels";
    labels.textContent = key.toUpperCase();
    const count = document.createElement("span");
    count.textContent = String(value);
    labels.appendChild(count);
    row.appendChild(labels);
    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    fill.style.width = `${Math.max(4, (value / totalPriority) * 100)}%`;
    track.appendChild(fill);
    row.appendChild(track);
    priorityBars.appendChild(row);
  });

  const agingCounts = state.riskSummary?.aging_buckets || {};
  const agingKeys = ["new", "active", "stale", "chronic"];
  const totalAging = agingKeys.reduce((sum, key) => sum + Number(agingCounts[key] || 0), 0) || 1;
  agingKeys.forEach((key) => {
    const value = Number(agingCounts[key] || 0);
    if (!agingBars) {
      return;
    }
    const row = document.createElement("div");
    row.className = "bar-row";
    const labels = document.createElement("div");
    labels.className = "bar-labels";
    labels.textContent = key;
    const count = document.createElement("span");
    count.textContent = String(value);
    labels.appendChild(count);
    row.appendChild(labels);
    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    fill.style.width = `${Math.max(4, (value / totalAging) * 100)}%`;
    track.appendChild(fill);
    row.appendChild(track);
    agingBars.appendChild(row);
  });

  const hottest = sortFindings(state.findings).slice(0, 8);
  if (!hotFindings) {
    return;
  }
  if (!hottest.length) {
    hotFindings.appendChild(emptyNode());
    return;
  }
  hottest.forEach((item) => {
    hotFindings.appendChild(card(
      item.title || item.category || "Untitled",
      item.description || "No description.",
      [
        item.risk?.priority || "p4",
        item.risk?.sla_class || "no-sla",
        item.asset?.asset_name || item.asset?.asset_id || "unknown asset"
      ]
    ));
  });
}

function renderFindings() {
  const tbody = document.getElementById("findings-table");
  const detail = document.getElementById("finding-detail");
  const actionButton = document.getElementById("create-remediation-btn");
  clearNode(tbody);
  clearNode(detail);

  const filtered = applyFindingFilters();
  if (!tbody) {
    return;
  }
  if (!filtered.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.textContent = "No findings match the current filters.";
    row.appendChild(cell);
    tbody.appendChild(row);
    if (detail) {
      detail.appendChild(emptyNode());
    }
    if (actionButton) {
      actionButton.disabled = true;
    }
    return;
  }

  filtered.forEach((item) => {
    const row = document.createElement("tr");
    row.dataset.id = item.finding_id;
    if (state.selectedFindingID && state.selectedFindingID === item.finding_id) {
      row.classList.add("selected");
    }

    const priorityCell = document.createElement("td");
    priorityCell.appendChild(pill((item.risk?.priority || "p4").toUpperCase(), severityClass(item.severity)));
    row.appendChild(priorityCell);

    const sevCell = document.createElement("td");
    sevCell.textContent = item.severity || "unknown";
    row.appendChild(sevCell);

    const titleCell = document.createElement("td");
    titleCell.textContent = item.title || item.category || "Untitled finding";
    row.appendChild(titleCell);

    const layerCell = document.createElement("td");
    layerCell.textContent = item.source?.layer || "unknown";
    row.appendChild(layerCell);

    const assetCell = document.createElement("td");
    assetCell.textContent = item.asset?.asset_name || item.asset?.asset_id || "unknown";
    row.appendChild(assetCell);

    const slaCell = document.createElement("td");
    slaCell.textContent = `${item.risk?.sla_class || "n/a"} (${formatDate(item.risk?.sla_due_at)})`;
    row.appendChild(slaCell);

    row.addEventListener("click", () => {
      state.selectedFindingID = item.finding_id;
      renderFindings();
    });

    tbody.appendChild(row);
  });

  const selected = filtered.find((item) => item.finding_id === state.selectedFindingID) || filtered[0];
  state.selectedFindingID = selected.finding_id;
  if (!detail) {
    return;
  }

  detail.appendChild(card(
    selected.title || selected.category || "Untitled finding",
    selected.description || "No description.",
    [
      `severity: ${selected.severity}`,
      `priority: ${selected.risk?.priority || "p4"}`,
      `layer: ${selected.source?.layer || "unknown"}`,
      `asset: ${selected.asset?.asset_name || selected.asset?.asset_id || "unknown"}`
    ]
  ));

  const lines = document.createElement("article");
  lines.className = "card";
  const loc = selected.locations && selected.locations[0] ? selected.locations[0] : {};
  const evidence = selected.evidence && selected.evidence[0] ? selected.evidence[0] : {};
  const linesHeading = document.createElement("strong");
  linesHeading.textContent = "Operational Context";
  lines.appendChild(linesHeading);
  const linesBody = [
    `SLA: ${selected.risk?.sla_class || "n/a"} | Due: ${formatDate(selected.risk?.sla_due_at)} | Overdue: ${selected.risk?.overdue ? "yes" : "no"}`,
    `Exposure: ${selected.asset?.exposure || "unknown"} | Environment: ${selected.asset?.environment || "unknown"}`,
    `Location: ${loc.path || loc.endpoint || "n/a"}${loc.line ? `:${loc.line}` : ""}`,
    `Evidence: ${evidence.ref || "n/a"}`
  ];
  linesBody.forEach((value) => {
    const para = document.createElement("p");
    para.textContent = value;
    lines.appendChild(para);
  });
  detail.appendChild(lines);

  if (actionButton) {
    actionButton.disabled = false;
  }
}

async function createRemediationFromSelectedFinding() {
  const finding = state.findings.find((item) => item.finding_id === state.selectedFindingID);
  if (!finding) {
    return;
  }

  const title = window.prompt("Remediation title", `Mitigate: ${finding.title || finding.category}`);
  if (!title || !title.trim()) {
    return;
  }

  try {
    setStatus("Creating remediation...");
    await postJSON("/v1/remediations", {
      finding_id: finding.finding_id,
      title: title.trim(),
      status: "open",
      notes: `Created from finding ${finding.finding_id}`
    });
    await refreshAllData();
    setRoute("remediations");
    setStatus("Remediation created.");
  } catch (error) {
    setStatus(error.message, true);
  }
}

function renderAssets() {
  const tbody = document.getElementById("assets-table");
  const detail = document.getElementById("asset-detail");
  const controlsNode = document.getElementById("asset-controls");
  clearNode(tbody);
  clearNode(detail);
  clearNode(controlsNode);

  if (!tbody) {
    return;
  }
  if (!state.assets.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.textContent = "No assets available.";
    row.appendChild(cell);
    tbody.appendChild(row);
    if (detail) {
      detail.appendChild(emptyNode());
    }
    return;
  }

  state.assets.forEach((item) => {
    const row = document.createElement("tr");
    row.dataset.id = item.asset_id;
    if (state.selectedAssetID === item.asset_id) {
      row.classList.add("selected");
    }
    appendCell(row, item.asset_id);
    appendCell(row, item.asset_type || "unknown");
    appendCell(row, item.exposure || "unknown");
    appendCell(row, Number(item.criticality || 0).toFixed(1));
    appendCell(row, item.finding_count || 0);
    appendCell(row, item.compensating_control_count || 0);
    row.addEventListener("click", async () => {
      state.selectedAssetID = item.asset_id;
      await loadAssetDetails(item.asset_id);
      renderAssets();
    });
    tbody.appendChild(row);
  });

  if (!state.selectedAssetID && state.assets.length) {
    state.selectedAssetID = state.assets[0].asset_id;
  }
  const selectedSummary = state.assets.find((item) => item.asset_id === state.selectedAssetID);
  const profile = state.assetProfilesByID[state.selectedAssetID] || selectedSummary;
  if (detail && profile) {
    detail.appendChild(card(
      profile.asset_name || profile.asset_id || profile.asset_id,
      `Type: ${profile.asset_type || "unknown"} | Exposure: ${profile.exposure || "unknown"} | Environment: ${profile.environment || "unknown"}`,
      [
        `criticality: ${Number(profile.criticality || 0).toFixed(1)}`,
        `owner: ${profile.owner_team || "unassigned"}`,
        `service: ${profile.service_name || "n/a"}`
      ]
    ));
  } else if (detail) {
    detail.appendChild(emptyNode());
  }

  const controls = state.assetControlsByID[state.selectedAssetID] || [];
  if (controlsNode) {
    if (!controls.length) {
      controlsNode.appendChild(emptyNode());
    } else {
      controls.forEach((control) => {
        controlsNode.appendChild(card(
          control.name || "Unnamed control",
          `${control.control_type || "control"} (${control.scope_layer || "scope"})`,
          [
            `effectiveness: ${Number(control.effectiveness || 0).toFixed(1)}`,
            control.enabled ? "enabled" : "disabled",
            formatDateTime(control.updated_at)
          ]
        ));
      });
    }
  }
}

async function loadAssetDetails(assetID) {
  if (!assetID) {
    return;
  }
  try {
    const [profile, controlsResponse] = await Promise.all([
      getJSON(`/v1/assets/${encodeURIComponent(assetID)}`),
      getJSON(`/v1/assets/${encodeURIComponent(assetID)}/controls`)
    ]);
    state.assetProfilesByID[assetID] = profile;
    state.assetControlsByID[assetID] = listItems(controlsResponse);
  } catch (error) {
    setStatus(`Asset detail load failed: ${error.message}`, true);
  }
}

function formatPolicyRule(rule) {
  if (typeof rule === "string") {
    return rule;
  }
  if (!rule || typeof rule !== "object") {
    return "invalid rule";
  }
  const values = Array.isArray(rule.values) && rule.values.length ? rule.values.join("|") : "*";
  const base = `${rule.effect || "monitor"} ${rule.field || "field"} ${rule.match || "exact"} ${values}`;
  const exceptions = Array.isArray(rule.exceptions) ? rule.exceptions : [];
  if (!exceptions.length) {
    return base;
  }
  const details = exceptions.map((item) => {
    const exceptValues = Array.isArray(item.values) && item.values.length ? item.values.join("|") : "*";
    return `except ${item.field || rule.field || "field"} ${item.match || "exact"} ${exceptValues}`;
  });
  return `${base}; ${details.join("; ")}`;
}

function renderPolicies() {
  const tbody = document.getElementById("policies-table");
  const detail = document.getElementById("policy-detail");
  const versions = document.getElementById("policy-versions");
  const versionsButton = document.getElementById("load-policy-versions");
  clearNode(tbody);
  clearNode(detail);
  clearNode(versions);

  if (!tbody) {
    return;
  }
  if (!state.policies.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No policies available.";
    row.appendChild(cell);
    tbody.appendChild(row);
    if (detail) {
      detail.appendChild(emptyNode());
    }
    if (versionsButton) {
      versionsButton.disabled = true;
    }
    return;
  }

  state.policies.forEach((item) => {
    const row = document.createElement("tr");
    row.dataset.id = item.id;
    if (state.selectedPolicyID === item.id) {
      row.classList.add("selected");
    }
    appendCell(row, item.name);
    appendCell(row, item.scope || "global");
    appendCell(row, item.mode || "monitor");
    appendCell(row, item.enabled ? "yes" : "no");
    appendCell(row, `v${item.version_number || 1}`);
    row.addEventListener("click", () => {
      state.selectedPolicyID = item.id;
      renderPolicies();
    });
    tbody.appendChild(row);
  });

  const selected = state.policies.find((item) => item.id === state.selectedPolicyID) || state.policies[0];
  state.selectedPolicyID = selected.id;
  if (detail) {
    detail.appendChild(card(
      selected.name,
      `${selected.scope || "global"} | ${selected.mode || "monitor"} | ${selected.enabled ? "enabled" : "disabled"}`,
      [`version: ${selected.version_number || 1}`, `updated by: ${selected.updated_by || "n/a"}`, formatDateTime(selected.updated_at)]
    ));
    const rules = Array.isArray(selected.rules) ? selected.rules : [];
    if (!rules.length) {
      detail.appendChild(card("Rules", "No explicit rules configured.", []));
    } else {
      rules.forEach((rule) => {
        detail.appendChild(card("Rule", formatPolicyRule(rule), []));
      });
    }
  }

  if (versionsButton) {
    versionsButton.disabled = false;
  }
  const cached = state.policyVersionsByID[selected.id];
  if (versions) {
    if (!cached || !cached.length) {
      versions.appendChild(emptyNode());
    } else {
      cached.forEach((item) => {
        const node = card(
          `v${item.version_number} · ${item.change_type || "change"}`,
          `by ${item.created_by || "unknown"}`,
          [formatDateTime(item.created_at)]
        );
        if (item.version_number !== selected.version_number) {
          const rollback = document.createElement("button");
          rollback.textContent = "Rollback";
          rollback.addEventListener("click", () => rollbackPolicy(selected.id, item.version_number));
          node.appendChild(rollback);
        }
        versions.appendChild(node);
      });
    }
  }
}

async function loadPolicyVersions() {
  if (!state.selectedPolicyID) {
    return;
  }
  try {
    const response = await getJSON(`/v1/policies/${encodeURIComponent(state.selectedPolicyID)}/versions`);
    state.policyVersionsByID[state.selectedPolicyID] = listItems(response);
    renderPolicies();
    setStatus("Policy versions loaded.");
  } catch (error) {
    setStatus(`Policy versions load failed: ${error.message}`, true);
  }
}

async function rollbackPolicy(policyID, versionNumber) {
  const ok = window.confirm(`Rollback policy to version ${versionNumber}?`);
  if (!ok) {
    return;
  }
  try {
    await postJSON(`/v1/policies/${encodeURIComponent(policyID)}/rollback`, { version_number: versionNumber });
    await refreshAllData();
    setStatus(`Policy rolled back to v${versionNumber}.`);
  } catch (error) {
    setStatus(`Policy rollback failed: ${error.message}`, true);
  }
}

function renderPolicyApprovalsList() {
  const node = document.getElementById("policy-approvals-list");
  clearNode(node);
  if (!node) {
    return;
  }
  if (!state.policyApprovals.length) {
    node.appendChild(emptyNode());
    return;
  }

  state.policyApprovals.forEach((item) => {
    const entry = card(
      `${item.action || "approval"} · ${item.status || "pending"}`,
      item.reason || "No approval note provided.",
      [item.policy_id || "no policy", item.requested_by || "unknown", formatDateTime(item.created_at)]
    );
    if (item.status === "pending") {
      const actions = document.createElement("div");
      actions.className = "action-row";
      const approve = document.createElement("button");
      approve.textContent = "Approve";
      approve.addEventListener("click", () => decidePolicyApproval(item.id, true));
      const deny = document.createElement("button");
      deny.className = "ghost";
      deny.textContent = "Deny";
      deny.addEventListener("click", () => decidePolicyApproval(item.id, false));
      actions.appendChild(approve);
      actions.appendChild(deny);
      entry.appendChild(actions);
    }
    node.appendChild(entry);
  });
}

function flattenPendingRequests(collectionByRemediation, desiredStatus) {
  return Object.values(collectionByRemediation)
    .flat()
    .filter((item) => String(item.status || "").toLowerCase() === desiredStatus);
}

function renderApprovalQueues() {
  renderPolicyApprovalsList();

  const assignmentNode = document.getElementById("assignment-requests-list");
  const exceptionNode = document.getElementById("exception-requests-list");
  clearNode(assignmentNode);
  clearNode(exceptionNode);

  const assignments = state.pendingAssignmentRequests;
  const exceptions = state.pendingExceptionRequests;

  if (assignmentNode) {
    if (!assignments.length) {
      assignmentNode.appendChild(emptyNode());
    } else {
      assignments.forEach((item) => {
        const entry = card(
          `Assign ${item.requested_owner || "unassigned"}`,
          item.reason || "No reason provided.",
          [item.remediation_id, item.requested_by || "unknown", formatDateTime(item.created_at)]
        );
        const actions = document.createElement("div");
        actions.className = "action-row";
        const approve = document.createElement("button");
        approve.textContent = "Approve";
        approve.addEventListener("click", () => decideAssignment(item.id, true));
        const deny = document.createElement("button");
        deny.className = "ghost";
        deny.textContent = "Deny";
        deny.addEventListener("click", () => decideAssignment(item.id, false));
        actions.appendChild(approve);
        actions.appendChild(deny);
        entry.appendChild(actions);
        assignmentNode.appendChild(entry);
      });
    }
  }

  if (exceptionNode) {
    if (!exceptions.length) {
      exceptionNode.appendChild(emptyNode());
    } else {
      exceptions.forEach((item) => {
        const entry = card(
          `Exception request (${Number(item.reduction || 0).toFixed(1)} reduction)`,
          item.reason || "No reason provided.",
          [item.remediation_id, item.requested_by || "unknown", formatDateTime(item.created_at)]
        );
        const actions = document.createElement("div");
        actions.className = "action-row";
        const approve = document.createElement("button");
        approve.textContent = "Approve";
        approve.addEventListener("click", () => decideException(item.id, true));
        const deny = document.createElement("button");
        deny.className = "ghost";
        deny.textContent = "Deny";
        deny.addEventListener("click", () => decideException(item.id, false));
        actions.appendChild(approve);
        actions.appendChild(deny);
        entry.appendChild(actions);
        exceptionNode.appendChild(entry);
      });
    }
  }
}

async function refreshApprovalWorkQueues() {
  if (!state.remediations.length) {
    state.pendingAssignmentRequests = [];
    state.pendingExceptionRequests = [];
    renderApprovalQueues();
    return;
  }

  setStatus("Loading assignment and exception approval queues...");
  const assignmentTasks = state.remediations.map((item) =>
    getJSON(`/v1/remediations/${encodeURIComponent(item.id)}/assignment-requests`)
      .then((payload) => ({ remediationID: item.id, items: listItems(payload) }))
      .catch(() => ({ remediationID: item.id, items: [] }))
  );
  const exceptionTasks = state.remediations.map((item) =>
    getJSON(`/v1/remediations/${encodeURIComponent(item.id)}/exceptions`)
      .then((payload) => ({ remediationID: item.id, items: listItems(payload) }))
      .catch(() => ({ remediationID: item.id, items: [] }))
  );

  const [assignmentResults, exceptionResults] = await Promise.all([
    Promise.all(assignmentTasks),
    Promise.all(exceptionTasks)
  ]);

  assignmentResults.forEach((result) => {
    state.remediationAssignmentsByID[result.remediationID] = result.items;
  });
  exceptionResults.forEach((result) => {
    state.remediationExceptionsByID[result.remediationID] = result.items;
  });

  state.pendingAssignmentRequests = flattenPendingRequests(state.remediationAssignmentsByID, "pending");
  state.pendingExceptionRequests = flattenPendingRequests(state.remediationExceptionsByID, "pending");
  renderApprovalQueues();
  setStatus("Approval queues loaded.");
}

async function decidePolicyApproval(approvalID, approved) {
  const reason = window.prompt(approved ? "Approval reason" : "Denial reason", "") || "";
  try {
    await postJSON(`/v1/policy-approvals/${encodeURIComponent(approvalID)}/${approved ? "approve" : "deny"}`, { reason });
    await refreshAllData();
    setStatus(`Policy approval ${approved ? "approved" : "denied"}.`);
  } catch (error) {
    setStatus(`Policy approval decision failed: ${error.message}`, true);
  }
}

async function decideAssignment(requestID, approved) {
  const reason = window.prompt(approved ? "Assignment approval note" : "Assignment denial note", "") || "";
  try {
    await postJSON(`/v1/remediation-assignments/${encodeURIComponent(requestID)}/${approved ? "approve" : "deny"}`, { reason });
    await refreshApprovalWorkQueues();
    await refreshAllData();
    setStatus(`Assignment request ${approved ? "approved" : "denied"}.`);
  } catch (error) {
    setStatus(`Assignment decision failed: ${error.message}`, true);
  }
}

async function decideException(exceptionID, approved) {
  const reason = window.prompt(approved ? "Exception approval note" : "Exception denial note", "") || "";
  try {
    await postJSON(`/v1/remediation-exceptions/${encodeURIComponent(exceptionID)}/${approved ? "approve" : "deny"}`, { reason });
    await refreshApprovalWorkQueues();
    await refreshAllData();
    setStatus(`Exception request ${approved ? "approved" : "denied"}.`);
  } catch (error) {
    setStatus(`Exception decision failed: ${error.message}`, true);
  }
}

function currentRemediationItems() {
  const filter = (document.getElementById("remediation-status-filter")?.value || "").trim().toLowerCase();
  if (!filter) {
    return [...state.remediations];
  }
  return state.remediations.filter((item) => String(item.status || "").toLowerCase() === filter);
}

function renderRemediations() {
  const tbody = document.getElementById("remediations-table");
  const detail = document.getElementById("remediation-detail");
  const activity = document.getElementById("remediation-activity");
  const transitionButton = document.getElementById("transition-remediation-btn");
  const retestButton = document.getElementById("request-retest-btn");
  const commentButton = document.getElementById("add-comment-btn");

  clearNode(tbody);
  clearNode(detail);
  clearNode(activity);

  if (!tbody) {
    return;
  }

  const items = currentRemediationItems();
  if (!items.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No remediations for the selected filter.";
    row.appendChild(cell);
    tbody.appendChild(row);
    if (detail) {
      detail.appendChild(emptyNode());
    }
    if (activity) {
      activity.appendChild(emptyNode());
    }
    [transitionButton, retestButton, commentButton].forEach((button) => {
      if (button) {
        button.disabled = true;
      }
    });
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("tr");
    row.dataset.id = item.id;
    if (state.selectedRemediationID === item.id) {
      row.classList.add("selected");
    }
    appendCell(row, item.status || "open");
    appendCell(row, item.title || "Untitled remediation");
    appendCell(row, item.owner || "unassigned");
    appendCell(row, formatDate(item.due_at));
    appendCell(row, item.finding_id || "n/a");
    row.addEventListener("click", async () => {
      state.selectedRemediationID = item.id;
      await loadRemediationDetails(item.id);
      renderRemediations();
    });
    tbody.appendChild(row);
  });

  const selected = items.find((item) => item.id === state.selectedRemediationID) || items[0];
  state.selectedRemediationID = selected.id;

  if (detail) {
    detail.appendChild(card(
      selected.title || "Untitled remediation",
      selected.notes || "No remediation notes yet.",
      [
        `status: ${selected.status || "open"}`,
        `owner: ${selected.owner || "unassigned"}`,
        `due: ${formatDate(selected.due_at)}`,
        `finding: ${selected.finding_id || "n/a"}`
      ]
    ));

    const verificationItems = state.remediationVerificationsByID[selected.id] || [];
    const evidenceItems = state.remediationEvidenceByID[selected.id] || [];
    const exceptionItems = state.remediationExceptionsByID[selected.id] || [];
    const ticketItems = state.remediationTicketsByID[selected.id] || [];
    const assignmentItems = state.remediationAssignmentsByID[selected.id] || [];

    detail.appendChild(card("Verifications", `${verificationItems.length} records`, []));
    detail.appendChild(card("Evidence", `${evidenceItems.length} records`, []));
    detail.appendChild(card("Exceptions", `${exceptionItems.length} records`, []));
    detail.appendChild(card("Tickets", `${ticketItems.length} links`, []));
    detail.appendChild(card("Assignment Requests", `${assignmentItems.length} requests`, []));
  }

  if (activity) {
    const activityItems = state.remediationActivityByID[selected.id] || [];
    if (!activityItems.length) {
      activity.appendChild(emptyNode());
    } else {
      activityItems.forEach((item) => {
        activity.appendChild(card(
          item.event_type || "event",
          item.comment || JSON.stringify(item.metadata || {}),
          [item.actor || "system", formatDateTime(item.created_at)]
        ));
      });
    }
  }

  [transitionButton, retestButton, commentButton].forEach((button) => {
    if (button) {
      button.disabled = false;
    }
  });
}

async function loadRemediationDetails(remediationID) {
  if (!remediationID) {
    return;
  }
  try {
    const [activity, verifications, evidence, exceptions, tickets, assignments] = await Promise.all([
      getJSON(`/v1/remediations/${encodeURIComponent(remediationID)}/activity`),
      getJSON(`/v1/remediations/${encodeURIComponent(remediationID)}/verifications`),
      getJSON(`/v1/remediations/${encodeURIComponent(remediationID)}/evidence`),
      getJSON(`/v1/remediations/${encodeURIComponent(remediationID)}/exceptions`),
      getJSON(`/v1/remediations/${encodeURIComponent(remediationID)}/tickets`),
      getJSON(`/v1/remediations/${encodeURIComponent(remediationID)}/assignment-requests`)
    ]);

    state.remediationActivityByID[remediationID] = listItems(activity);
    state.remediationVerificationsByID[remediationID] = listItems(verifications);
    state.remediationEvidenceByID[remediationID] = listItems(evidence);
    state.remediationExceptionsByID[remediationID] = listItems(exceptions);
    state.remediationTicketsByID[remediationID] = listItems(tickets);
    state.remediationAssignmentsByID[remediationID] = listItems(assignments);
  } catch (error) {
    setStatus(`Remediation detail load failed: ${error.message}`, true);
  }
}

async function transitionSelectedRemediation() {
  const remediation = state.remediations.find((item) => item.id === state.selectedRemediationID);
  if (!remediation) {
    return;
  }
  const defaultTarget = REMEDIATION_STATUS_FLOW[remediation.status] || remediation.status;
  const status = window.prompt("Next remediation status", defaultTarget);
  if (!status || !status.trim()) {
    return;
  }

  const notes = window.prompt("Transition notes", "") || "";
  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/transition`, {
      status: status.trim(),
      notes
    });
    await refreshAllData();
    await loadRemediationDetails(remediation.id);
    renderRemediations();
    setStatus(`Remediation transitioned to ${status.trim()}.`);
  } catch (error) {
    setStatus(`Remediation transition failed: ${error.message}`, true);
  }
}

async function requestRetestForSelectedRemediation() {
  const remediation = state.remediations.find((item) => item.id === state.selectedRemediationID);
  if (!remediation) {
    return;
  }
  const notes = window.prompt("Retest notes", "") || "";
  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/retest`, { notes });
    await refreshAllData();
    await loadRemediationDetails(remediation.id);
    renderRemediations();
    setStatus("Retest requested.");
  } catch (error) {
    setStatus(`Retest request failed: ${error.message}`, true);
  }
}

async function addCommentForSelectedRemediation() {
  const remediation = state.remediations.find((item) => item.id === state.selectedRemediationID);
  if (!remediation) {
    return;
  }
  const comment = window.prompt("Comment", "");
  if (!comment || !comment.trim()) {
    return;
  }
  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/comments`, { comment: comment.trim() });
    await loadRemediationDetails(remediation.id);
    renderRemediations();
    setStatus("Comment added.");
  } catch (error) {
    setStatus(`Comment creation failed: ${error.message}`, true);
  }
}

function renderOperations() {
  const node = document.getElementById("notifications-list");
  clearNode(node);
  if (!node) {
    return;
  }
  if (!state.notifications.length) {
    node.appendChild(emptyNode());
    return;
  }

  state.notifications.forEach((item) => {
    const entry = card(
      `${item.category || "notification"} · ${item.status || "open"}`,
      item.subject || item.body || "No notification text",
      [item.severity || "info", item.recipient || "n/a", formatDateTime(item.created_at)]
    );
    if (item.status !== "acknowledged") {
      const ack = document.createElement("button");
      ack.textContent = "Acknowledge";
      ack.addEventListener("click", () => acknowledgeNotification(item.id));
      entry.appendChild(ack);
    }
    node.appendChild(entry);
  });
}

async function acknowledgeNotification(notificationID) {
  try {
    await postJSON(`/v1/notifications/${encodeURIComponent(notificationID)}/ack`, {});
    await refreshAllData();
    setStatus("Notification acknowledged.");
  } catch (error) {
    setStatus(`Notification acknowledgment failed: ${error.message}`, true);
  }
}

async function runEscalationSweep() {
  try {
    const result = await postJSON("/v1/remediation-escalations/sweep", {});
    await refreshAllData();
    setStatus(`Escalation sweep complete: ${Number(result.created || 0)} notifications created.`);
  } catch (error) {
    setStatus(`Escalation sweep failed: ${error.message}`, true);
  }
}

function renderReportPreview(payload) {
  const node = document.getElementById("report-preview");
  if (!node) {
    return;
  }
  node.textContent = JSON.stringify(payload, null, 2);
}

function downloadJSONFile(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

function buildSummarySnapshot() {
  return {
    generated_at: new Date().toISOString(),
    session: state.session,
    counts: {
      findings: state.findings.length,
      remediations: state.remediations.length,
      assets: state.assets.length,
      policies: state.policies.length,
      approvals: state.policyApprovals.length,
      notifications: state.notifications.length,
      scan_jobs: state.scanJobs.length
    },
    risk_summary: state.riskSummary
  };
}

async function createScanJobFromForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const resultNode = document.getElementById("scanjob-result");
  const formData = new FormData(form);
  const targetKind = String(formData.get("target_kind") || "").trim();
  const target = String(formData.get("target") || "").trim();
  const profile = String(formData.get("profile") || "").trim();
  const toolsInput = String(formData.get("tools") || "").trim();
  const tools = toolsInput ? toolsInput.split(",").map((item) => item.trim()).filter(Boolean) : [];

  if (!targetKind || !target || !profile) {
    setStatus("target_kind, target, and profile are required.", true);
    return;
  }

  try {
    const job = await postJSON("/v1/scan-jobs", {
      target_kind: targetKind,
      target,
      profile,
      tools
    });
    if (resultNode) {
      resultNode.textContent = `Created ${job.id} (${job.status}) with approval mode ${job.approval_mode}`;
    }
    await refreshAllData();
    setStatus(`Scan job ${job.id} created.`);
  } catch (error) {
    setStatus(`Scan job creation failed: ${error.message}`, true);
  }
}

function renderAll() {
  updateSession(state.session);
  renderRoute();
  renderDashboard();
  renderFindings();
  renderAssets();
  renderPolicies();
  renderApprovalQueues();
  renderRemediations();
  renderOperations();
  renderReportPreview(buildSummarySnapshot());
}

async function refreshAllData() {
  setStatus("Loading tenant data...");

  const tasks = await Promise.allSettled([
    getJSON("/v1/auth/me"),
    getJSON("/v1/findings"),
    getJSON("/v1/assets"),
    getJSON("/v1/policies"),
    getJSON("/v1/policy-approvals"),
    getJSON("/v1/remediations"),
    getJSON("/v1/notifications"),
    getJSON("/v1/scan-jobs"),
    getJSON("/v1/risk/summary")
  ]);

  const [sessionRes, findingsRes, assetsRes, policiesRes, approvalsRes, remediationsRes, notificationsRes, scanJobsRes, riskSummaryRes] = tasks;

  if (sessionRes.status === "fulfilled") {
    state.session = sessionRes.value;
  } else {
    const status = sessionRes.reason && sessionRes.reason.status ? sessionRes.reason.status : 0;
    if (status === 401) {
      state.session = null;
      renderAll();
      setStatus("Authentication required. Use SSO or an API token.", true);
      return;
    }
    setStatus(`Session load failed: ${sessionRes.reason.message}`, true);
  }

  state.findings = findingsRes.status === "fulfilled" ? listItems(findingsRes.value) : [];
  state.assets = assetsRes.status === "fulfilled" ? listItems(assetsRes.value) : [];
  state.policies = policiesRes.status === "fulfilled" ? listItems(policiesRes.value) : [];
  state.policyApprovals = approvalsRes.status === "fulfilled" ? listItems(approvalsRes.value) : [];
  state.remediations = remediationsRes.status === "fulfilled" ? listItems(remediationsRes.value) : [];
  state.notifications = notificationsRes.status === "fulfilled" ? listItems(notificationsRes.value) : [];
  state.scanJobs = scanJobsRes.status === "fulfilled" ? listItems(scanJobsRes.value) : [];
  state.riskSummary = riskSummaryRes.status === "fulfilled" ? riskSummaryRes.value : null;

  if (state.selectedAssetID) {
    await loadAssetDetails(state.selectedAssetID);
  }
  if (state.selectedRemediationID) {
    await loadRemediationDetails(state.selectedRemediationID);
  }
  if (state.route === "approvals") {
    await refreshApprovalWorkQueues();
  } else {
    state.pendingAssignmentRequests = flattenPendingRequests(state.remediationAssignmentsByID, "pending");
    state.pendingExceptionRequests = flattenPendingRequests(state.remediationExceptionsByID, "pending");
  }

  renderAll();
  setStatus("Data refreshed.");
}

function bindRouteNav() {
  document.querySelectorAll("#route-nav button").forEach((button) => {
    button.addEventListener("click", () => {
      setRoute(button.dataset.route || "dashboard");
    });
  });
  window.addEventListener("hashchange", () => {
    setRoute(routeFromHash(), false);
  });
}

function bindAuthControls() {
  const tokenInput = document.getElementById("token-input");
  const saveButton = document.getElementById("token-save");
  const clearButton = document.getElementById("token-clear");
  const ssoButton = document.getElementById("sso-start");
  const logoutButton = document.getElementById("session-logout");

  if (tokenInput) {
    tokenInput.value = currentToken();
  }

  saveButton?.addEventListener("click", async () => {
    if (!tokenInput) {
      return;
    }
    const token = tokenInput.value.trim();
    if (!token) {
      setStatus("Enter a token before saving.", true);
      return;
    }
    setToken(token);
    await refreshAllData();
  });

  clearButton?.addEventListener("click", async () => {
    clearToken();
    if (tokenInput) {
      tokenInput.value = "";
    }
    await refreshAllData();
  });

  ssoButton?.addEventListener("click", () => {
    window.location.href = "/auth/oidc/start";
  });

  logoutButton?.addEventListener("click", () => {
    clearToken();
    if (tokenInput) {
      tokenInput.value = "";
    }
    window.location.href = "/auth/logout";
  });
}

function bindViewControls() {
  document.getElementById("refresh-all")?.addEventListener("click", () => refreshAllData());
  document.getElementById("create-remediation-btn")?.addEventListener("click", () => createRemediationFromSelectedFinding());
  document.getElementById("load-policy-versions")?.addEventListener("click", () => loadPolicyVersions());
  document.getElementById("transition-remediation-btn")?.addEventListener("click", () => transitionSelectedRemediation());
  document.getElementById("request-retest-btn")?.addEventListener("click", () => requestRetestForSelectedRemediation());
  document.getElementById("add-comment-btn")?.addEventListener("click", () => addCommentForSelectedRemediation());
  document.getElementById("sweep-escalations-btn")?.addEventListener("click", () => runEscalationSweep());
  document.getElementById("scanjob-form")?.addEventListener("submit", (event) => createScanJobFromForm(event));

  ["findings-search", "filter-severity", "filter-priority", "filter-layer", "filter-overdue"].forEach((id) => {
    document.getElementById(id)?.addEventListener("input", () => renderFindings());
    document.getElementById(id)?.addEventListener("change", () => renderFindings());
  });

  document.getElementById("remediation-status-filter")?.addEventListener("change", () => renderRemediations());

  document.getElementById("export-summary-json")?.addEventListener("click", () => {
    const payload = buildSummarySnapshot();
    renderReportPreview(payload);
    downloadJSONFile(`uss-summary-${Date.now()}.json`, payload);
  });

  document.getElementById("export-findings-json")?.addEventListener("click", () => {
    const payload = {
      generated_at: new Date().toISOString(),
      count: state.findings.length,
      items: sortFindings(state.findings)
    };
    renderReportPreview(payload);
    downloadJSONFile(`uss-findings-${Date.now()}.json`, payload);
  });
}

async function boot() {
  bindRouteNav();
  bindAuthControls();
  bindViewControls();
  setRoute(routeFromHash(), false);
  await refreshAllData();
}

boot();
