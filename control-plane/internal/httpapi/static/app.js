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
  auditEvents: [],
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

function byId(id) {
  return document.getElementById(id);
}

function currentToken() {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

function setToken(value) {
  window.localStorage.setItem(TOKEN_STORAGE_KEY, value);
}

function clearToken() {
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

function listItems(payload) {
  if (!payload || !Array.isArray(payload.items)) {
    return [];
  }
  return payload.items;
}

function splitCSV(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseRulesJSON(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return [];
  }
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error("rules_json must be a JSON array");
  }
  return parsed;
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

function setStatus(message, isError = false) {
  const node = byId("status-strip");
  if (!node) {
    return;
  }
  node.textContent = message;
  node.classList.toggle("error", isError);
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

function clearNode(node) {
  if (node) {
    node.innerHTML = "";
  }
}

function emptyNode() {
  const template = byId("empty-state-template");
  if (template) {
    return template.content.cloneNode(true);
  }
  const fallback = document.createElement("article");
  fallback.className = "empty-box";
  fallback.textContent = "No records.";
  return fallback;
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value ?? "");
  row.appendChild(cell);
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

function pill(value, className) {
  const span = document.createElement("span");
  span.className = `pill ${className || ""}`.trim();
  span.textContent = value;
  return span;
}

function setDisabled(ids, disabled) {
  ids.forEach((id) => {
    const node = byId(id);
    if (node) {
      node.disabled = Boolean(disabled);
    }
  });
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

function routeFromHash() {
  const hash = (window.location.hash || "").replace(/^#\/?/, "").trim().toLowerCase();
  return ROUTES.includes(hash) ? hash : "dashboard";
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

function renderRoute() {
  const titleNode = byId("route-title");
  if (titleNode) {
    titleNode.textContent = ROUTE_TITLES[state.route] || "Dashboard";
  }

  document.querySelectorAll("#route-nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.route === state.route);
  });

  document.querySelectorAll(".view").forEach((view) => {
    view.classList.remove("active");
  });

  const active = byId(`view-${state.route}`);
  if (active) {
    active.classList.add("active");
  }
}

function updateSession() {
  const session = state.session;
  const userNode = byId("session-user");
  const metaNode = byId("session-meta");
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

function upsertMetric(id, value) {
  const node = byId(id);
  if (node) {
    node.textContent = String(value);
  }
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

  const priorityBars = byId("priority-bars");
  const agingBars = byId("aging-bars");
  const hotFindings = byId("hot-findings");
  clearNode(priorityBars);
  clearNode(agingBars);
  clearNode(hotFindings);

  const priorityCounts = state.riskSummary?.priority_counts || {};
  const priorities = ["p0", "p1", "p2", "p3", "p4"];
  const totalPriority = priorities.reduce((sum, key) => sum + Number(priorityCounts[key] || 0), 0) || 1;
  priorities.forEach((key) => {
    if (!priorityBars) {
      return;
    }
    const value = Number(priorityCounts[key] || 0);
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
    if (!agingBars) {
      return;
    }
    const value = Number(agingCounts[key] || 0);
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

  if (!hotFindings) {
    return;
  }
  const hottest = sortFindings(state.findings).slice(0, 8);
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

function applyFindingFilters() {
  const search = String(byId("findings-search")?.value || "").trim().toLowerCase();
  const severity = String(byId("filter-severity")?.value || "").trim().toLowerCase();
  const priority = String(byId("filter-priority")?.value || "").trim().toLowerCase();
  const layer = String(byId("filter-layer")?.value || "").trim().toLowerCase();
  const overdueOnly = Boolean(byId("filter-overdue")?.checked);

  return sortFindings(state.findings).filter((item) => {
    const title = String(item.title || "").toLowerCase();
    const category = String(item.category || "").toLowerCase();
    const assetName = String((item.asset && (item.asset.asset_name || item.asset.asset_id)) || "").toLowerCase();
    if (search && !title.includes(search) && !category.includes(search) && !assetName.includes(search)) {
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

function renderFindings() {
  const tbody = byId("findings-table");
  const detail = byId("finding-detail");
  clearNode(tbody);
  clearNode(detail);

  if (!tbody) {
    return;
  }

  const filtered = applyFindingFilters();
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
    setDisabled(["create-remediation-btn"], true);
    return;
  }

  filtered.forEach((item) => {
    const row = document.createElement("tr");
    row.dataset.id = item.finding_id;
    if (state.selectedFindingID === item.finding_id) {
      row.classList.add("selected");
    }

    const priorityCell = document.createElement("td");
    priorityCell.appendChild(pill((item.risk?.priority || "p4").toUpperCase(), severityClass(item.severity)));
    row.appendChild(priorityCell);
    appendCell(row, item.severity || "unknown");
    appendCell(row, item.title || item.category || "Untitled finding");
    appendCell(row, item.source?.layer || "unknown");
    appendCell(row, item.asset?.asset_name || item.asset?.asset_id || "unknown");
    appendCell(row, `${item.risk?.sla_class || "n/a"} (${formatDate(item.risk?.sla_due_at)})`);

    row.addEventListener("click", () => {
      state.selectedFindingID = item.finding_id;
      renderFindings();
    });

    tbody.appendChild(row);
  });

  const selected = filtered.find((item) => item.finding_id === state.selectedFindingID) || filtered[0];
  state.selectedFindingID = selected.finding_id;
  setDisabled(["create-remediation-btn"], false);
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

  const loc = selected.locations && selected.locations[0] ? selected.locations[0] : {};
  const evidence = selected.evidence && selected.evidence[0] ? selected.evidence[0] : {};
  detail.appendChild(card(
    "Operational Context",
    `SLA ${selected.risk?.sla_class || "n/a"}, due ${formatDate(selected.risk?.sla_due_at)}, overdue ${selected.risk?.overdue ? "yes" : "no"}`,
    [
      `exposure: ${selected.asset?.exposure || "unknown"}`,
      `environment: ${selected.asset?.environment || "unknown"}`,
      `location: ${loc.path || loc.endpoint || "n/a"}${loc.line ? `:${loc.line}` : ""}`,
      `evidence: ${evidence.ref || "n/a"}`
    ]
  ));
}

function populateAssetProfileForm(profile) {
  const form = byId("asset-profile-form");
  if (!form) {
    return;
  }
  if (!profile) {
    form.reset();
    return;
  }

  form.asset_type.value = profile.asset_type || "";
  form.asset_name.value = profile.asset_name || profile.asset_id || "";
  form.environment.value = profile.environment || "";
  form.exposure.value = profile.exposure || "";
  form.criticality.value = Number(profile.criticality || 0).toFixed(1);
  form.owner_team.value = profile.owner_team || "";
  form.owner_hierarchy.value = Array.isArray(profile.owner_hierarchy) ? profile.owner_hierarchy.join(",") : "";
  form.service_name.value = profile.service_name || "";
  form.service_tier.value = profile.service_tier || "";
  form.service_criticality_class.value = profile.service_criticality_class || "";
  form.external_source.value = profile.external_source || "";
  form.external_reference.value = profile.external_reference || "";
  form.tags.value = Array.isArray(profile.tags) ? profile.tags.join(",") : "";
}

function renderAssets() {
  const tbody = byId("assets-table");
  const detail = byId("asset-detail");
  const controlsNode = byId("asset-controls");
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
    populateAssetProfileForm(null);
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

  if (!state.selectedAssetID) {
    state.selectedAssetID = state.assets[0].asset_id;
  }
  const summary = state.assets.find((item) => item.asset_id === state.selectedAssetID);
  const profile = state.assetProfilesByID[state.selectedAssetID] || summary;
  populateAssetProfileForm(profile);

  if (detail && profile) {
    detail.appendChild(card(
      profile.asset_name || profile.asset_id || state.selectedAssetID,
      `type ${profile.asset_type || "unknown"}, exposure ${profile.exposure || "unknown"}, environment ${profile.environment || "unknown"}`,
      [
        `criticality: ${Number(profile.criticality || 0).toFixed(1)}`,
        `owner: ${profile.owner_team || "unassigned"}`,
        `service: ${profile.service_name || "n/a"}`
      ]
    ));
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
    const [profile, controls] = await Promise.all([
      getJSON(`/v1/assets/${encodeURIComponent(assetID)}`),
      getJSON(`/v1/assets/${encodeURIComponent(assetID)}/controls`)
    ]);
    state.assetProfilesByID[assetID] = profile;
    state.assetControlsByID[assetID] = listItems(controls);
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
  const rendered = exceptions.map((item) => {
    const v = Array.isArray(item.values) && item.values.length ? item.values.join("|") : "*";
    return `except ${item.field || rule.field || "field"} ${item.match || "exact"} ${v}`;
  });
  return `${base}; ${rendered.join("; ")}`;
}

function populatePolicyForms(policy) {
  const updateForm = byId("policy-update-form");
  const updateButton = byId("policy-update-submit");
  if (!updateForm || !updateButton) {
    return;
  }
  if (!policy) {
    updateForm.reset();
    updateButton.disabled = true;
    return;
  }

  updateForm.name.value = policy.name || "";
  updateForm.scope.value = policy.scope || "";
  updateForm.mode.value = policy.mode || "monitor";
  updateForm.enabled.checked = Boolean(policy.enabled);
  updateForm.rules_json.value = JSON.stringify(Array.isArray(policy.rules) ? policy.rules : [], null, 2);
  updateButton.disabled = false;
}

function renderPolicies() {
  const tbody = byId("policies-table");
  const detail = byId("policy-detail");
  const versionsNode = byId("policy-versions");
  const versionsButton = byId("load-policy-versions");
  clearNode(tbody);
  clearNode(detail);
  clearNode(versionsNode);

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
    populatePolicyForms(null);
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
  const versions = state.policyVersionsByID[selected.id] || [];
  if (versionsNode) {
    if (!versions.length) {
      versionsNode.appendChild(emptyNode());
    } else {
      versions.forEach((item) => {
        const node = card(
          `v${item.version_number} | ${item.change_type || "change"}`,
          `by ${item.created_by || "unknown"}`,
          [formatDateTime(item.created_at)]
        );
        if (item.version_number !== selected.version_number) {
          const rollback = document.createElement("button");
          rollback.textContent = "Rollback";
          rollback.addEventListener("click", () => rollbackPolicy(selected.id, item.version_number));
          node.appendChild(rollback);
        }
        versionsNode.appendChild(node);
      });
    }
  }

  populatePolicyForms(selected);
}

function flattenPendingRequests(collectionByRemediation, desiredStatus) {
  return Object.values(collectionByRemediation)
    .flat()
    .filter((item) => String(item.status || "").toLowerCase() === desiredStatus);
}

function renderPolicyApprovalsList() {
  const node = byId("policy-approvals-list");
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
      `${item.action || "approval"} | ${item.status || "pending"}`,
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

function renderApprovalQueues() {
  renderPolicyApprovalsList();

  const assignmentNode = byId("assignment-requests-list");
  const exceptionNode = byId("exception-requests-list");
  clearNode(assignmentNode);
  clearNode(exceptionNode);

  if (assignmentNode) {
    if (!state.pendingAssignmentRequests.length) {
      assignmentNode.appendChild(emptyNode());
    } else {
      state.pendingAssignmentRequests.forEach((item) => {
        const entry = card(
          `Assign ${item.requested_owner || "unassigned"}`,
          item.reason || "No reason provided.",
          [item.remediation_id || "n/a", item.requested_by || "unknown", formatDateTime(item.created_at)]
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
    if (!state.pendingExceptionRequests.length) {
      exceptionNode.appendChild(emptyNode());
    } else {
      state.pendingExceptionRequests.forEach((item) => {
        const entry = card(
          `Exception request (${Number(item.reduction || 0).toFixed(1)} reduction)`,
          item.reason || "No reason provided.",
          [item.remediation_id || "n/a", item.requested_by || "unknown", formatDateTime(item.created_at)]
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

function currentRemediationItems() {
  const filter = String(byId("remediation-status-filter")?.value || "").trim().toLowerCase();
  if (!filter) {
    return [...state.remediations];
  }
  return state.remediations.filter((item) => String(item.status || "").toLowerCase() === filter);
}

function renderRemediationCollection(nodeID, items, titleFn, bodyFn, metaFn) {
  const node = byId(nodeID);
  clearNode(node);
  if (!node) {
    return;
  }
  if (!items.length) {
    node.appendChild(emptyNode());
    return;
  }
  items.forEach((item) => {
    node.appendChild(card(titleFn(item), bodyFn(item), metaFn(item)));
  });
}

function setRemediationControlsEnabled(enabled) {
  setDisabled([
    "transition-remediation-btn",
    "request-retest-btn",
    "add-comment-btn",
    "remediation-transition-submit",
    "remediation-retest-submit",
    "remediation-comment-submit",
    "remediation-exception-submit",
    "remediation-assignment-submit",
    "remediation-ticket-submit",
    "remediation-evidence-submit",
    "remediation-verify-submit"
  ], !enabled);
}

function renderRemediations() {
  const tbody = byId("remediations-table");
  const detail = byId("remediation-detail");
  const activity = byId("remediation-activity");
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
    renderRemediationCollection("remediation-verifications", [], () => "", () => "", () => []);
    renderRemediationCollection("remediation-evidence", [], () => "", () => "", () => []);
    renderRemediationCollection("remediation-exceptions", [], () => "", () => "", () => []);
    renderRemediationCollection("remediation-tickets", [], () => "", () => "", () => []);
    renderRemediationCollection("remediation-assignments", [], () => "", () => "", () => []);
    setRemediationControlsEnabled(false);
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
  setRemediationControlsEnabled(true);

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
  }

  const activityItems = state.remediationActivityByID[selected.id] || [];
  if (activity) {
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

  const verifications = state.remediationVerificationsByID[selected.id] || [];
  renderRemediationCollection(
    "remediation-verifications",
    verifications,
    (item) => `${item.status || "unknown"} | ${item.outcome || "pending"}`,
    (item) => item.notes || "No verification notes.",
    (item) => [item.id || "n/a", item.scan_job_id || "no scan job", formatDateTime(item.updated_at)]
  );

  const evidence = state.remediationEvidenceByID[selected.id] || [];
  renderRemediationCollection(
    "remediation-evidence",
    evidence,
    (item) => `${item.kind || "evidence"} | ${item.name || "unnamed"}`,
    (item) => item.summary || item.ref || "No evidence summary.",
    (item) => [item.ref || "n/a", item.created_by || "unknown", formatDateTime(item.created_at)]
  );

  const exceptions = state.remediationExceptionsByID[selected.id] || [];
  renderRemediationCollection(
    "remediation-exceptions",
    exceptions,
    (item) => `${item.status || "pending"} | reduction ${Number(item.reduction || 0).toFixed(1)}`,
    (item) => item.reason || "No reason provided.",
    (item) => [item.requested_by || "unknown", item.decided_by || "n/a", formatDateTime(item.updated_at)]
  );

  const tickets = state.remediationTicketsByID[selected.id] || [];
  renderRemediationCollection(
    "remediation-tickets",
    tickets,
    (item) => `${item.provider || "provider"} | ${item.external_id || "external id"}`,
    (item) => item.title || item.url || "No ticket details.",
    (item) => [item.status || "unknown", formatDateTime(item.updated_at)]
  );

  const assignments = state.remediationAssignmentsByID[selected.id] || [];
  renderRemediationCollection(
    "remediation-assignments",
    assignments,
    (item) => `${item.status || "pending"} | ${item.requested_owner || "unassigned"}`,
    (item) => item.reason || "No reason provided.",
    (item) => [item.requested_by || "unknown", item.decided_by || "n/a", formatDateTime(item.updated_at)]
  );

  const transitionForm = byId("remediation-transition-form");
  if (transitionForm) {
    transitionForm.status.value = REMEDIATION_STATUS_FLOW[selected.status] || selected.status || "in_progress";
  }

  const verifyForm = byId("remediation-verify-form");
  if (verifyForm) {
    const latest = verifications.length ? verifications[0] : null;
    verifyForm.verification_id.value = latest ? (latest.id || "") : "";
  }
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

function renderOperations() {
  const notificationsNode = byId("notifications-list");
  const auditNode = byId("audit-events-list");
  clearNode(notificationsNode);
  clearNode(auditNode);

  if (notificationsNode) {
    if (!state.notifications.length) {
      notificationsNode.appendChild(emptyNode());
    } else {
      state.notifications.forEach((item) => {
        const entry = card(
          `${item.category || "notification"} | ${item.status || "open"}`,
          item.subject || item.body || "No notification text.",
          [item.severity || "info", item.recipient || "n/a", formatDateTime(item.created_at)]
        );
        if (item.status !== "acknowledged") {
          const ack = document.createElement("button");
          ack.textContent = "Acknowledge";
          ack.addEventListener("click", () => acknowledgeNotification(item.id));
          entry.appendChild(ack);
        }
        notificationsNode.appendChild(entry);
      });
    }
  }

  if (auditNode) {
    if (!state.auditEvents.length) {
      auditNode.appendChild(emptyNode());
    } else {
      state.auditEvents.slice(0, 40).forEach((item) => {
        auditNode.appendChild(card(
          `${item.action || "action"} | ${item.status || "status"}`,
          `${item.resource_type || "resource"} ${item.resource_id || ""}`.trim(),
          [item.actor_email || "system", item.request_method || "n/a", formatDateTime(item.created_at)]
        ));
      });
    }
  }
}

function renderReportPreview(payload) {
  const node = byId("report-preview");
  if (node) {
    node.textContent = JSON.stringify(payload, null, 2);
  }
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
      audit_events: state.auditEvents.length,
      scan_jobs: state.scanJobs.length
    },
    risk_summary: state.riskSummary
  };
}

function renderAll() {
  updateSession();
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

  const [assignments, exceptions] = await Promise.all([Promise.all(assignmentTasks), Promise.all(exceptionTasks)]);
  assignments.forEach((item) => {
    state.remediationAssignmentsByID[item.remediationID] = item.items;
  });
  exceptions.forEach((item) => {
    state.remediationExceptionsByID[item.remediationID] = item.items;
  });

  state.pendingAssignmentRequests = flattenPendingRequests(state.remediationAssignmentsByID, "pending");
  state.pendingExceptionRequests = flattenPendingRequests(state.remediationExceptionsByID, "pending");
  renderApprovalQueues();
  setStatus("Approval queues loaded.");
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
    getJSON("/v1/audit-events"),
    getJSON("/v1/scan-jobs"),
    getJSON("/v1/risk/summary")
  ]);

  const [sessionRes, findingsRes, assetsRes, policiesRes, approvalsRes, remediationsRes, notificationsRes, auditRes, jobsRes, riskRes] = tasks;

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
  state.auditEvents = auditRes.status === "fulfilled" ? listItems(auditRes.value) : [];
  state.scanJobs = jobsRes.status === "fulfilled" ? listItems(jobsRes.value) : [];
  state.riskSummary = riskRes.status === "fulfilled" ? riskRes.value : null;

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

function parseNumber(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return numeric;
}

async function createRemediationFromSelectedFinding() {
  const finding = state.findings.find((item) => item.finding_id === state.selectedFindingID);
  if (!finding) {
    setStatus("Select a finding before creating remediation.", true);
    return;
  }

  try {
    setStatus("Creating remediation...");
    const created = await postJSON("/v1/remediations", {
      finding_id: finding.finding_id,
      title: `Mitigate: ${finding.title || finding.category || finding.finding_id}`,
      status: "open",
      notes: `Created from finding ${finding.finding_id}`
    });
    if (created && created.id) {
      state.selectedRemediationID = created.id;
    }
    await refreshAllData();
    setRoute("remediations");
    setStatus("Remediation created.");
  } catch (error) {
    setStatus(`Remediation creation failed: ${error.message}`, true);
  }
}

async function upsertSelectedAssetProfile(event) {
  event.preventDefault();
  const assetID = state.selectedAssetID;
  if (!assetID) {
    setStatus("Select an asset before updating profile.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const body = {
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
  };

  if (!body.asset_type) {
    setStatus("asset_type is required.", true);
    return;
  }

  try {
    await putJSON(`/v1/assets/${encodeURIComponent(assetID)}`, body);
    await loadAssetDetails(assetID);
    await refreshAllData();
    setStatus(`Asset profile ${assetID} updated.`);
  } catch (error) {
    setStatus(`Asset profile update failed: ${error.message}`, true);
  }
}

async function createCompensatingControlForSelectedAsset(event) {
  event.preventDefault();
  const assetID = state.selectedAssetID;
  if (!assetID) {
    setStatus("Select an asset before adding a control.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const body = {
    name: String(formData.get("name") || "").trim(),
    control_type: String(formData.get("control_type") || "").trim(),
    scope_layer: String(formData.get("scope_layer") || "").trim(),
    effectiveness: parseNumber(formData.get("effectiveness"), 0),
    enabled: formData.get("enabled") === "on",
    notes: String(formData.get("notes") || "").trim()
  };

  if (!body.name) {
    setStatus("Control name is required.", true);
    return;
  }

  try {
    await postJSON(`/v1/assets/${encodeURIComponent(assetID)}/controls`, body);
    event.currentTarget.reset();
    await loadAssetDetails(assetID);
    await refreshAllData();
    setStatus("Compensating control added.");
  } catch (error) {
    setStatus(`Compensating control creation failed: ${error.message}`, true);
  }
}

async function createPolicyFromForm(event) {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const name = String(formData.get("name") || "").trim();
  if (!name) {
    setStatus("Policy name is required.", true);
    return;
  }

  let rules = [];
  try {
    rules = parseRulesJSON(formData.get("rules_json"));
  } catch (error) {
    setStatus(error.message, true);
    return;
  }

  try {
    const created = await postJSON("/v1/policies", {
      name,
      scope: String(formData.get("scope") || "").trim(),
      mode: String(formData.get("mode") || "enforced").trim(),
      enabled: formData.get("enabled") === "on",
      global: formData.get("global") === "on",
      rules
    });
    if (created && created.id) {
      state.selectedPolicyID = created.id;
    }
    await refreshAllData();
    setStatus("Policy created.");
  } catch (error) {
    setStatus(`Policy creation failed: ${error.message}`, true);
  }
}

async function updateSelectedPolicyFromForm(event) {
  event.preventDefault();
  if (!state.selectedPolicyID) {
    setStatus("Select a policy before updating.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const name = String(formData.get("name") || "").trim();
  if (!name) {
    setStatus("Policy name is required.", true);
    return;
  }

  let rules = [];
  try {
    rules = parseRulesJSON(formData.get("rules_json"));
  } catch (error) {
    setStatus(error.message, true);
    return;
  }

  try {
    await putJSON(`/v1/policies/${encodeURIComponent(state.selectedPolicyID)}`, {
      name,
      scope: String(formData.get("scope") || "").trim(),
      mode: String(formData.get("mode") || "monitor").trim(),
      enabled: formData.get("enabled") === "on",
      rules
    });
    await refreshAllData();
    setStatus("Policy updated.");
  } catch (error) {
    setStatus(`Policy update failed: ${error.message}`, true);
  }
}

async function loadPolicyVersions() {
  if (!state.selectedPolicyID) {
    setStatus("Select a policy before loading versions.", true);
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
  const confirmed = window.confirm(`Rollback policy to version ${versionNumber}?`);
  if (!confirmed) {
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

async function decidePolicyApproval(approvalID, approved) {
  const reason = window.prompt(approved ? "Approval reason" : "Denial reason", "") || "";
  try {
    await postJSON(`/v1/policy-approvals/${encodeURIComponent(approvalID)}/${approved ? "approve" : "deny"}`, { reason });
    await refreshAllData();
    if (state.route === "approvals") {
      await refreshApprovalWorkQueues();
    }
    setStatus(`Policy approval ${approved ? "approved" : "denied"}.`);
  } catch (error) {
    setStatus(`Policy approval decision failed: ${error.message}`, true);
  }
}

async function decideAssignment(requestID, approved) {
  const reason = window.prompt(approved ? "Assignment approval note" : "Assignment denial note", "") || "";
  try {
    await postJSON(`/v1/remediation-assignments/${encodeURIComponent(requestID)}/${approved ? "approve" : "deny"}`, { reason });
    await refreshAllData();
    if (state.route === "approvals") {
      await refreshApprovalWorkQueues();
    }
    setStatus(`Assignment request ${approved ? "approved" : "denied"}.`);
  } catch (error) {
    setStatus(`Assignment decision failed: ${error.message}`, true);
  }
}

async function decideException(exceptionID, approved) {
  const reason = window.prompt(approved ? "Exception approval note" : "Exception denial note", "") || "";
  try {
    await postJSON(`/v1/remediation-exceptions/${encodeURIComponent(exceptionID)}/${approved ? "approve" : "deny"}`, { reason });
    await refreshAllData();
    if (state.route === "approvals") {
      await refreshApprovalWorkQueues();
    }
    setStatus(`Exception request ${approved ? "approved" : "denied"}.`);
  } catch (error) {
    setStatus(`Exception decision failed: ${error.message}`, true);
  }
}

function selectedRemediation() {
  return state.remediations.find((item) => item.id === state.selectedRemediationID) || null;
}

async function transitionSelectedRemediationFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before transitioning.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const status = String(formData.get("status") || "").trim();
  if (!status) {
    setStatus("Next status is required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/transition`, {
      status,
      notes: String(formData.get("notes") || "").trim()
    });
    await refreshAllData();
    setStatus(`Remediation transitioned to ${status}.`);
  } catch (error) {
    setStatus(`Remediation transition failed: ${error.message}`, true);
  }
}

async function requestRetestForSelectedRemediationFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before requesting retest.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  try {
    const result = await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/retest`, {
      notes: String(formData.get("notes") || "").trim()
    });
    await refreshAllData();
    const jobID = result && result.scan_job ? result.scan_job.id : "";
    if (jobID) {
      setStatus(`Retest requested. Scan job ${jobID} created.`);
    } else {
      setStatus("Retest requested.");
    }
  } catch (error) {
    setStatus(`Retest request failed: ${error.message}`, true);
  }
}

async function addCommentForSelectedRemediationFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before adding a comment.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const comment = String(formData.get("comment") || "").trim();
  if (!comment) {
    setStatus("Comment is required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/comments`, { comment });
    event.currentTarget.reset();
    await refreshAllData();
    setStatus("Comment added.");
  } catch (error) {
    setStatus(`Comment creation failed: ${error.message}`, true);
  }
}

async function createRemediationExceptionFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before creating an exception.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const reason = String(formData.get("reason") || "").trim();
  const reduction = parseNumber(formData.get("reduction"), 0);
  if (!reason || reduction <= 0) {
    setStatus("Exception reason and positive reduction are required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/exceptions`, {
      reason,
      reduction,
      notes: String(formData.get("notes") || "").trim()
    });
    event.currentTarget.reset();
    await refreshAllData();
    if (state.route === "approvals") {
      await refreshApprovalWorkQueues();
    }
    setStatus("Exception request created.");
  } catch (error) {
    setStatus(`Exception creation failed: ${error.message}`, true);
  }
}

async function createRemediationAssignmentFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before requesting assignment.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const requestedOwner = String(formData.get("requested_owner") || "").trim();
  if (!requestedOwner) {
    setStatus("Requested owner is required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/assignment-requests`, {
      requested_owner: requestedOwner,
      reason: String(formData.get("reason") || "").trim()
    });
    event.currentTarget.reset();
    await refreshAllData();
    if (state.route === "approvals") {
      await refreshApprovalWorkQueues();
    }
    setStatus("Assignment request created.");
  } catch (error) {
    setStatus(`Assignment request failed: ${error.message}`, true);
  }
}

async function createRemediationTicketFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before linking ticket.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const provider = String(formData.get("provider") || "").trim();
  const externalID = String(formData.get("external_id") || "").trim();
  if (!provider || !externalID) {
    setStatus("Provider and external ID are required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/tickets`, {
      provider,
      external_id: externalID,
      title: String(formData.get("title") || "").trim(),
      url: String(formData.get("url") || "").trim(),
      status: String(formData.get("status") || "").trim()
    });
    event.currentTarget.reset();
    await refreshAllData();
    setStatus("Ticket link created.");
  } catch (error) {
    setStatus(`Ticket link creation failed: ${error.message}`, true);
  }
}

async function createRemediationEvidenceFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before adding evidence.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const kind = String(formData.get("kind") || "").trim();
  const ref = String(formData.get("ref") || "").trim();
  if (!kind || !ref) {
    setStatus("Evidence kind and reference are required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/evidence`, {
      kind,
      name: String(formData.get("name") || "").trim(),
      ref,
      summary: String(formData.get("summary") || "").trim()
    });
    event.currentTarget.reset();
    await refreshAllData();
    setStatus("Evidence added.");
  } catch (error) {
    setStatus(`Evidence creation failed: ${error.message}`, true);
  }
}

async function recordRemediationVerificationFromForm(event) {
  event.preventDefault();
  const remediation = selectedRemediation();
  if (!remediation) {
    setStatus("Select a remediation before recording verification.", true);
    return;
  }

  const formData = new FormData(event.currentTarget);
  const verificationID = String(formData.get("verification_id") || "").trim();
  const outcome = String(formData.get("outcome") || "").trim();
  if (!verificationID || !outcome) {
    setStatus("Verification ID and outcome are required.", true);
    return;
  }

  try {
    await postJSON(`/v1/remediations/${encodeURIComponent(remediation.id)}/verify`, {
      verification_id: verificationID,
      outcome,
      notes: String(formData.get("notes") || "").trim()
    });
    await refreshAllData();
    setStatus("Verification recorded.");
  } catch (error) {
    setStatus(`Verification recording failed: ${error.message}`, true);
  }
}

async function transitionSelectedRemediation() {
  const form = byId("remediation-transition-form");
  if (!form) {
    return;
  }
  form.requestSubmit();
}

async function requestRetestForSelectedRemediation() {
  const form = byId("remediation-retest-form");
  if (!form) {
    return;
  }
  form.requestSubmit();
}

async function addCommentForSelectedRemediation() {
  const form = byId("remediation-comment-form");
  if (!form) {
    return;
  }
  form.requestSubmit();
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

async function createScanJobFromForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const resultNode = byId("scanjob-result");
  const formData = new FormData(form);
  const targetKind = String(formData.get("target_kind") || "").trim();
  const target = String(formData.get("target") || "").trim();
  const profile = String(formData.get("profile") || "").trim();
  const tools = splitCSV(formData.get("tools"));

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
    form.reset();
    await refreshAllData();
    setStatus(`Scan job ${job.id} created.`);
  } catch (error) {
    setStatus(`Scan job creation failed: ${error.message}`, true);
  }
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
  const tokenInput = byId("token-input");
  const saveButton = byId("token-save");
  const clearButton = byId("token-clear");
  const ssoButton = byId("sso-start");
  const logoutButton = byId("session-logout");

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
  byId("refresh-all")?.addEventListener("click", () => refreshAllData());
  byId("create-remediation-btn")?.addEventListener("click", () => createRemediationFromSelectedFinding());
  byId("load-policy-versions")?.addEventListener("click", () => loadPolicyVersions());
  byId("transition-remediation-btn")?.addEventListener("click", () => transitionSelectedRemediation());
  byId("request-retest-btn")?.addEventListener("click", () => requestRetestForSelectedRemediation());
  byId("add-comment-btn")?.addEventListener("click", () => addCommentForSelectedRemediation());
  byId("sweep-escalations-btn")?.addEventListener("click", () => runEscalationSweep());

  byId("scanjob-form")?.addEventListener("submit", (event) => createScanJobFromForm(event));
  byId("asset-profile-form")?.addEventListener("submit", (event) => upsertSelectedAssetProfile(event));
  byId("asset-control-form")?.addEventListener("submit", (event) => createCompensatingControlForSelectedAsset(event));
  byId("policy-create-form")?.addEventListener("submit", (event) => createPolicyFromForm(event));
  byId("policy-update-form")?.addEventListener("submit", (event) => updateSelectedPolicyFromForm(event));
  byId("remediation-transition-form")?.addEventListener("submit", (event) => transitionSelectedRemediationFromForm(event));
  byId("remediation-retest-form")?.addEventListener("submit", (event) => requestRetestForSelectedRemediationFromForm(event));
  byId("remediation-comment-form")?.addEventListener("submit", (event) => addCommentForSelectedRemediationFromForm(event));
  byId("remediation-exception-form")?.addEventListener("submit", (event) => createRemediationExceptionFromForm(event));
  byId("remediation-assignment-form")?.addEventListener("submit", (event) => createRemediationAssignmentFromForm(event));
  byId("remediation-ticket-form")?.addEventListener("submit", (event) => createRemediationTicketFromForm(event));
  byId("remediation-evidence-form")?.addEventListener("submit", (event) => createRemediationEvidenceFromForm(event));
  byId("remediation-verify-form")?.addEventListener("submit", (event) => recordRemediationVerificationFromForm(event));

  ["findings-search", "filter-severity", "filter-priority", "filter-layer", "filter-overdue"].forEach((id) => {
    byId(id)?.addEventListener("input", () => renderFindings());
    byId(id)?.addEventListener("change", () => renderFindings());
  });

  byId("remediation-status-filter")?.addEventListener("change", () => renderRemediations());

  byId("export-summary-json")?.addEventListener("click", () => {
    const payload = buildSummarySnapshot();
    renderReportPreview(payload);
    downloadJSONFile(`uss-summary-${Date.now()}.json`, payload);
  });

  byId("export-findings-json")?.addEventListener("click", () => {
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
