const TOKEN_STORAGE_KEY = "uss_api_token";

function currentToken() {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

async function loadJSON(url) {
  const token = currentToken();
  const headers = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    credentials: "same-origin",
    headers
  });

  if (!response.ok) {
    if (response.status === 401 && !token) {
      throw new Error("Sign in with SSO or use an API token.");
    }

    let message = `Request failed for ${url}`;
    try {
      const payload = await response.json();
      if (payload && payload.message) {
        message = payload.message;
      }
    } catch (_) {
      // ignore response decoding errors
    }
    throw new Error(message);
  }

  return response.json();
}

function setMetric(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = String(value);
  }
}

function renderList(targetId, items, renderItem) {
  const root = document.getElementById(targetId);
  if (!root) {
    return;
  }

  root.innerHTML = "";
  if (!items.length) {
    const template = document.getElementById("empty-state");
    root.appendChild(template.content.cloneNode(true));
    return;
  }

  items.slice(0, 8).forEach((item) => {
    root.appendChild(renderItem(item));
  });
}

function makeCard(title, body, meta, severity) {
  const card = document.createElement("article");
  card.className = "card";

  const heading = document.createElement("strong");
  if (severity) {
    heading.classList.add(`severity-${severity}`);
  }
  heading.textContent = title;
  card.appendChild(heading);

  const paragraph = document.createElement("p");
  paragraph.textContent = body;
  card.appendChild(paragraph);

  const metaRow = document.createElement("div");
  metaRow.className = "meta";
  meta.forEach((value) => {
    const span = document.createElement("span");
    span.textContent = value;
    metaRow.appendChild(span);
  });
  card.appendChild(metaRow);

  return card;
}

function formatRuleClause(field, match, values) {
  const normalizedValues = Array.isArray(values) && values.length ? values.join("|") : "*";
  return `${field || "unknown"} ${match || "exact"} ${normalizedValues}`;
}

function formatPolicyRule(rule) {
  if (typeof rule === "string") {
    return rule;
  }
  if (!rule || typeof rule !== "object") {
    return "";
  }

  const head = `${rule.effect || "monitor"} ${formatRuleClause(rule.field, rule.match, rule.values)}`;
  const exceptions = Array.isArray(rule.exceptions) ? rule.exceptions : [];
  if (!exceptions.length) {
    return head;
  }

  const renderedExceptions = exceptions
    .map((item) => `except ${formatRuleClause(item.field || rule.field, item.match, item.values)}`)
    .filter(Boolean);
  if (!renderedExceptions.length) {
    return head;
  }

  return `${head}; ${renderedExceptions.join("; ")}`;
}

function formatPolicyRules(rules) {
  if (!Array.isArray(rules) || !rules.length) {
    return "No explicit rules configured.";
  }

  const rendered = rules.map((item) => formatPolicyRule(item)).filter(Boolean);
  if (!rendered.length) {
    return "No explicit rules configured.";
  }

  return rendered.join(", ");
}

function updateSession(session) {
  const user = document.getElementById("session-user");
  const org = document.getElementById("session-org");
  if (!user || !org) {
    return;
  }

  user.textContent = `${session.principal.display_name} (${session.principal.role})`;

  const extras = [
    session.principal.organization_name,
    session.principal.email
  ];
  if (session.bootstrap_token) {
    extras.push("bootstrap token");
  }
  if (session.sso_enabled) {
    extras.push("oidc-ready");
  }

  org.textContent = extras.join(" | ");
}

function renderError(message) {
  const findings = document.getElementById("findings");
  if (findings) {
    findings.innerHTML = `<article class="empty">${message}</article>`;
  }
}

async function boot() {
  try {
    const [session, findingsData, assetsData, policiesData, approvalsData, remediationsData] = await Promise.all([
      loadJSON("/v1/auth/me"),
      loadJSON("/v1/findings"),
      loadJSON("/v1/assets"),
      loadJSON("/v1/policies"),
      loadJSON("/v1/policy-approvals"),
      loadJSON("/v1/remediations")
    ]);

    updateSession(session);

    const findings = findingsData.items || [];
    const assets = assetsData.items || [];
    const policies = policiesData.items || [];
    const approvals = approvalsData.items || [];
    const remediations = remediationsData.items || [];

    setMetric("metric-findings", findings.length);
    setMetric("metric-assets", assets.length);
    setMetric("metric-policies", policies.length);
    setMetric("metric-approvals", approvals.length);
    setMetric("metric-remediations", remediations.length);

    renderList("findings", findings, (item) =>
      makeCard(
        item.title || item.category || "Untitled finding",
        item.description || "No description available.",
        [
          item.severity || "unknown",
          item.source?.layer || "unknown layer",
          item.asset?.asset_name || item.asset?.asset_id || "unknown asset"
        ],
        item.severity || ""
      )
    );

    renderList("assets", assets, (item) =>
      makeCard(
        item.asset_id,
        `${item.scan_count} scans, ${item.finding_count} findings`,
        [item.asset_type, new Date(item.last_scanned_at).toLocaleString()],
        ""
      )
    );

    renderList("policies", policies, (item) =>
      makeCard(
        item.name,
        formatPolicyRules(item.rules),
        [
          item.scope || "global",
          item.mode || "monitor",
          item.enabled ? "enabled" : "disabled",
          `v${item.version_number || 1}`
        ],
        ""
      )
    );

    renderList("policy-approvals", approvals, (item) =>
      makeCard(
        item.action || "Policy approval",
        item.reason || "Awaiting decision.",
        [item.status || "pending", item.requested_by || "unknown", item.policy_id || "no policy"],
        ""
      )
    );

    renderList("remediations", remediations, (item) =>
      makeCard(
        item.title,
        item.notes || "No remediation notes yet.",
        [item.status || "open", item.owner || "unassigned", item.finding_id || "no finding"],
        ""
      )
    );
  } catch (error) {
    setMetric("metric-findings", 0);
    setMetric("metric-assets", 0);
    setMetric("metric-policies", 0);
    setMetric("metric-approvals", 0);
    setMetric("metric-remediations", 0);
    renderList("findings", [], () => document.createElement("div"));
    renderList("assets", [], () => document.createElement("div"));
    renderList("policies", [], () => document.createElement("div"));
    renderList("policy-approvals", [], () => document.createElement("div"));
    renderList("remediations", [], () => document.createElement("div"));
    renderError(error.message);
  }
}

function bindTokenControls() {
  const input = document.getElementById("token-input");
  const saveButton = document.getElementById("token-save");
  const clearButton = document.getElementById("token-clear");
  const ssoButton = document.getElementById("sso-start");
  const logoutButton = document.getElementById("session-logout");

  if (!input || !saveButton || !clearButton || !ssoButton || !logoutButton) {
    return;
  }

  input.value = currentToken();

  saveButton.addEventListener("click", () => {
    const value = input.value.trim();
    if (!value) {
      return;
    }
    window.localStorage.setItem(TOKEN_STORAGE_KEY, value);
    boot();
  });

  clearButton.addEventListener("click", () => {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    input.value = "";
    const user = document.getElementById("session-user");
    const org = document.getElementById("session-org");
    if (user) {
      user.textContent = "Signed out";
    }
    if (org) {
      org.textContent = "Paste an API token to load tenant data.";
    }
    boot();
  });

  ssoButton.addEventListener("click", () => {
    window.location.href = "/auth/oidc/start";
  });

  logoutButton.addEventListener("click", async () => {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    input.value = "";
    window.location.href = "/auth/logout";
  });
}

bindTokenControls();
boot();
