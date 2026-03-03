const TOKEN_STORAGE_KEY = "uss_api_token";

function currentToken() {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

async function loadJSON(url) {
  const token = currentToken();
  if (!token) {
    throw new Error("No API token configured. Use the token panel above.");
  }

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  if (!response.ok) {
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
    const [session, findingsData, assetsData, policiesData, remediationsData] = await Promise.all([
      loadJSON("/v1/auth/me"),
      loadJSON("/v1/findings"),
      loadJSON("/v1/assets"),
      loadJSON("/v1/policies"),
      loadJSON("/v1/remediations")
    ]);

    updateSession(session);

    const findings = findingsData.items || [];
    const assets = assetsData.items || [];
    const policies = policiesData.items || [];
    const remediations = remediationsData.items || [];

    setMetric("metric-findings", findings.length);
    setMetric("metric-assets", assets.length);
    setMetric("metric-policies", policies.length);
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
        item.rules?.length ? item.rules.join(", ") : "No explicit rules configured.",
        [item.scope || "global", item.mode || "monitor", item.enabled ? "enabled" : "disabled"],
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
    setMetric("metric-remediations", 0);
    renderList("findings", [], () => document.createElement("div"));
    renderList("assets", [], () => document.createElement("div"));
    renderList("policies", [], () => document.createElement("div"));
    renderList("remediations", [], () => document.createElement("div"));
    renderError(error.message);
  }
}

function bindTokenControls() {
  const input = document.getElementById("token-input");
  const saveButton = document.getElementById("token-save");
  const clearButton = document.getElementById("token-clear");

  if (!input || !saveButton || !clearButton) {
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
}

bindTokenControls();
boot();
