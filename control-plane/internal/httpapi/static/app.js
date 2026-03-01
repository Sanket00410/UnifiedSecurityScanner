async function loadJSON(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed for ${url}`);
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

async function boot() {
  try {
    const [findingsData, assetsData, policiesData, remediationsData] = await Promise.all([
      loadJSON("/v1/findings"),
      loadJSON("/v1/assets"),
      loadJSON("/v1/policies"),
      loadJSON("/v1/remediations")
    ]);

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
    renderList("findings", [], () => document.createElement("div"));
    const findings = document.getElementById("findings");
    if (findings) {
      findings.innerHTML = `<article class="empty">${error.message}</article>`;
    }
  }
}

boot();
