"use strict";

// Session credentials are held only in this page's memory. This view never
// changes membership, dispatches work, or sends data outside the local agent.
const byId = (id) => document.getElementById(id);
const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
if (window.location.hash) window.history.replaceState(null, "", window.location.pathname + window.location.search);
let inventory = null;
let selectedId = null;
let inFlight = false;
let connectionLost = false;
let stopped = false;
let activeRequest = null;
const svgNamespace = "http://www.w3.org/2000/svg";

function text(id, value) { byId(id).textContent = value; }
function number(value) { return typeof value === "number" && Number.isFinite(value); }
function bytes(value) {
  if (!number(value) || value < 0) return "Unavailable";
  if (value < 1024 ** 2) return `${Math.round(value / 1024)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  if (value < 1024 ** 4) return `${(value / 1024 ** 3).toFixed(1)} GiB`;
  return `${(value / 1024 ** 4).toFixed(1)} TiB`;
}
function uptime(value) {
  if (!number(value) || value < 0) return "Unavailable";
  const days = Math.floor(value / 86400);
  const hours = Math.floor(value % 86400 / 3600);
  const minutes = Math.floor(value % 3600 / 60);
  return `${days ? `${days}d ` : ""}${hours}h ${minutes}m`;
}
function timestamp(value) {
  if (!number(value) || value <= 0) return "Not yet observed";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function status(node) { return ["online", "offline", "awaiting"].includes(node.status) ? node.status : "offline"; }
function statusLabel(node) {
  const label = { online: "Online", offline: "Offline", awaiting: "Awaiting heartbeat" }[status(node)];
  return connectionLost ? `Last known: ${label.toLowerCase()}` : label;
}
function element(tag, className, content) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (content !== undefined) item.textContent = content;
  return item;
}
function machineIcon() {
  const svg = document.createElementNS(svgNamespace, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(svgNamespace, "path");
  path.setAttribute("d", "M4 4.5h16v11H4zM9 20h6M12 16v4M7 8h4M7 11h7");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.4");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  svg.append(path);
  return svg;
}
function nodeCard(node) {
  const local = node.kind === "local";
  const card = element("button", `node-card ${local ? "local" : "peer"} ${status(node)}${selectedId === node.node_id ? " selected" : ""}`);
  card.type = "button";
  card.dataset.nodeId = node.node_id;
  card.setAttribute("aria-pressed", String(selectedId === node.node_id));
  card.setAttribute("aria-label", `${node.name}, ${local ? "local machine" : "fabric member"}, ${statusLabel(node)}. Inspect node.`);
  const top = element("span", "node-card-top");
  const icon = element("span", "node-icon");
  icon.append(machineIcon());
  top.append(icon, element("span", "node-kind-label", local ? "THIS MACHINE" : "FABRIC MEMBER"));
  const name = element("span", "node-card-name", node.name);
  name.title = node.name;
  const resource = node.resources;
  const detail = [];
  if (number(resource?.cpu?.logical_cores)) detail.push(`${resource.cpu.logical_cores} cores`);
  if (number(resource?.memory?.total_bytes)) detail.push(bytes(resource.memory.total_bytes));
  const summary = element("span", "node-card-resource", detail.length ? detail.join(" · ") : "No resource sample yet");
  const state = element("span", "node-card-status");
  state.append(element("i", "tiny-dot"), element("span", "", statusLabel(node)));
  card.append(top, name, summary, state);
  return card;
}
function drawConnections() {
  const svg = byId("topology-lines");
  svg.replaceChildren();
  const local = byId("local-node").querySelector("button");
  if (!local) return;
  const container = byId("topology").getBoundingClientRect();
  const origin = local.getBoundingClientRect();
  const startX = origin.left + origin.width / 2 - container.left;
  const startY = origin.bottom - container.top;
  for (const peer of byId("peer-nodes").querySelectorAll("button")) {
    const rect = peer.getBoundingClientRect();
    const targetX = rect.left + rect.width / 2 - container.left;
    const targetY = rect.top - container.top;
    const path = document.createElementNS(svgNamespace, "path");
    const curveY = startY + Math.max(12, (targetY - startY) / 2);
    path.setAttribute("d", `M${startX},${startY} C${startX},${curveY} ${targetX},${curveY} ${targetX},${targetY}`);
    path.setAttribute("fill", "none");
    path.setAttribute("class", `topology-line${peer.classList.contains("online") ? "" : " inactive"}`);
    svg.append(path);
  }
}
function renderNodes() {
  const focusedId = document.activeElement?.dataset?.nodeId;
  const localNodes = document.createDocumentFragment();
  const peerNodes = document.createDocumentFragment();
  for (const node of inventory.nodes) (node.kind === "local" ? localNodes : peerNodes).append(nodeCard(node));
  byId("local-node").replaceChildren(localNodes);
  byId("peer-nodes").replaceChildren(peerNodes);
  byId("map-empty").hidden = inventory.nodes.some((node) => node.kind !== "local");
  if (focusedId) {
    const matching = [...byId("topology").querySelectorAll("button")].find((button) => button.dataset.nodeId === focusedId);
    matching?.focus({ preventScroll: true });
  }
  requestAnimationFrame(drawConnections);
}
function meter(prefix, ratio, hint) {
  const valid = number(ratio) && ratio >= 0;
  const clamped = valid ? Math.max(0, Math.min(100, ratio)) : 0;
  text(`${prefix}-value`, valid ? `${Math.round(clamped)}%` : "Unavailable");
  byId(`${prefix}-fill`).style.width = `${clamped}%`;
  text(`${prefix}-hint`, hint);
}
function renderInspector() {
  const node = inventory.nodes.find((item) => item.node_id === selectedId);
  byId("inspector-placeholder").hidden = Boolean(node);
  byId("inspector-body").hidden = !node;
  if (!node) return;
  const resource = node.resources;
  const stale = connectionLost || status(node) !== "online";
  text("inspector-title", node.name);
  text("inspector-kind", node.kind === "local" ? "Local node" : "Fabric member");
  text("inspector-status", statusLabel(node));
  byId("inspector-status").className = `status-badge ${status(node)}`;
  text("inspector-system", resource?.node ? `${resource.node.operating_system}${resource.node.is_wsl ? " / WSL2" : ""}` : "No telemetry");
  const errors = [];
  if (connectionLost) errors.push("The local agent is unavailable. Showing the last received inventory.");
  else if (stale && resource) errors.push("Showing cached measurements, excluded from online totals.");
  else if (status(node) === "awaiting") errors.push("Membership confirmed. Waiting for this node's first authenticated heartbeat.");
  else if (status(node) === "offline") errors.push("No recent heartbeat. This node is excluded from online totals.");
  if (node.error) errors.push(node.error);
  byId("inspector-error").hidden = errors.length === 0;
  text("inspector-error", errors.join(" "));
  const cores = resource?.cpu?.logical_cores;
  meter("cpu", resource?.cpu?.usage_percent, resource ? `${number(cores) ? `${cores} logical cores` : "Core count unavailable"}${number(resource.cpu?.load_one_minute) ? ` · load ${resource.cpu.load_one_minute.toFixed(2)}` : ""}${stale ? " · cached" : ""}` : "No resource sample received");
  const memory = resource?.memory;
  const memoryRatio = number(memory?.used_bytes) && number(memory?.total_bytes) && memory.total_bytes > 0 ? memory.used_bytes / memory.total_bytes * 100 : null;
  meter("memory", memoryRatio, memory ? `${bytes(memory.used_bytes)} / ${bytes(memory.total_bytes)}${stale ? " · cached" : ""}` : "No resource sample received");
  const storage = resource?.storage;
  const storageRatio = number(storage?.used_bytes) && number(storage?.total_bytes) && storage.total_bytes > 0 ? storage.used_bytes / storage.total_bytes * 100 : null;
  meter("storage", storageRatio, storage ? `${bytes(storage.used_bytes)} / ${bytes(storage.total_bytes)}${stale ? " · cached" : ""}` : "Storage measurement unavailable");
  text("detail-endpoint", node.endpoint || (node.kind === "local" ? "This machine" : "Not advertised"));
  text("detail-uptime", uptime(resource?.node?.uptime_seconds));
  const interfaces = Array.isArray(resource?.network) ? resource.network.filter((item) => item.link_state === "up").map((item) => item.name) : null;
  text("detail-network", interfaces ? interfaces.join(", ") || "No active interfaces" : "Unavailable");
  text("detail-gpu", resource?.gpu?.status && !["unavailable", "not_implemented"].includes(resource.gpu.status) ? resource.gpu.status : "Not yet probed");
  text("detail-seen", timestamp(node.last_seen_ms));
  text("detail-id", node.node_id);
  byId("detail-id").title = node.node_id;
}
function renderSummary() {
  const online = inventory.nodes.filter((node) => status(node) === "online");
  const peers = inventory.nodes.filter((node) => node.kind !== "local");
  const cpuNodes = online.filter((node) => number(node.resources?.cpu?.logical_cores));
  const memoryNodes = online.filter((node) => number(node.resources?.memory?.available_bytes) && number(node.resources?.memory?.total_bytes));
  const memoryAvailable = memoryNodes.reduce((sum, node) => sum + node.resources.memory.available_bytes, 0);
  const memoryTotal = memoryNodes.reduce((sum, node) => sum + node.resources.memory.total_bytes, 0);
  const memoryParts = bytes(memoryAvailable).split(" ");
  text("nav-count", inventory.nodes.length);
  text("online-count", connectionLost ? "—" : online.length);
  text("node-summary", connectionLost ? "Local agent unavailable" : `${inventory.nodes.length} known ${inventory.nodes.length === 1 ? "node" : "nodes"} · ${peers.length} remote ${peers.length === 1 ? "member" : "members"}`);
  text("core-count", connectionLost || !cpuNodes.length ? "—" : cpuNodes.reduce((sum, node) => sum + node.resources.cpu.logical_cores, 0));
  text("memory-free", connectionLost || !memoryNodes.length ? "—" : memoryParts[0]);
  text("memory-unit", connectionLost || !memoryNodes.length ? "" : memoryParts[1]);
  text("memory-summary", connectionLost ? "Current inventory unavailable" : memoryNodes.length ? `Of ${bytes(memoryTotal)} reported memory` : "No online memory measurements");
  text("fabric-label", `FABRIC / ${inventory.fabric_id}`);
  text("sample-time", `${connectionLost ? "Last sample" : "Updated"} ${timestamp(inventory.collected_at_ms)}`);
}
function render(data) {
  inventory = data;
  if (!data.nodes.some((node) => node.node_id === selectedId)) selectedId = data.local_node_id || data.nodes[0]?.node_id || null;
  renderSummary();
  renderNodes();
  renderInspector();
  byId("copy-json").disabled = false;
}
function validateInventory(data) {
  if (data?.schema_version !== 1 || !Array.isArray(data.nodes) || typeof data.fabric_id !== "string") throw new Error("Unsupported fabric inventory response");
  const identities = new Set();
  for (const node of data.nodes) {
    if (!node || typeof node.node_id !== "string" || typeof node.name !== "string" || !["local", "peer"].includes(node.kind) || identities.has(node.node_id)) throw new Error("Invalid node identity in fabric inventory");
    identities.add(node.node_id);
  }
  return data;
}
async function refresh() {
  if (inFlight || !token || stopped) return;
  inFlight = true;
  byId("refresh").disabled = true;
  activeRequest = new AbortController();
  const timeout = setTimeout(() => activeRequest?.abort(), 12000);
  try {
    const response = await fetch("/api/v1/fabric", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store", signal: activeRequest.signal });
    if (response.status === 401) throw new Error("Session expired. Reopen the complete resource-map URL printed by the local agent.");
    if (!response.ok) throw new Error(`Local agent returned HTTP ${response.status}`);
    const data = validateInventory(await response.json());
    connectionLost = false;
    render(data);
    byId("session-status").className = "session-status live";
    text("session-label", "Local agent connected");
    byId("error").hidden = true;
  } catch (error) {
    if (stopped) return;
    connectionLost = true;
    byId("session-status").className = "session-status failed";
    text("session-label", "Agent unavailable");
    text("error", `Unable to refresh the resource map. ${error.name === "AbortError" ? "The local agent did not respond in time." : error.message}`);
    byId("error").hidden = false;
    if (inventory) render(inventory);
  } finally {
    clearTimeout(timeout);
    activeRequest = null;
    inFlight = false;
    byId("refresh").disabled = !token;
  }
}

byId("topology").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-node-id]");
  if (!button || !inventory) return;
  selectedId = button.dataset.nodeId;
  renderNodes();
  renderInspector();
});
byId("refresh").addEventListener("click", () => void refresh());
byId("copy-json").addEventListener("click", async () => {
  if (!inventory) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(inventory, null, 2));
    byId("copy-json").textContent = "Inventory copied";
  } catch {
    byId("copy-json").textContent = "Clipboard unavailable";
  }
  setTimeout(() => { byId("copy-json").textContent = "Copy inventory JSON ↗"; }, 1800);
});
if (typeof ResizeObserver !== "undefined") new ResizeObserver(drawConnections).observe(byId("topology"));
else window.addEventListener("resize", drawConnections);
if (!token) {
  byId("refresh").disabled = true;
  byId("error").hidden = false;
  text("error", "This page needs a session credential. Open the complete resource-map URL printed by the local agent. Reloading without that URL starts an unauthenticated view.");
  byId("session-status").className = "session-status failed";
  text("session-label", "No active session");
} else {
  void refresh();
}
const interval = setInterval(() => void refresh(), 2000);
window.addEventListener("pagehide", () => { stopped = true; clearInterval(interval); activeRequest?.abort(); });
