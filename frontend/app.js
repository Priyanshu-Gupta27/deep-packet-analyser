const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;
const PAGE_SIZE = 50;
const COLORS = ["#5da9ff", "#54c9df", "#6fd1a4", "#b39afa", "#efb36b", "#e783a1", "#84a9ff", "#84c9b1", "#d897e6", "#d4c46e", "#7da7b3", "#de8c70", "#78b9e7", "#9fa7ec", "#83c7cf", "#a1bd77"];

const state = {
  analysisId: "",
  analysis: null,
  page: 1,
  total: 0,
  sortBy: "number",
  sortOrder: "asc",
  packetCacheKey: "",
  packetCache: null,
  packetController: null,
  searchTimer: null,
  selectedFile: null,
  view: "overview"
};

function formatNumber(value) {
  return new Intl.NumberFormat().format(value ?? 0);
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1000) return `${formatNumber(value)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1000;
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit += 1;
  }
  return `${size.toFixed(size < 10 ? 2 : 1)} ${units[unit]}`;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(2)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${(seconds % 60).toFixed(0)}s`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function setUploadState(message, { loading = false, error = false } = {}) {
  const target = $("#upload-state");
  target.hidden = false;
  target.classList.toggle("error", error);
  target.innerHTML = loading
    ? `<span class="loading-stage"><i class="spinner" aria-hidden="true"></i>${escapeHtml(message)}</span>`
    : escapeHtml(message);
}

function setHealth(online) {
  const pill = $("#engine-health");
  pill.classList.toggle("offline", !online);
  pill.innerHTML = `<i aria-hidden="true"></i>${online ? "Analyzer ready" : "Analyzer unavailable"}`;
  const sidebarHealth = $("#sidebar-health");
  if (sidebarHealth) {
    $("#sidebar-health-label").textContent = online ? "Analyzer connected" : "Analyzer unavailable";
    $(".health-dot", sidebarHealth).classList.toggle("offline", !online);
  }
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health", { headers: { Accept: "application/json" } });
    setHealth(response.ok);
  } catch {
    setHealth(false);
  }
}

function showSelectedFile(file) {
  state.selectedFile = file;
  $("#selected-file").hidden = false;
  $("#selected-name").textContent = file.name;
  $("#selected-size").textContent = formatBytes(file.size);
  const extension = file.name.toLowerCase();
  const validCapture = extension.endsWith(".pcap") && !extension.endsWith(".pcapng");
  $("#analyze-button").disabled = !validCapture || file.size > MAX_UPLOAD_BYTES;
  if (extension.endsWith(".pcapng")) setUploadState("This analyzer currently supports .pcap files only. PCAPNG support is not available yet.", { error: true });
  else if (!validCapture) setUploadState("Choose a classic .pcap capture file.", { error: true });
  else if (file.size > MAX_UPLOAD_BYTES) setUploadState("This file exceeds the 200 MB upload limit.", { error: true });
  else $("#upload-state").hidden = true;
}

function clearSelectedFile() {
  state.selectedFile = null;
  $("#capture-file").value = "";
  $("#selected-file").hidden = true;
  $("#analyze-button").disabled = true;
  $("#upload-state").hidden = true;
}

function setupUpload() {
  const input = $("#capture-file");
  const dropZone = $("#drop-zone");
  input.addEventListener("change", () => {
    if (input.files?.[0]) showSelectedFile(input.files[0]);
  });
  $("#remove-file").addEventListener("click", clearSelectedFile);
  dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });
  for (const eventName of ["dragenter", "dragover"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
  }
  for (const eventName of ["dragleave", "drop"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
    });
  }
  dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) showSelectedFile(file);
  });
  $("#upload-form").addEventListener("submit", submitUpload);
}

function submitUpload(event) {
  event.preventDefault();
  const file = state.selectedFile;
  if (!file) return;
  if (file.name.toLowerCase().endsWith(".pcapng")) {
    setUploadState("This analyzer currently supports .pcap files only. PCAPNG support is not available yet.", { error: true });
    return;
  }
  if (!file.name.toLowerCase().endsWith(".pcap")) {
    setUploadState("Choose a classic .pcap capture file.", { error: true });
    return;
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    setUploadState("This file exceeds the 200 MB upload limit.", { error: true });
    return;
  }

  const form = new FormData();
  form.append("file", file);
  const request = new XMLHttpRequest();
  request.open("POST", "/api/analyses");
  request.setRequestHeader("Accept", "application/json");
  $("#analyze-button").disabled = true;
  setUploadState("Uploading capture…", { loading: true });
  request.upload.addEventListener("progress", (progress) => {
    if (progress.lengthComputable) {
      setUploadState(`Uploading capture… ${formatBytes(progress.loaded)} of ${formatBytes(progress.total)}`, { loading: true });
    }
  });
  request.upload.addEventListener("load", () => {
    setUploadState("Analyzing packets and preparing results…", { loading: true });
  });
  request.addEventListener("load", () => {
    let result;
    try {
      result = JSON.parse(request.responseText);
    } catch {
      $("#analyze-button").disabled = false;
      setUploadState("The analysis server returned an unreadable response. Please try again.", { error: true });
      return;
    }
    if (request.status < 200 || request.status >= 300) {
      $("#analyze-button").disabled = false;
      setUploadState(result.detail || "The capture could not be analyzed.", { error: true });
      return;
    }
    setUploadState("Processing results…", { loading: true });
    window.location.assign(`/analysis/${encodeURIComponent(result.analysis_id)}`);
  });
  request.addEventListener("error", () => {
    $("#analyze-button").disabled = false;
    setUploadState("Unable to connect to the analysis server.", { error: true });
    setHealth(false);
  });
  request.send(form);
}

async function apiGet(url, signal) {
  let response;
  try {
    response = await fetch(url, { headers: { Accept: "application/json" }, signal });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error("Unable to connect to the analysis server.");
  }
  if (!response.ok) {
    let message = "The requested analysis data is unavailable.";
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch { /* Keep the user-facing fallback message. */ }
    throw new Error(message);
  }
  return response.json();
}

async function loadAnalysis(analysisId) {
  state.analysisId = analysisId;
  $("#upload-screen").hidden = true;
  $("#analysis-shell").hidden = false;
  $("#view-content").setAttribute("aria-busy", "true");
  showGlobalError("Loading capture analysis…", true);
  try {
    const analysis = await apiGet(`/api/analyses/${encodeURIComponent(analysisId)}`);
    state.analysis = analysis;
    renderAnalysis(analysis);
    $("#view-content").setAttribute("aria-busy", "false");
    const requestedView = window.location.hash.slice(1);
    setView(["overview", "packets", "flows", "protocols", "about"].includes(requestedView) ? requestedView : "overview", false);
    await loadPackets();
  } catch (error) {
    $("#view-content").setAttribute("aria-busy", "false");
    if (error.message === "Unable to connect to the analysis server.") setHealth(false);
    showGlobalError(error.message, false);
  }
}

function showGlobalError(message, loading) {
  const target = $("#global-error");
  target.hidden = false;
  target.innerHTML = loading
    ? `<span class="loading-stage"><i class="spinner" aria-hidden="true"></i>${escapeHtml(message)}</span>`
    : escapeHtml(message);
  target.classList.toggle("is-loading", loading);
}

function hideGlobalError() {
  $("#global-error").hidden = true;
  $("#global-error").textContent = "";
}

function renderAnalysis(analysis) {
  const summary = analysis.summary;
  const total = summary.total_packets ?? 0;
  const protocolCount = Object.keys(summary.protocols ?? {}).length;
  $("#capture-name").textContent = summary.filename || "Capture analysis";
  $("#capture-packet-total").textContent = `${formatNumber(total)} packets`;
  $("#overview-filename").textContent = summary.filename || "Capture";
  renderSummary(summary, analysis.flows ?? [], protocolCount);
  const protocolData = Object.entries(summary.protocols ?? {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
  renderDonut("#overview-protocol-chart", protocolData, total, 6);
  renderDonut("#protocol-full-chart", protocolData, total, 16);
  renderTimeline(analysis.charts?.timeline ?? []);
  renderRankList("#overview-sources", analysis.charts?.sources ?? [], "Packets");
  renderRankList("#overview-destinations", analysis.charts?.destinations ?? [], "Packets");
  renderRankList("#overview-ports", analysis.charts?.ports ?? [], "Appearances");
  renderFlows(analysis.flows ?? []);
  renderProtocols(protocolData, total);
  setupProtocolOptions(protocolData);
}

function renderSummary(summary, flows, protocolCount) {
  const cards = [
    { label: "Total packets", value: formatNumber(summary.total_packets), note: "Captured records", icon: "#" },
    { label: "Network flows", value: formatNumber(flows.length), note: "Directional five-tuples", icon: "⇄" },
    { label: "Detected protocols", value: formatNumber(protocolCount), note: "Application categories", icon: "◉" },
    { label: "Total traffic", value: formatBytes(summary.total_bytes), note: "Captured packet bytes", icon: "↓" },
    { label: "Capture duration", value: formatDuration(summary.duration_seconds), note: "First to last timestamp", icon: "◷" },
    { label: "TCP packets", value: formatNumber(summary.tcp_packets), note: "Transport protocol", icon: "T" },
    { label: "UDP packets", value: formatNumber(summary.udp_packets), note: "Transport protocol", icon: "U" }
  ];
  $("#summary-cards").innerHTML = cards.map((card) => `
    <article class="summary-card"><div class="metric-heading"><span>${escapeHtml(card.label)}</span><span class="metric-icon" aria-hidden="true">${card.icon}</span></div>
      <strong>${escapeHtml(card.value)}</strong><small>${escapeHtml(card.note)}</small>
    </article>`).join("");
}

function renderDonut(selector, values, total, limit) {
  const target = $(selector);
  if (!values.length || !total) {
    target.innerHTML = `<div class="chart-empty" role="status">No protocol data available for this capture.</div>`;
    return;
  }
  const circumference = 2 * Math.PI * 58;
  let offset = 0;
  const circles = values.map((item, index) => {
    const length = circumference * (item.value / total);
    const circle = `<circle cx="90" cy="90" r="58" fill="none" stroke="${COLORS[index % COLORS.length]}" stroke-width="23" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" transform="rotate(-90 90 90)"><title>${escapeHtml(item.name)}: ${formatNumber(item.value)} packets (${((item.value / total) * 100).toFixed(1)}%)</title></circle>`;
    offset += length;
    return circle;
  }).join("");
  const visible = values.slice(0, limit);
  const legend = visible.map((item) => {
    const index = values.indexOf(item);
    return `<div class="legend-row"><i class="legend-dot" style="background:${COLORS[index % COLORS.length]}" aria-hidden="true"></i><span class="legend-name">${escapeHtml(item.name)}</span><span class="legend-count">${formatNumber(item.value)}</span></div>`;
  }).join("");
  const more = values.length > limit ? `<div class="legend-more">+ ${values.length - limit} more categories</div>` : "";
  target.innerHTML = `<div class="donut-wrap"><svg viewBox="0 0 180 180" role="img" aria-label="Protocol distribution across ${formatNumber(total)} packets"><circle cx="90" cy="90" r="58" fill="none" stroke="#263440" stroke-width="23"></circle>${circles}</svg><div class="donut-center"><strong>${formatNumber(total)}</strong><span>packets</span></div></div><div class="donut-legend">${legend}${more}</div>`;
}

function renderTimeline(points) {
  const target = $("#overview-timeline");
  if (!points.length) {
    target.innerHTML = `<div class="chart-empty" role="status">No timestamp data available.</div>`;
    return;
  }
  if (points.length === 1) {
    const point = points[0];
    target.innerHTML = `<div class="single-bucket"><div><strong>${formatNumber(point.packets)}</strong>${formatNumber(point.packets) === "1" ? "packet" : "packets"} in capture second +${formatNumber(point.second)}<br><span>${formatBytes(point.bytes)} recorded in this bucket</span></div></div>`;
    return;
  }
  const width = 680;
  const height = 142;
  const left = 14;
  const right = width - 14;
  const top = 12;
  const bottom = height - 13;
  const max = Math.max(1, ...points.map((item) => item.packets));
  const coords = points.map((item, index) => ({
    x: left + ((right - left) * index) / (points.length - 1),
    y: bottom - ((bottom - top) * item.packets) / max,
    item
  }));
  const line = coords.map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");
  const area = `${line} L${right},${bottom} L${left},${bottom} Z`;
  const markers = coords.map((point) => `<circle class="chart-point" cx="${point.x}" cy="${point.y}" r="3"><title>+${formatNumber(point.item.second)}s · ${formatNumber(point.item.packets)} packets · ${formatBytes(point.item.bytes)}</title></circle>`).join("");
  const start = points[0].second;
  const end = points[points.length - 1].second;
  target.innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Packet traffic over ${points.length} capture seconds, with ${formatNumber(points.reduce((sum, point) => sum + point.packets, 0))} packets"><defs><linearGradient id="traffic-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#54c9df" stop-opacity=".25"></stop><stop offset="100%" stop-color="#54c9df" stop-opacity=".01"></stop></linearGradient></defs><line class="chart-grid-line" x1="${left}" y1="${top}" x2="${right}" y2="${top}"></line><line class="chart-grid-line" x1="${left}" y1="${(top + bottom) / 2}" x2="${right}" y2="${(top + bottom) / 2}"></line><line class="chart-grid-line" x1="${left}" y1="${bottom}" x2="${right}" y2="${bottom}"></line><path class="chart-area" d="${area}"></path><path class="chart-line" d="${line}"></path>${markers}</svg><div class="chart-labels"><span>+${formatNumber(start)}s</span><span>Capture elapsed time</span><span>+${formatNumber(end)}s</span></div>`;
}

function renderRankList(selector, rows, unit) {
  const target = $(selector);
  if (!rows.length) {
    target.innerHTML = `<div class="rank-empty">No ${unit.toLowerCase()} data available.</div>`;
    return;
  }
  const max = Math.max(1, ...rows.map((row) => row.value));
  target.innerHTML = rows.map((row) => `
    <div class="rank-row"><span class="rank-label" title="${escapeHtml(row.name)}">${escapeHtml(row.name)}</span>
      <span class="rank-track" aria-hidden="true"><i class="rank-fill" style="width:${(row.value / max) * 100}%"></i></span>
      <span class="rank-value" title="${formatNumber(row.value)} ${unit.toLowerCase()}">${formatNumber(row.value)}</span>
    </div>`).join("");
}

function renderFlows(flows) {
  const target = $("#flow-rows");
  $("#flow-count").textContent = `${formatNumber(flows.length)} flows`;
  $("#flow-table-caption").textContent = `${formatNumber(flows.length)} directional flow records`;
  $("#flow-empty").hidden = flows.length > 0;
  target.innerHTML = flows.map((flow) => `<tr>
    <td class="endpoint">${escapeHtml(flow.src_ip || "—")}<span class="muted-cell">:${escapeHtml(flow.src_port || "—")}</span></td>
    <td class="endpoint">${escapeHtml(flow.dst_ip || "—")}<span class="muted-cell">:${escapeHtml(flow.dst_port || "—")}</span></td>
    <td>${protocolBadge(flow.transport)}</td><td>${protocolBadge(flow.application)}</td>
    <td>${formatNumber(flow.packets)}</td><td>${formatBytes(flow.bytes)}</td>
  </tr>`).join("");
}

function renderProtocols(protocols, total) {
  $("#protocol-count").textContent = `${formatNumber(protocols.length)} categories`;
  $("#protocol-empty").hidden = protocols.length > 0;
  $("#protocol-rows").innerHTML = protocols.map((item, index) => {
    const share = total ? (item.value / total) * 100 : 0;
    return `<tr><td>${protocolBadge(item.name, COLORS[index % COLORS.length])}</td>
      <td>${formatNumber(item.value)}</td>
      <td><span class="share-cell"><span>${share.toFixed(1)}%</span><span class="share-track" aria-hidden="true"><i class="share-fill" style="width:${share}%"></i></span></span></td>
      <td class="muted-cell" aria-label="Not available">—</td>
      <td><button class="protocol-row-button" type="button" data-filter-protocol="${escapeHtml(item.name)}">View packets</button></td></tr>`;
  }).join("");
  $$("[data-filter-protocol]").forEach((button) => button.addEventListener("click", () => filterPacketsByProtocol(button.dataset.filterProtocol)));
}

function setupProtocolOptions(protocols) {
  const select = $("#protocol");
  const values = new Set(protocols.map((protocol) => protocol.name));
  const packetRowsInclude = ["TCP", "UDP"];
  packetRowsInclude.forEach((protocol) => values.add(protocol));
  select.innerHTML = `<option value="">All protocols</option>${[...values].map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("")}`;
}

function protocolBadge(value, color = "") {
  const normalized = String(value || "Unknown").toLowerCase();
  const known = ["tcp", "udp", "dns", "http", "tls", "https"].includes(normalized) ? ` badge-${normalized}` : "";
  const custom = color ? ` style="--badge-accent:${color}"` : "";
  return `<span class="protocol-badge${known}"${custom}>${escapeHtml(value || "Unknown")}</span>`;
}

function setupNavigation() {
  $$('[data-view-link]').forEach((link) => link.addEventListener("click", () => closeSidebar()));
  window.addEventListener("hashchange", () => {
    const requestedView = window.location.hash.slice(1);
    if (state.analysis && ["overview", "packets", "flows", "protocols", "about"].includes(requestedView)) setView(requestedView, false);
  });
  $("#menu-toggle").addEventListener("click", () => {
    const open = $("#sidebar").classList.toggle("open");
    $("#menu-toggle").setAttribute("aria-expanded", String(open));
    $("#sidebar-scrim").hidden = !open;
  });
  $("#sidebar-scrim").addEventListener("click", closeSidebar);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeSidebar();
      closePacketDetails();
    }
  });
}

function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#menu-toggle").setAttribute("aria-expanded", "false");
  $("#sidebar-scrim").hidden = true;
}

function setView(view, updateHash = true) {
  state.view = view;
  $$(".view").forEach((section) => { section.hidden = section.id !== `view-${view}`; });
  $$('[data-view-link]').forEach((link) => {
    const active = link.dataset.viewLink === view;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  if (updateHash && window.location.hash !== `#${view}`) window.location.hash = view;
}

function setupPacketControls() {
  const filterIds = ["search", "src", "dst", "port"];
  filterIds.forEach((inputId) => $("#" + inputId).addEventListener("input", () => {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(() => { state.page = 1; loadPackets(); }, 250);
  }));
  $("#protocol").addEventListener("change", () => { state.page = 1; loadPackets(); });
  $("#clear-filters").addEventListener("click", clearPacketFilters);
  $$('[data-clear-filters]').forEach((button) => button.addEventListener("click", clearPacketFilters));
  $("#prev").addEventListener("click", () => { if (state.page > 1) { state.page -= 1; loadPackets(); } });
  $("#next").addEventListener("click", () => {
    if (state.page * PAGE_SIZE < state.total) { state.page += 1; loadPackets(); }
  });
  $$("[data-sort]").forEach((button) => button.addEventListener("click", () => {
    const field = button.dataset.sort;
    state.sortOrder = state.sortBy === field && state.sortOrder === "asc" ? "desc" : "asc";
    state.sortBy = field;
    state.page = 1;
    updateSortLabels();
    loadPackets();
  }));
  $("#close-detail").addEventListener("click", closePacketDetails);
  $("#protocol-chart-filter").addEventListener("click", () => {
    setView("packets");
    $("#protocol").focus();
  });
}

function clearPacketFilters() {
  ["search", "src", "dst", "port"].forEach((inputId) => { $("#" + inputId).value = ""; });
  $("#protocol").value = "";
  state.page = 1;
  loadPackets();
}

function filterPacketsByProtocol(protocol) {
  setView("packets");
  $("#protocol").value = protocol;
  state.page = 1;
  loadPackets();
}

function packetQuery() {
  return new URLSearchParams({
    page: String(state.page), page_size: String(PAGE_SIZE),
    search: $("#search").value.trim(), protocol: $("#protocol").value,
    src_ip: $("#src").value.trim(), dst_ip: $("#dst").value.trim(),
    port: $("#port").value.trim(), sort_by: state.sortBy, order: state.sortOrder
  });
}

async function loadPackets() {
  const query = packetQuery().toString();
  const cacheKey = `${state.analysisId}?${query}`;
  if (state.packetCacheKey === cacheKey && state.packetCache) {
    renderPackets(state.packetCache);
    return;
  }
  state.packetController?.abort();
  state.packetController = new AbortController();
  const signal = state.packetController.signal;
  try {
    const result = await apiGet(`/api/analyses/${encodeURIComponent(state.analysisId)}/packets?${query}`, signal);
    if (signal.aborted) return;
    state.packetCacheKey = cacheKey;
    state.packetCache = result;
    renderPackets(result);
    hideGlobalError();
  } catch (error) {
    if (error.name !== "AbortError") showGlobalError(error.message, false);
  }
}

function updateSortLabels() {
  $$("[data-sort]").forEach((button) => {
    const active = button.dataset.sort === state.sortBy;
    button.closest("th").setAttribute("aria-sort", active ? (state.sortOrder === "asc" ? "ascending" : "descending") : "none");
    const symbol = $("span", button);
    if (symbol) symbol.textContent = active ? (state.sortOrder === "asc" ? "↑" : "↓") : "↕";
  });
  $("#packet-sort-caption").textContent = `Sorted by ${state.sortBy.replaceAll("_", " ")} · ${state.sortOrder === "asc" ? "ascending" : "descending"}`;
}

function renderPackets(result) {
  state.total = result.total;
  const start = result.total ? (result.page - 1) * result.page_size + 1 : 0;
  const end = Math.min(result.total, result.page * result.page_size);
  const pageCount = Math.max(1, Math.ceil(result.total / result.page_size));
  $("#packet-count-heading").textContent = `${formatNumber(result.total)} packets`;
  $("#packet-range").textContent = `Showing ${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(result.total)} packets`;
  $("#packet-page-label").textContent = `Page ${formatNumber(result.page)} of ${formatNumber(pageCount)}`;
  $("#prev").disabled = result.page <= 1;
  $("#next").disabled = result.page >= pageCount;
  $("#packet-empty").hidden = result.items.length > 0;
  $("#packet-rows").innerHTML = result.items.map((packet) => `<tr>
    <td class="muted-cell">${formatNumber(packet.number)}</td>
    <td>${escapeHtml(formatTimestamp(packet.timestamp))}</td>
    <td class="mono-cell">${escapeHtml(packet.src_ip || "—")}</td>
    <td>${packet.src_port || "—"}</td>
    <td class="mono-cell">${escapeHtml(packet.dst_ip || "—")}</td>
    <td>${packet.dst_port || "—"}</td>
    <td>${protocolBadge(packet.transport)}</td>
    <td>${protocolBadge(packet.application)}</td>
    <td>${formatNumber(packet.length)} B</td>
    <td title="${escapeHtml(packet.host || packet.tcp_flags || "—")}">${escapeHtml(packet.host || packet.tcp_flags || "—")}</td>
    <td><button class="details-button" type="button" data-packet-number="${packet.number}" aria-label="View details for packet ${packet.number}">Details</button></td>
  </tr>`).join("");
  $$('[data-packet-number]').forEach((button) => button.addEventListener("click", () => {
    const packet = result.items.find((item) => item.number === Number(button.dataset.packetNumber));
    if (packet) showPacketDetails(packet);
  }));
  updateSortLabels();
}

function formatTimestamp(timestamp) {
  if (!Number.isFinite(timestamp)) return "—";
  return new Date(timestamp * 1000).toISOString().replace("T", " ").replace("Z", "");
}

function showPacketDetails(packet) {
  const fields = [
    ["Packet", formatNumber(packet.number)], ["Timestamp", formatTimestamp(packet.timestamp)],
    ["Captured length", `${formatNumber(packet.length)} bytes`],
    ["Ethernet source", packet.src_mac || "—"], ["Ethernet destination", packet.dst_mac || "—"],
    ["Source IP", packet.src_ip || "—"], ["Destination IP", packet.dst_ip || "—"],
    ["TTL", packet.ttl || "—"], ["Transport", packet.transport || "—"],
    ["Source port", packet.src_port || "—"], ["Destination port", packet.dst_port || "—"],
    ["TCP flags", packet.tcp_flags || "—"], ["Application", packet.application || "—"],
    ["Host / SNI / DNS", packet.host || "—"], ["Payload length", `${formatNumber(packet.payload_length)} bytes`]
  ];
  $("#detail-title").textContent = `Packet ${formatNumber(packet.number)}`;
  $("#detail-fields").replaceChildren(...fields.map(([label, value]) => {
    const row = document.createElement("div");
    row.className = "detail-row";
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = value;
    row.append(term, detail);
    return row;
  }));
  $("#packet-detail").hidden = false;
  $("#close-detail").focus();
}

function closePacketDetails() {
  const panel = $("#packet-detail");
  if (panel && !panel.hidden) panel.hidden = true;
}

function initialize() {
  setupUpload();
  setupNavigation();
  setupPacketControls();
  updateSortLabels();
  checkHealth();
  const match = window.location.pathname.match(/^\/analysis\/([^/]+)$/);
  if (match) loadAnalysis(decodeURIComponent(match[1]));
}

initialize();
