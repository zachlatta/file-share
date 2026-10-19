// file-share admin dashboard. The admin token lives only in this closure:
// never in cookies or web storage, which uploaded pages on this origin could
// read. All page content is built with textContent, never parsed as HTML,
// because log fields (user agents, referrers) come from visitors.
(() => {
  "use strict";
  let token = "";
  let fileFilter = null;
  let oldest = 0;

  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  };
  const when = (iso) => (iso ? new Date(iso).toLocaleString() : "—");

  async function api(path) {
    const res = await fetch(path, { headers: { Authorization: "Bearer " + token }, cache: "no-store", credentials: "omit" });
    if (res.status === 401) throw new Error("unauthorized");
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  function showLogin(message) {
    token = "";
    $("dashboard").hidden = true;
    $("login-view").hidden = false;
    $("login-error").hidden = !message;
    $("login-error").textContent = message || "";
    $("token").value = "";
    $("token").focus();
  }

  async function signIn(event) {
    event.preventDefault();
    token = $("token").value.trim();
    $("token").value = "";
    try {
      await loadFiles();
    } catch (err) {
      showLogin(err.message === "unauthorized" ? "That admin token is not valid." : "Could not reach the server: " + err.message);
      return;
    }
    $("login-view").hidden = true;
    $("dashboard").hidden = false;
    await loadListening();
    await loadLog(false);
  }

  async function guarded(fn) {
    try {
      await fn();
    } catch (err) {
      if (err.message === "unauthorized") showLogin("Session ended. Sign in again.");
      else alert("Error: " + err.message);
    }
  }

  async function loadFiles() {
    const data = await api("/api/admin/files");
    const body = $("files-table").tBodies[0];
    body.replaceChildren();
    for (const f of data.files) {
      const row = el("tr");
      const name = el("td");
      const link = el("a", f.name);
      link.href = f.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      name.append(link);
      const protection = [];
      if (f.has_password) protection.push("password");
      if (f.allowed_emails && f.allowed_emails.length) protection.push(f.allowed_emails.join(", "));
      row.append(name, el("td", protection.join(" + "), "wrap"), el("td", f.views), el("td", f.viewers), el("td", f.denied), el("td", when(f.last_viewed_at)));
      const action = el("td");
      const button = el("button", "Show log", "link");
      button.type = "button";
      button.addEventListener("click", () => {
        fileFilter = { id: f.id, name: f.name };
        guarded(() => loadLog(false));
        $("log-table").scrollIntoView({ behavior: "smooth" });
      });
      action.append(button);
      row.append(action);
      body.append(row);
    }
    $("files-empty").hidden = data.files.length > 0;
  }

  const size = (n) => {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + units[i];
  };

  async function loadListening() {
    const params = new URLSearchParams({ buckets: "50" });
    const ns = $("listening-namespace").value.trim();
    if (ns) params.set("namespace", ns);
    const days = $("listening-since").value;
    if (days) params.set("since", new Date(Date.now() - Number(days) * 86400000).toISOString().replace(/\.\d+Z$/, "Z"));
    const data = await api("/api/admin/listening?" + params);
    const body = $("listening-table").tBodies[0];
    body.replaceChildren();
    for (const f of data.files) {
      const row = el("tr");
      const bar = el("td");
      const strip = el("div", null, "coverage");
      const most = Math.max(1, ...f.coverage);
      f.coverage.forEach((n, i) => {
        const cell = el("span");
        // CSSOM writes are allowed under style-src 'self'.
        cell.style.opacity = n ? String(0.2 + 0.8 * (n / most)) : "0.05";
        cell.title = Math.round((i / f.coverage.length) * 100) + "%: " + n + " listener" + (n === 1 ? "" : "s");
        strip.append(cell);
      });
      bar.append(strip);
      const who = f.listeners_detail.map((l) => l.user_agent + " · " + l.ip + " · " + Math.round(l.covered * 100) + "%").join("\n");
      const listeners = el("td", f.listeners);
      listeners.title = who;
      row.append(el("td", f.name || f.file_id, "wrap"), el("td", f.requests), listeners, el("td", f.full_downloads),
        el("td", size(f.bytes_served)), el("td", when(f.last_at)), bar);
      body.append(row);
    }
    $("listening-empty").hidden = data.files.length > 0;
  }

  async function loadLog(append) {
    const params = new URLSearchParams({ limit: "200" });
    if ($("event-filter").value) params.set("event", $("event-filter").value);
    if ($("search").value.trim()) params.set("q", $("search").value.trim());
    if (fileFilter) params.set("file", fileFilter.id);
    if (append && oldest) params.set("before", String(oldest));
    $("file-filter").hidden = !fileFilter;
    $("file-filter-name").textContent = fileFilter ? fileFilter.name : "";

    const data = await api("/api/admin/access?" + params);
    const body = $("log-table").tBodies[0];
    if (!append) body.replaceChildren();
    for (const e of data.events) {
      const row = el("tr");
      const event = el("td");
      event.append(el("span", e.event.replace(/_/g, " "), "badge " + e.event));
      const ip = el("td", e.ip + (e.country ? " · " + e.country : ""));
      ip.title = "socket " + (e.remote_addr || "?") + (e.forwarded_for ? "; X-Forwarded-For " + e.forwarded_for : "");
      const ua = el("td", e.user_agent, "wrap");
      row.append(
        el("td", when(e.at)), event, el("td", e.name || e.namespace || "—", "wrap"), el("td", e.email || "—"),
        el("td", (e.via || "").replace(/_/g, " ") || "—"), ip, ua, el("td", e.referer || "—", "wrap"), el("td", e.status || "—"),
      );
      body.append(row);
    }
    if (data.events.length) oldest = data.events[data.events.length - 1].id;
    $("more").hidden = data.events.length < 200;
    $("log-empty").hidden = body.rows.length > 0;
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("login-form").addEventListener("submit", signIn);
    $("logout").addEventListener("click", () => showLogin(""));
    $("refresh").addEventListener("click", () => guarded(async () => { await loadFiles(); await loadListening(); await loadLog(false); }));
    $("listening-filters").addEventListener("submit", (event) => { event.preventDefault(); guarded(loadListening); });
    $("listening-since").addEventListener("change", () => guarded(loadListening));
    $("filters").addEventListener("submit", (event) => { event.preventDefault(); guarded(() => loadLog(false)); });
    $("event-filter").addEventListener("change", () => guarded(() => loadLog(false)));
    $("clear-file").addEventListener("click", () => { fileFilter = null; guarded(() => loadLog(false)); });
    $("more").addEventListener("click", () => guarded(() => loadLog(true)));
  });
})();
