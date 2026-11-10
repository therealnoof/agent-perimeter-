// agentd audit view — Preact + HTM, no build step.
//
// Data arrives as one JSON document over Server-Sent Events (/events) and
// is re-sent whole on every change. The page is a pure function of that
// document plus two bits of local UI state: the selected request and the
// theme. Nothing here writes anywhere.

import { h, render } from "./vendor/preact.module.js";
import { useState, useEffect, useRef, useMemo } from "./vendor/hooks.module.js";
import htm from "./vendor/htm.module.js";
import uPlot from "./vendor/uPlot.esm.js";

const html = htm.bind(h);

// ---------- helpers ------------------------------------------------------------

const fmtTime = (iso) => {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
};
const short = (s, n = 8) => (s ? s.slice(0, n) : "");
const us = (v) => (v >= 1000 ? (v / 1000).toFixed(1) + " ms" : v + " µs");
const ms = (v) => (v >= 1000 ? (v / 1000).toFixed(1) + " s" : v + " ms");
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// Fixed categorical slot per tool name, assigned in first-seen order and
// then never changed for the life of the page (colour follows the entity).
const toolSlots = new Map();
const toolColor = (tool) => {
  if (!toolSlots.has(tool)) toolSlots.set(tool, (toolSlots.size % 8) + 1);
  return `var(--series-${toolSlots.get(tool)})`;
};

// Verdict / outcome words. The pill colour is status; the word is always shown.
const outcomeLabel = {
  executed: "executed", allowed: "allowed", denied: "denied", pending: "pending",
  pending_timeout: "timed out", declined: "declined", approved: "approved",
  approved_then_failed: "approved, failed", exec_failed: "exec failed", rejected: "rejected",
};

// ---------- data: SSE with reconnect ------------------------------------------------

function useLiveState() {
  const [state, setState] = useState(null);
  const [live, setLive] = useState(false);
  useEffect(() => {
    let es;
    const connect = () => {
      es = new EventSource("/events");
      es.onopen = () => setLive(true);
      es.onmessage = (e) => { try { setState(JSON.parse(e.data)); } catch {} };
      es.onerror = () => { setLive(false); es.close(); setTimeout(connect, 1500); };
    };
    fetch("/api/state").then((r) => r.json()).then(setState).catch(() => {});
    connect();
    return () => es && es.close();
  }, []);
  return [state, live];
}

// ---------- components ---------------------------------------------------------------

function Pill({ kind, children }) {
  return html`<span class=${"pill " + kind}>${children}</span>`;
}

function StatusBar({ s, live, theme, setTheme }) {
  const g = s.governor || {};
  const c = s.chain || {};
  return html`
    <div class="card">
      <div class="brand">agentd <small>audit view</small></div>
      <div class="kv"><span class="k">chain</span>
        <span class=${c.ok ? "v chain-ok" : "v chain-bad"}>${c.ok ? `intact · ${c.records} records` : `BROKEN · ${c.error || "unverified"}`}</span></div>
      <div class="kv"><span class="k">role</span><span class="v">${g.role || "—"}</span></div>
      <div class="kv"><span class="k">operator</span><span class="v">${g.originating_user || "—"}</span></div>
      <div class="kv"><span class="k">governor runs in chain</span><span class="v">${g.runs || 0}</span></div>
      <div class="kv"><span class="k">worker</span>
        <span class="v mono" title=${g.worker_cmd}>${(g.worker_cmd || "—").split(" ").slice(-1)[0]}
          <span class="muted"> exe ${short(g.worker_exe_sha256)}${g.worker_script_sha256 ? " · script " + short(g.worker_script_sha256) : ""}</span></span></div>
      <div class="spacer"></div>
      <span class=${"live" + (live ? "" : " off")}><span class="dot"></span>${live ? "live" : "reconnecting"}</span>
      <button class="btn" onClick=${() => setTheme(theme === "dark" ? "light" : "dark")}>${theme === "dark" ? "light" : "dark"} theme</button>
    </div>`;
}

function Timeline({ reqs, sel, setSel }) {
  const ref = useRef();
  useEffect(() => { if (ref.current && sel == null) ref.current.scrollTop = ref.current.scrollHeight; }, [reqs.length]);
  return html`
    <div class="card col-8">
      <h2>Trace timeline <span class="sub">${reqs.length} requests · newest last · click a row</span></h2>
      ${reqs.length === 0 ? html`<div class="empty">No requests yet. Run a worker through the governor.</div>` : html`
      <div class="scroll" ref=${ref}>
        <table>
          <thead><tr><th>time</th><th>tool</th><th>target</th><th>verdict</th><th>rule</th><th class="num">taint</th><th>outcome</th><th class="num">total</th></tr></thead>
          <tbody>
            ${reqs.map((q) => html`
              <tr class=${"row" + (sel === q.req_id ? " sel" : "")} onClick=${() => setSel(sel === q.req_id ? null : q.req_id)} key=${q.req_id}>
                <td class="mono dim">${fmtTime(q.time)}</td>
                <td><span style=${`border-left:3px solid ${toolColor(q.tool)};padding-left:6px`}>${q.tool || html`<span class="muted">—</span>`}</span></td>
                <td class="mono">${q.target && q.target !== "-" ? q.target : html`<span class="muted">–</span>`}</td>
                <td><${Pill} kind=${q.verdict}>${q.verdict}<//></td>
                <td class="mono dim">${q.rule || q.reason_code || ""}</td>
                <td class="num">${q.taint_at}${q.executor && q.executor.taint_after > q.taint_at ? html`<span class="muted"> → ${q.executor.taint_after}</span>` : ""}</td>
                <td><${Pill} kind=${q.outcome}>${outcomeLabel[q.outcome] || q.outcome}<//></td>
                <td class="num mono dim">${us(q.t_total_us)}</td>
              </tr>`)}
          </tbody>
        </table>
      </div>`}
    </div>`;
}

function Detail({ q, releases }) {
  if (!q) return html`<div class="card col-4"><h2>Trace detail</h2><div class="empty">Select a request to see its spans.</div></div>`;
  const rel = releases.filter((r) => r.req_id === q.req_id);
  const total = Math.max(q.t_total_us, 1);
  const spans = [
    ["schema", q.t_schema_us, "schema"],
    ["policy", q.t_policy_us, "policy"],
    ["approval wait", q.t_approval_ms * 1000, "approval"],
    ["executor", q.t_exec_ms * 1000, "exec"],
  ].filter(([, v]) => v > 0);
  return html`
    <div class="card col-4">
      <h2>Trace detail <span class="sub mono">${q.req_id}</span></h2>
      <div class="detail">
        <div class="kv"><span class="k">task</span><span class="v">${q.task_id}</span></div>
        <div class="kv"><span class="k">tool · target</span><span class="v">${q.tool} · ${q.target || "-"}</span></div>
        <div class="kv"><span class="k">args sha256</span><span class="v">${short(q.args_hash, 16)}…</span></div>
        <div class="kv"><span class="k">client</span><span class="v">${q.client || "—"}</span></div>
        <div class="kv"><span class="k">verdict · rule</span><span class="v">${q.verdict} · ${q.rule || q.reason_code || "—"}</span></div>
        <div class="kv"><span class="k">justification</span><span class="v">${q.j_len ? q.j_len + " bytes (not shown)" : "none"}</span></div>
        ${q.approval ? html`<div class="kv"><span class="k">human</span><span class="v">${q.approval.decision} by ${q.approval.approver_id} · ${q.approval.reason_code} · waited ${ms(q.approval.wait_ms)}</span></div>` : ""}
        ${q.executor ? html`<div class="kv"><span class="k">executor</span><span class="v">exit ${q.executor.exit_code} · token ${short(q.executor.token_id)} · ${q.executor.released ? "credential released" : "no credential"}</span></div>` : ""}
        ${q.reject_why ? html`<div class="kv"><span class="k">rejected</span><span class="v">${q.reject_why}</span></div>` : ""}
      </div>
      <div class="spans">
        ${spans.map(([name, v, cls]) => html`
          <div class="span"><span class="dim">${name}</span>
            <div><div class=${"bar " + cls} style=${`width:${Math.max(2, Math.min(100, (v / total) * 100))}%`}></div></div>
            <span class="val">${us(Math.round(v))}</span></div>`)}
        <div class="span"><span class="dim">total</span><div></div><span class="val">${us(q.t_total_us)}</span></div>
      </div>
      ${rel.length ? html`<div class="chart-note">sidecar: ${rel.map((r) => `${r.event} ${r.path || ""}`).join(", ")}</div>` : ""}
    </div>`;
}

// Taint over time: one series, step line, approval events as markers.
function TaintChart({ points, approvals, theme }) {
  const ref = useRef();
  const plot = useRef();
  useEffect(() => {
    if (!ref.current) return;
    const xs = points.map((p) => new Date(p.t).getTime() / 1000);
    const ys = points.map((p) => p.taint);
    const appr = new Set(approvals.map((a) => new Date(a.time).getTime() / 1000));
    const opts = {
      width: ref.current.clientWidth, height: 170,
      cursor: { drag: { x: false, y: false } },
      scales: { y: { range: [0, 10] } },
      axes: [
        { stroke: cssVar("--text-3"), grid: { stroke: cssVar("--grid") }, ticks: { stroke: cssVar("--grid") }, font: "11px system-ui" },
        { stroke: cssVar("--text-3"), grid: { stroke: cssVar("--grid") }, ticks: { stroke: cssVar("--grid") }, font: "11px system-ui", size: 36, incrs: [1, 2, 5] },
      ],
      series: [
        {},
        { label: "taint", stroke: cssVar("--series-1"), width: 2, paths: uPlot.paths.stepped({ align: 1 }),
          points: { show: (u, si, i0, i1) => true, size: 8, stroke: cssVar("--series-1"), fill: cssVar("--surface-1"), width: 2 } },
      ],
      hooks: {
        draw: [(u) => {
          // Approval markers: a short dashed rule at each approval time.
          const ctx = u.ctx; ctx.save(); ctx.setLineDash([3, 3]); ctx.strokeStyle = cssVar("--warning"); ctx.lineWidth = 1.5;
          for (const t of appr) { const x = u.valToPos(t, "x", true); ctx.beginPath(); ctx.moveTo(x, u.bbox.top); ctx.lineTo(x, u.bbox.top + u.bbox.height); ctx.stroke(); }
          ctx.restore();
        }],
      },
    };
    if (plot.current) plot.current.destroy();
    plot.current = new uPlot(opts, [xs, ys], ref.current);
    const onResize = () => plot.current && plot.current.setSize({ width: ref.current.clientWidth, height: 170 });
    window.addEventListener("resize", onResize);
    return () => { window.removeEventListener("resize", onResize); plot.current && plot.current.destroy(); plot.current = null; };
  }, [points, approvals, theme]);
  return html`
    <div class="card col-6">
      <h2>Taint over time <span class="sub">highest sensitivity the task has touched · dashed = human asked</span></h2>
      ${points.length ? html`<div class="chart" ref=${ref}></div>` : html`<div class="empty">No verdicts yet.</div>`}
      <div class="chart-note">Taint only rises. The floor at which an outbound tool needs a human is set per tool in the manifest.</div>
    </div>`;
}

function Approvals({ approvals, setSel }) {
  return html`
    <div class="card col-6">
      <h2>Human decisions <span class="sub">${approvals.length}</span></h2>
      ${approvals.length === 0 ? html`<div class="empty">No approve verdicts yet.</div>` : html`
      <div class="scroll"><table>
        <thead><tr><th>time</th><th>tool · target</th><th>rule</th><th>decision</th><th>by</th><th class="num">waited</th></tr></thead>
        <tbody>${[...approvals].reverse().map((a) => html`
          <tr class="row" onClick=${() => setSel(a.req_id)}>
            <td class="mono dim">${fmtTime(a.time)}</td>
            <td>${a.tool} <span class="mono dim">${a.target && a.target !== "-" ? a.target : ""}</span></td>
            <td class="mono dim">${a.rule}</td>
            <td><${Pill} kind=${a.decision === "approved" ? "approved" : a.reason_code === "approval_timeout" ? "pending_timeout" : "declined"}>${a.reason_code}<//></td>
            <td>${a.approver_id}</td>
            <td class="num mono dim">${ms(a.wait_ms)}</td>
          </tr>`)}</tbody>
      </table></div>`}
    </div>`;
}

function Credentials({ releases, reqs, setSel }) {
  const byReq = new Map(reqs.map((q) => [q.req_id, q]));
  return html`
    <div class="card col-6">
      <h2>Credential releases <span class="sub">sidecar events joined to executor records by token id</span></h2>
      ${releases.length === 0 ? html`<div class="empty">No sidecar events (is -secretsd-log set?).</div>` : html`
      <div class="scroll"><table>
        <thead><tr><th>time</th><th>event</th><th>tool</th><th>path</th><th>token</th><th>matched request</th></tr></thead>
        <tbody>${[...releases].reverse().map((r) => { const q = byReq.get(r.req_id); return html`
          <tr class="row" onClick=${() => r.req_id && setSel(r.req_id)}>
            <td class="mono dim">${fmtTime(r.ts)}</td>
            <td><${Pill} kind=${r.event}>${r.event}<//></td>
            <td>${r.tool}</td>
            <td class="mono dim">${r.path || ""}</td>
            <td class="mono dim">${short(r.token_id)}</td>
            <td>${q ? html`${q.tool} → ${outcomeLabel[q.outcome]}` : html`<span class=${r.event === "released" ? "pill critical" : "muted"}>${r.event === "released" ? "ORPHAN: no executor record" : r.error || ""}</span>`}</td>
          </tr>`; })}</tbody>
      </table></div>`}
    </div>`;
}

function Profile({ p, setSel }) {
  const mix = Object.entries(p.tool_mix || {}).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...mix.map(([, n]) => n));
  const grams = Object.entries(p.bigrams || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  return html`
    <div class="card col-6">
      <h2>Behavioural profile <span class="sub">shape of the agent's activity · never its words · never a policy input</span></h2>
      <div>
        <span class="stat"><span class="n">${p.requests || 0}</span><span class="k">requests</span></span>
        <span class="stat"><span class="n">${p.distinct_targets || 0}</span><span class="k">targets</span></span>
        <span class="stat"><span class="n">${p.approve_verdicts || 0}</span><span class="k">human asks</span></span>
        <span class="stat"><span class="n">${p.unknown_tool_attempts || 0}</span><span class="k">off-manifest</span></span>
        <span class="stat"><span class="n">${p.retry_after_deny || 0}</span><span class="k">retries after deny</span></span>
        <span class="stat"><span class="n">${p.policy_p95_us ? us(p.policy_p95_us) : "—"}</span><span class="k">policy p95</span></span>
        <span class="stat"><span class="n">${p.gap_p50_ms != null && p.requests > 1 ? ms(p.gap_p50_ms) : "—"}</span><span class="k">gap p50</span></span>
      </div>
      ${p.flags && p.flags.length ? html`
        <div class="flags" style="margin:8px 0 12px">
          ${p.flags.map((f) => html`<div class="flag"><${Pill} kind=${f.severity}>${f.severity}<//>
            <div><div class="txt">${f.text}</div>
              ${f.req_ids && f.req_ids.length ? html`<div class="refs">${f.req_ids.map((id) => html`<a href="#" onClick=${(e) => { e.preventDefault(); setSel(id); }}>${short(id)}</a> `)}</div>` : ""}
            </div></div>`)}
        </div>` : html`<div class="chart-note" style="margin:6px 0 12px">No anomaly flags. Baselines per role arrive with the week-5 benign runs; until then these are fixed heuristics.</div>`}
      <div class="bars">
        ${mix.map(([tool, n]) => html`<div class="barrow"><span>${tool}</span><div class="track"><div class="fill" style=${`width:${(n / max) * 100}%;background:${toolColor(tool)}`}></div></div><span class="n">${n}</span></div>`)}
      </div>
      ${p.sequence && p.sequence.length ? html`<div class="chart-note" style="margin-top:12px">call sequence (last ${p.sequence.length})</div>
        <div class="seq">${p.sequence.map((t, i) => html`<span class="tok" style=${`border-left-color:${toolColor(t)}`} key=${i}>${t}</span>`)}</div>` : ""}
      ${grams.length ? html`<div class="chart-note" style="margin-top:10px">frequent transitions: ${grams.map(([g, n]) => `${g} ×${n}`).join(" · ")}</div>` : ""}
      ${p.clients && Object.keys(p.clients).length ? html`<div class="chart-note">client: ${Object.keys(p.clients).join(", ")}</div>` : ""}
    </div>`;
}

function Services({ lines, lifecycle }) {
  return html`
    <div class="card col-12">
      <h2>What reached the services <span class="sub">mock Jira/Slack request log · call = governor token id</span></h2>
      ${lines && lines.length ? html`<pre class="log">${lines.slice(-40).join("\n")}</pre>` : html`<div class="empty">No service calls yet (is -mock-addr set and mockserv running?).</div>`}
      ${lifecycle && lifecycle.length ? html`<div class="chart-note" style="margin-top:10px">governor lifecycle: ${lifecycle.slice(-6).map((e) => `${fmtTime(e.time)} ${e.event}${e.detail ? " (" + e.detail.slice(0, 60) + ")" : ""}`).join(" · ")}</div>` : ""}
    </div>`;
}

// ---------- app ------------------------------------------------------------------------

function App() {
  const [s, live] = useLiveState();
  const [sel, setSel] = useState(null);
  const [theme, setThemeState] = useState(() => { try { return localStorage.getItem("auditview-theme") || "dark"; } catch { return "dark"; } });
  const setTheme = (t) => { setThemeState(t); try { localStorage.setItem("auditview-theme", t); } catch {} };
  useEffect(() => { document.body.setAttribute("data-theme", theme); document.documentElement.setAttribute("data-theme", theme); }, [theme]);

  if (!s) return html`<div class="boot">waiting for first state…</div>`;
  const reqs = s.requests || [];
  const q = reqs.find((r) => r.req_id === sel);
  return html`
    <div class="app">
      <div class="statusbar"><${StatusBar} s=${s} live=${live} theme=${theme} setTheme=${setTheme} /></div>
      <${Timeline} reqs=${reqs} sel=${sel} setSel=${setSel} />
      <${Detail} q=${q} releases=${s.releases || []} />
      <${TaintChart} points=${s.taint || []} approvals=${s.approvals || []} theme=${theme} />
      <${Approvals} approvals=${s.approvals || []} setSel=${setSel} />
      <${Credentials} releases=${s.releases || []} reqs=${reqs} setSel=${setSel} />
      <${Profile} p=${s.profile || {}} setSel=${setSel} />
      <${Services} lines=${s.services} lifecycle=${s.lifecycle} />
    </div>`;
}

render(html`<${App} />`, document.getElementById("app"));
