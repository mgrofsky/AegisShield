// Live "watch the agents work" office: pure CSS + DOM renderer.
//
// Public contract: officeRenderInit / officeRenderSync / officeRenderHide /
// officeRenderReady. The renderer owns its rAF loop and calls the pure tween
// (advanceDeskAnim) from roster.js once per desk per frame.
//
// One renderer, two model sources (distinguished by model.agentic):
//   - linear  office:true  -> buildStageDeskModel (lead === null, one desk/stage)
//   - agentic agentic:true -> buildDeskModel       (central Lead + specialists)
//
// CSP-clean: built entirely with createElement + textContent. The activity
// bubble text is untrusted stage/agent text, so it is ALWAYS set via
// textContent (never a markup-injection sink). Inline `style` left/top (numeric
// percentages we compute) is allowed under the CSP (style-src is not nonce-gated).

import {
  advanceDeskAnim,
  allDeskAnimsSettled,
  isTerminalStatus,
  staggerDelayMs,
  officeFracPos,
  officeEdges,
} from "./roster.js";

const SVG_NS = "http://www.w3.org/2000/svg";

// The agent palette is the locked design-system --ag-* tokens; the model already
// carries the resolved hex per desk in d.color, so the head shape is tinted from
// that directly (no per-id lookup here).

const CX = {
  mountEl: null,
  shell: null,
  edgeSvg: null,
  packetHost: null,
  rug: null,
  deskHost: null,
  nodes: new Map(), // desk id -> { node, head, label, bubble }
  anim: new Map(), // desk id -> tween anim state
  edges: [], // active-edge packet records: { dot, a, b, dir, offset }
  pulsePhase: 0, // shared packet clock (loops in [0,1)), advanced by step(dt)
  model: null,
  deskKey: "",
  raf: 0,
  lastTs: 0,
  ready: false,
};

// Map a tween display phase to the desk state CSS class. Reading the tween phase
// (not the raw polled status) is what makes the guaranteed-visible working dwell
// actually show: a desk the backend jumped straight to "done" still wears
// .working until advanceDeskAnim commits it.
const PHASE_CLASS = {
  queued: "",
  working: "working",
  done: "done",
  fallback: "fallback",
  error: "error",
};

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// Build the static office shell: dark room + room tag + dashed command rug +
// the desk host the per-desk nodes mount into.
function buildShell(mountEl) {
  clear(mountEl);

  const shell = document.createElement("div");
  shell.className = "office lg office-vector";

  const tag = document.createElement("span");
  tag.className = "tag";
  tag.textContent = "LEAD · SPECIALIST MESH";
  shell.appendChild(tag);

  // Mesh edge layer: BEHIND the rug + desks, never intercepts pointer events.
  // viewBox 0..100 with preserveAspectRatio=none maps SVG user units directly to
  // the same left/top percentages the desk nodes use (officeFracPos), so edges
  // and nodes share one coordinate space with no extra math.
  const edgeSvg = document.createElementNS(SVG_NS, "svg");
  edgeSvg.setAttribute("class", "office-edges");
  edgeSvg.setAttribute("viewBox", "0 0 100 100");
  edgeSvg.setAttribute("preserveAspectRatio", "none");
  edgeSvg.style.position = "absolute";
  edgeSvg.style.inset = "0";
  edgeSvg.style.width = "100%";
  edgeSvg.style.height = "100%";
  edgeSvg.style.pointerEvents = "none";
  shell.appendChild(edgeSvg);

  // Dashed command rug centered under the Lead (agentic) / room center.
  const rug = document.createElement("div");
  rug.className = "rug";
  rug.style.left = "30%";
  rug.style.top = "26%";
  rug.style.width = "40%";
  rug.style.height = "48%";
  shell.appendChild(rug);

  // Packet layer: ABOVE the SVG edges (so dots ride on the lines) but BEFORE the
  // desk host (so nodes paint over the dots). Never intercepts pointer events.
  const packetHost = document.createElement("div");
  packetHost.className = "office-packets";
  shell.appendChild(packetHost);

  const deskHost = document.createElement("div");
  deskHost.className = "office-desks";
  shell.appendChild(deskHost);

  mountEl.appendChild(shell);
  CX.shell = shell;
  CX.edgeSvg = edgeSvg;
  CX.packetHost = packetHost;
  CX.rug = rug;
  CX.deskHost = deskHost;
}

// Dim slate for an inactive link; active links inherit the worker's phase color.
const EDGE_DIM = "rgba(148, 163, 184, .18)";

// Draw the mesh: one SVG <line> per officeEdges() edge, endpoints normalized
// through the SAME officeFracPos the desk nodes use (so lines meet node centers).
// Active links (a real working endpoint) glow in the worker's phase color;
// inactive links are dim. Each ACTIVE edge also gets a traveling DOM packet dot
// (built into CX.edges, animated by the existing step() loop): an edge going
// inactive simply rebuilds without a dot, so its pulse stops cleanly.
function buildEdges(model) {
  if (!CX.edgeSvg) return;
  clear(CX.edgeSvg);
  if (CX.packetHost) clear(CX.packetHost);
  CX.edges = [];
  const { hub, edges } = officeEdges(model);

  // Position + color lookup per desk id (hub uses its synthesized x/y).
  const pos = new Map();
  const color = new Map();
  for (const desk of model.desks) {
    pos.set(desk.id, officeFracPos(model, desk));
    color.set(desk.id, desk.color);
  }
  pos.set(hub.id, officeFracPos(model, { x: hub.x, y: hub.y }));

  let activeIdx = 0;
  for (const edge of edges) {
    // Only draw edges that are currently carrying data (an endpoint is
    // working). The full any-to-any mesh rendered as a static web of dim lines
    // and read as visual noise ("spaghetti"); restricting to active links makes
    // every line meaningful, so the picture shows what is flowing RIGHT NOW.
    if (!edge.active) continue;
    const a = pos.get(edge.from);
    const b = pos.get(edge.to);
    if (!a || !b) continue;
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", String(a.leftPct));
    line.setAttribute("y1", String(a.topPct));
    line.setAttribute("x2", String(b.leftPct));
    line.setAttribute("y2", String(b.topPct));
    line.setAttribute("class", "edge active");
    // The worker endpoint carries the phase tint; for a spoke that is the
    // non-hub end, for a worker-worker link either end is a worker.
    const tint = color.get(edge.to) || color.get(edge.from) || EDGE_DIM;
    line.setAttribute("stroke", tint);
    // non-scaling-stroke keeps width in screen px regardless of the stretched
    // viewBox, so a thin active line reads the same on any office size.
    line.setAttribute("vector-effect", "non-scaling-stroke");
    line.setAttribute("stroke-width", "2");
    line.setAttribute("stroke-opacity", "0.85");
    CX.edgeSvg.appendChild(line);

    // One traveling packet per ACTIVE edge. A round DOM dot positioned by the
    // SAME left/top percentages as the nodes (so it stays perfectly round under
    // the stretched SVG viewBox). Desync each dot so they do not march in lock-
    // step. dir matches edge.dir: forward (hub calling out) or reverse (report).
    if (CX.packetHost) {
      const dot = document.createElement("div");
      dot.className = "office-packet";
      dot.style.color = tint; // currentColor drives the dot fill + glow in CSS
      CX.packetHost.appendChild(dot);
      CX.edges.push({ dot, a, b, dir: edge.dir, offset: (activeIdx * 0.37) % 1 });
      activeIdx += 1;
    }
  }
  pulsePackets(0); // place every dot on its line for frame 0 (no animation step)
}

// One full traversal per PULSE_PERIOD_MS: a calm progress-bar cadence.
const PULSE_PERIOD_MS = 1400;

// Advance the shared packet clock by dt and reposition every active-edge dot
// along its line. Driven by the existing step() loop (no second loop/timer).
// t runs 0..1 from->to for dir>=0 (hub calling out / data-flow forward) and
// 1..0 for dir<0 (terminal worker reporting back). Position uses the SAME
// left/top percentages the desk nodes use, so dots stay round and aligned.
function pulsePackets(dt) {
  if (!CX.edges.length) return;
  if (dt > 0) CX.pulsePhase = (CX.pulsePhase + dt / PULSE_PERIOD_MS) % 1;
  for (const rec of CX.edges) {
    const p = (CX.pulsePhase + rec.offset) % 1;
    const t = rec.dir >= 0 ? p : 1 - p;
    const left = rec.a.leftPct + t * (rec.b.leftPct - rec.a.leftPct);
    const top = rec.a.topPct + t * (rec.b.topPct - rec.a.topPct);
    rec.dot.style.left = `${left}%`;
    rec.dot.style.top = `${top}%`;
  }
}

// Build one desk node: a colored head shape, an always-on role-NAME label, and a
// (hidden until working) activity bubble. The role label answers "what is this
// agent CALLED"; the bubble answers "what is it DOING".
function buildDeskNode(desk) {
  const node = document.createElement("div");
  node.className = "desk lg";
  if (desk.lead) node.classList.add("lead");

  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.hidden = true;
  node.appendChild(bubble);

  const head = document.createElement("div");
  head.className = "head";
  // The ONLY per-desk variation is the fill color (the --ag-* phase/role tint),
  // so every worker reads as one consistent vector character.
  head.style.color = desk.color; // currentColor drives glow/box-shadow
  head.style.background = desk.color;
  node.appendChild(head);

  const label = document.createElement("div");
  label.className = "lbl";
  label.textContent = desk.name || desk.role || desk.id;
  node.appendChild(label);

  return { node, head, label, bubble };
}

// Rebuild all desk nodes (only when the desk id set changes; polls just retune
// the tween targets).
function buildDesks(model) {
  clear(CX.deskHost);
  CX.nodes.clear();
  for (const desk of model.desks) {
    const built = buildDeskNode(desk);
    const pos = officeFracPos(model, desk);
    built.node.style.left = `${pos.leftPct}%`;
    built.node.style.top = `${pos.topPct}%`;
    CX.deskHost.appendChild(built.node);
    CX.nodes.set(desk.id, built);
  }
  // The dashed rug only reads for the agentic ring (central Lead); hide it for
  // the linear stage grid so it does not float over an off-center layout.
  CX.rug.hidden = !model.agentic;
}

// Seed/prune the per-desk tween anim map to match the current desk set.
function ensureAnim(model) {
  const ids = new Set(model.desks.map((d) => d.id));
  for (const id of Array.from(CX.anim.keys())) {
    if (!ids.has(id)) CX.anim.delete(id);
  }
  for (const d of model.desks) {
    if (!CX.anim.has(d.id)) CX.anim.set(d.id, undefined);
  }
}

// Paint one desk from its current tween anim: swap the state class and drive the
// activity bubble. Only a working desk shows its bubble (the live stage text).
function paintDesk(desk) {
  const built = CX.nodes.get(desk.id);
  if (!built) return;
  const anim = CX.anim.get(desk.id);
  const phase = (anim && anim.phase) || "queued";

  built.node.classList.remove("working", "done", "fallback", "error");
  const cls = PHASE_CLASS[phase];
  if (cls) built.node.classList.add(cls);

  if (phase === "working" && desk.activity) {
    built.bubble.textContent = desk.activity; // untrusted -> textContent only
    built.bubble.hidden = false;
  } else {
    built.bubble.hidden = true;
  }
}

// The run is terminal when the model says every worker resolved, the Lead (if
// any) is terminal, AND every tween has settled.
function isOfficeTerminal(model) {
  if (!model) return true;
  const leadDone = model.lead ? isTerminalStatus(model.lead.status) : true;
  const animSettled = CX.anim.size ? allDeskAnimsSettled(CX.anim) : false;
  return model.allResolved && leadDone && animSettled;
}

function step(ts) {
  const model = CX.model;
  const panel = document.getElementById("tmAgentRoster");
  if (!model || !panel || panel.hidden) {
    stopLoop();
    return;
  }
  const dt = CX.lastTs ? Math.min(120, ts - CX.lastTs) : 16;
  CX.lastTs = ts;

  model.desks.forEach((desk, idx) => {
    const next = advanceDeskAnim(CX.anim.get(desk.id), desk.status, dt, {
      delayMs: staggerDelayMs(idx),
    });
    CX.anim.set(desk.id, next);
    paintDesk(desk);
  });

  pulsePackets(dt);

  if (isOfficeTerminal(model)) {
    stopLoop();
    return;
  }
  CX.raf = requestAnimationFrame(step);
}

function startLoop() {
  if (CX.raf) return;
  CX.lastTs = 0;
  CX.raf = requestAnimationFrame(step);
}

function stopLoop() {
  if (CX.raf) cancelAnimationFrame(CX.raf);
  CX.raf = 0;
  CX.lastTs = 0;
}

// Settle every desk in one shot (no animation) and paint a single frame: used
// when a fully-finished run is reattached (navigate-away / reload).
function settleAndPaint(model) {
  model.desks.forEach((desk, idx) => {
    const next = advanceDeskAnim(CX.anim.get(desk.id), desk.status, 9999, {
      delayMs: staggerDelayMs(idx),
    });
    CX.anim.set(desk.id, next);
    paintDesk(desk);
  });
}

// ── Public renderer contract ─────────────────────────────────────────────────

// Mount the office shell. Async so callers can await it; resolves true once
// the shell exists. Idempotent for the same mount element.
export async function officeRenderInit(mountId) {
  const mountEl = document.getElementById(mountId);
  if (!mountEl) return false;
  if (CX.ready && CX.mountEl === mountEl) return true;
  buildShell(mountEl);
  CX.mountEl = mountEl;
  CX.ready = true;
  CX.deskKey = "";
  return true;
}

// Bind a fresh desk model. Rebuilds desk nodes only when the id set changes;
// runs the rAF loop while anything animates, paints one settled frame otherwise.
export function officeRenderSync(model) {
  if (!model || !Array.isArray(model.desks)) return;
  if (!CX.ready) return;

  CX.model = model;
  const key = model.desks.map((d) => d.id).join("|");
  if (key !== CX.deskKey) {
    buildDesks(model);
    CX.deskKey = key;
  }
  ensureAnim(model);

  // Edges rebuild every sync: the desk-id set is stable but each poll can flip
  // an edge's active flag, so the static mesh always reflects the latest status.
  buildEdges(model);

  if (isOfficeTerminal(model)) {
    settleAndPaint(model);
    stopLoop();
  } else {
    startLoop();
  }
}

// Hide / detach the live binding (panel hidden). Stops the loop; keeps the built
// shell + nodes for a cheap re-reveal/resume.
export function officeRenderHide() {
  CX.model = null;
  stopLoop();
}

// True once the office shell is mounted.
export function officeRenderReady() {
  return CX.ready;
}
