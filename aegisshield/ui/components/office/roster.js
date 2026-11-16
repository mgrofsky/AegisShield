// Pure state-mapping for the live agentic threat-model office view.
//
// The renderer (office_vector.js) is intentionally thin: every decision about
// which desk shows which status / activity / findings is computed here, so
// the node tests can lock the contract without a DOM. The renderer only turns
// this model into elements.
//
// Live data contract (the progress record the agentic pipeline writes):
//   progress = {
//     agentic: true,
//     lead:   { status, note },
//     agents: [ { id, role, status, activity, findings } ],
//   }
// status is one of: queued | working | done | fallback | error.

export const ROSTER_STATUSES = ["queued", "working", "done", "fallback", "error"];

// Top-down floorplan geometry, in the model's virtual coordinates. The Lead
// sits at the center of a command rug; the specialists ring around it. This is
// static scene config, so it lives here rather than in the renderer, which
// stays a thin layer.
export const OFFICE_GEO = {
  cx: 440,
  cy: 300,
  ringR: 190,
  ringSquash: 0.86, // vertical squash so the ring reads as a top-down circle
};

function ringPos(index, count) {
  const ang = -Math.PI / 2 + (index / count) * Math.PI * 2;
  return {
    ang,
    x: OFFICE_GEO.cx + Math.cos(ang) * OFFICE_GEO.ringR,
    y: OFFICE_GEO.cy + Math.sin(ang) * OFFICE_GEO.ringR * OFFICE_GEO.ringSquash,
  };
}

// Canonical desks, in fixed layout order. ids match the pipeline's AGENT_ROLES
// agent_id values (lead is the Threat Model Lead). Lead is centered; the
// specialists are placed on the ring in registration order.
const RING_IDS = ["stride", "mitre", "dread", "mitigations", "test_cases", "teammate", "rebuttal"];
const RING_META = {
  stride: { role: "STRIDE Analyst", color: "#60a5fa" },
  mitre: { role: "MITRE ATT&CK Mapper", color: "#a78bfa" },
  dread: { role: "DREAD Risk Scorer", color: "#f472b6" },
  mitigations: { role: "Mitigations Engineer", color: "#34d399" },
  test_cases: { role: "Validation Engineer", color: "#22d3ee" },
  teammate: { role: "Teammate Reviewer", color: "#fb923c" },
  rebuttal: { role: "Rebuttal Analyst", color: "#a3e635" },
};

export const DESK_SLOTS = [
  { id: "lead", role: "Threat Model Lead", color: "#f5b942", x: OFFICE_GEO.cx, y: OFFICE_GEO.cy, ang: 0, lead: true },
  ...RING_IDS.map((id, i) => {
    const p = ringPos(i, RING_IDS.length);
    return { id, role: RING_META[id].role, color: RING_META[id].color, x: p.x, y: p.y, ang: p.ang };
  }),
];

export const STATUS_LABEL = {
  queued: "Queued",
  working: "Working",
  done: "Done",
  fallback: "Skipped",
  error: "Error",
};

// Per-status visual tone the renderer maps to scene colors. "accent" follows
// the live working color, "good" the done green, "warn" skipped,
// "bad" error, "idle" queued.
export const STATUS_TONE = {
  queued: "idle",
  working: "accent",
  done: "good",
  fallback: "warn",
  error: "bad",
};

// Idle placeholder activity per desk, shown before a status/activity arrives.
const QUEUED_ACTIVITY = {
  lead: "Reviewing scope and assets",
  stride: "Waiting on the run plan",
  mitre: "Waiting on STRIDE threats",
  dread: "Waiting on mapped threats",
  mitigations: "Waiting on scored risks",
  test_cases: "Waiting on mitigations",
  teammate: "Waiting on the finished draft",
  rebuttal: "Waiting on the review",
};

export function normalizeStatus(value) {
  const s = String(value || "").toLowerCase();
  return ROSTER_STATUSES.includes(s) ? s : "queued";
}

// The Lead reports lifecycle words ("orchestrating", "synthesizing",
// "planning") that are not worker statuses. For the office they all mean the
// Lead is actively coordinating, so they map to "working"; "done" passes
// through. Anything else falls back to the generic normalizer.
const LEAD_WORKING = new Set(["orchestrating", "synthesizing", "planning", "gathering"]);
export function normalizeLeadStatus(value) {
  const s = String(value || "").toLowerCase();
  if (LEAD_WORKING.has(s)) return "working";
  return normalizeStatus(value);
}

export function statusLabel(value) {
  const s = normalizeStatus(value);
  return STATUS_LABEL[s] || s;
}

export function statusTone(value) {
  return STATUS_TONE[normalizeStatus(value)] || "idle";
}

function coerceFindings(value) {
  if (value == null) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// True when the progress object is an agentic roster the office should render.
export function isAgenticProgress(progress) {
  return Boolean(
    progress && progress.agentic === true && Array.isArray(progress.agents)
  );
}

// True when the progress object is the linear-path office stream: the backend
// emits one entry per real pipeline stage under `stages`, flagged `office: true`
// (DISTINCT from the agentic `agentic: true`, so the office can render a normal
// Generate without being mistaken for an agentic run).
export function isOfficeProgress(progress) {
  return Boolean(
    progress && progress.office === true && Array.isArray(progress.stages)
  );
}

// Per-phase desk color + display label so the office clusters read at a glance
// (the backend stage list carries a `phase` on every entry). PHASE_ORDER is the
// canonical left-to-right cluster order; an unknown phase sorts last but is never
// dropped (so a new backend phase still lays out and animates).
export const PHASE_ORDER = ["enrichment", "modeling", "scoring", "validation"];
const PHASE_COLOR = {
  enrichment: "#22d3ee",
  modeling: "#60a5fa",
  scoring: "#f472b6",
  validation: "#34d399",
};
const PHASE_LABEL = {
  enrichment: "Enrichment",
  modeling: "Modeling",
  scoring: "Scoring",
  validation: "Validation",
};

function phaseColor(phase) {
  return PHASE_COLOR[phase] || "#60a5fa";
}

// Programmatic worker-capsule spec. ONE
// consistent character, recolored per pipeline phase. The
// geometry is IDENTICAL for every desk (head + body proportions never change);
// the fill color is the ONLY per-desk variation, so every worker reads as the
// same character design. Pure + numeric so the office renderer consumes it and
// the node tests cover it; no DOM here.
export const WORKER_CAPSULE_COLORS = {
  enrichment: 0x62b6ff,
  modeling: 0xa78bfa,
  scoring: 0xf5a524,
  validation: 0x13c08a,
};
export const WORKER_CAPSULE_DEFAULT = 0x8aa0c0;
export const WORKER_CAPSULE_GRAY = 0x8a93a3; // SKIPPED desaturated fill

// Fixed capsule geometry (desk-local units, feet at y=0 going up). Same for all.
const CAPSULE_GEO = Object.freeze({
  bodyW: 30,
  bodyH: 46,
  radius: 12,
  headR: 9,
  headCy: -52, // head center above the body top
  stroke: 3,
});

export function workerCapsule(phase, { skipped = false } = {}) {
  const fill = skipped
    ? WORKER_CAPSULE_GRAY
    : WORKER_CAPSULE_COLORS[phase] != null
      ? WORKER_CAPSULE_COLORS[phase]
      : WORKER_CAPSULE_DEFAULT;
  return {
    bodyW: CAPSULE_GEO.bodyW,
    bodyH: CAPSULE_GEO.bodyH,
    radius: CAPSULE_GEO.radius,
    headR: CAPSULE_GEO.headR,
    headCy: CAPSULE_GEO.headCy,
    stroke: CAPSULE_GEO.stroke,
    fill,
  };
}
function phaseLabel(phase) {
  return PHASE_LABEL[phase] || (phase ? String(phase) : "Pipeline");
}
function phaseRank(phase) {
  const i = PHASE_ORDER.indexOf(phase);
  return i === -1 ? PHASE_ORDER.length : i;
}

// Short, unique, human-readable nameplate label per canonical pipeline stage.
// A first-3-alnum slice would collide (mitre_load / mitre_map / mitigations all
// become "MIT") and read as noise (SER/TES/OTZ), so the desk nameplates carry an
// explicit per-id label. Unknown ids fall back to the cleaned 3-char slice.
const STAGE_CODES = {
  serialize: "PREP",
  nvd: "NVD",
  otx: "OTX",
  stride: "STRIDE",
  mitre_load: "MITRE",
  mitre_map: "ATT&CK",
  attack_tree: "TREE",
  markdown: "DRAFT",
  mitigations: "MITIG",
  dread: "DREAD",
  test_cases: "TESTS",
};
function stageCode(id) {
  const key = String(id || "");
  if (STAGE_CODES[key]) return STAGE_CODES[key];
  return key.replace(/[^a-z0-9]/gi, "").slice(0, 3).toUpperCase();
}

// Short, human role NAME per canonical pipeline stage, shown on every desk's
// nameplate. Distinct from the terse uppercase CODE:
// visitors read these, so they read as a person's job ("CVE Analyst") not a stage
// id ("nvd"). Every canonical stage maps to a unique, non-empty name; an unknown
// id falls back to a Title-cased version of the id (never empty for a real id).
const STAGE_ROLE_NAMES = {
  serialize: "Profiler",
  nvd: "CVE Analyst",
  otx: "Threat Intel",
  stride: "STRIDE Lead",
  mitre_load: "ATT&CK Loader",
  mitre_map: "ATT&CK Mapper",
  attack_tree: "Attack Tree",
  markdown: "Reporter",
  mitigations: "Mitigations",
  dread: "DREAD Scorer",
  test_cases: "Test Author",
};
export function stageRoleName(id) {
  const key = String(id || "");
  if (STAGE_ROLE_NAMES[key]) return STAGE_ROLE_NAMES[key];
  // Fallback: turn "some_stage_id" into "Some Stage Id" so it is still readable.
  const titled = key
    .replace(/[_-]+/g, " ")
    .trim()
    .replace(/\b\w/g, (ch) => ch.toUpperCase());
  return titled || "Worker";
}

// Floor box for the linear office, in the model's virtual coordinates (the
// renderer normalizes them, see officeFracPos). Desks spread across the full
// room; the inset leaves
// the back/left walls, the wall header, the per-row phase labels, and the corner
// props clear of the seated workers.
const FLOOR = { x: 150, y: 104, w: 940, h: 576 };

// Widest seated-worker token footprint in floor px (desk slab + chair frame),
// at the linear-office desk scale used by the renderer (officeToken: dw = 84 *
// scale, chair = botW + 10 ≈ 62 * scale; the desk slab is the wider of the two).
// Exported so the layout can be asserted overlap-free: within any phase row the
// per-column spacing (floor.w / members) must exceed this footprint, or two
// neighbouring workers would visually merge. Uses a 0.92 desk scale.
export const DESK_FOOTPRINT_W = 84 * 0.92;

// Tallest seated-worker token footprint in floor px (monitor top down to the
// chair foot), at the same 0.92 desk scale: the monitor mounts ~66.5px above the
// seat point and the chair foot falls ~56px below it (see officeToken geometry),
// so a worker spans ~122px. Exported so the row layout can be asserted
// non-merging: each phase row gets floor.h / rows of vertical space, which must
// exceed this footprint or a row's chair would blur into the next row's monitor
// (a viewer would then miscount the desks).
export const DESK_FOOTPRINT_H = 122;

// Smallest center-to-center column spacing across all phase rows for a given
// stage list. The renderer seats `members` desks evenly across `floor.w`, so a
// row of m desks spaces them floor.w / m apart; the crowded modeling row (5
// stages) is the tightest. Pure so the node tests can assert that
// this spacing stays clear of DESK_FOOTPRINT_W (no two seated workers merge).
export function minColumnSpacing(stages, floor = FLOOR) {
  const clusters = clusterStagesByPhase(stages);
  let min = Infinity;
  for (const c of clusters) {
    const m = c.members.length || 1;
    min = Math.min(min, floor.w / m);
  }
  return Number.isFinite(min) ? min : 0;
}

// Center-to-center vertical spacing between adjacent phase rows. The renderer
// stacks one row per phase cluster evenly down `floor.h`, so rows sit floor.h /
// rows apart. Pure so the node tests can assert this clears
// DESK_FOOTPRINT_H (no two stacked rows merge vertically).
export function rowSpacing(stages, floor = FLOOR) {
  const rows = clusterStagesByPhase(stages).length || 1;
  return floor.h / rows;
}

// Bounded per-desk jitter so a bay reads as a lived-in cluster of workstations
// instead of a sterile grid. The offset is DETERMINISTIC (seeded by the stage's
// emitted index, no Math.random) so the layout is stable across polls/frames and
// unit-testable. The bounds are deliberately conservative versus the no-overlap
// invariant: the densest row (5 cols) spaces columns 188px apart, so a +/-X
// offset on two neighbours leaves 188 - 2*X = 140px (>> the 77px desk width);
// rows sit 144px apart, so +/-Y leaves 144 - 2*Y = 132px (> the 122px worker
// height). Do NOT widen DESK_JITTER_Y past this margin.
export const DESK_JITTER_X = 24;
export const DESK_JITTER_Y = 6;

// Deterministic value in [-1, 1) from an integer seed (xorshift-style hash), so
// jitter is reproducible per desk without a RNG.
function jitterUnit(seed) {
  let h = Math.imul(seed | 0, 2654435761);
  h = (h ^ (h >>> 15)) >>> 0;
  return (h / 0x100000000) * 2 - 1;
}

// Group stages into phase clusters in canonical order, preserving each stage's
// emitted sequence within its cluster. Returns the ordered cluster list; an
// unknown phase becomes its own trailing cluster rather than being dropped.
export function clusterStagesByPhase(stages) {
  const order = [];
  const byPhase = new Map();
  (stages || []).forEach((s, idx) => {
    const phase = s && s.phase ? String(s.phase) : "";
    if (!byPhase.has(phase)) {
      byPhase.set(phase, []);
      order.push(phase);
    }
    byPhase.get(phase).push({ stage: s, seq: idx });
  });
  order.sort((a, b) => phaseRank(a) - phaseRank(b));
  return order.map((phase) => ({
    phase,
    label: phaseLabel(phase),
    color: phaseColor(phase),
    members: byPhase.get(phase),
  }));
}

// Pure clustered layout: each phase cluster is a horizontal ROW (top to bottom
// in canonical order); the stages within a cluster sit in evenly-spaced COLUMNS
// across that row, like a grid of workstations. Returns a Map keyed by the desk
// index in the ORIGINAL emitted order -> {x, y, col, row}. `row` is the phase
// band index, `col` is the seat index within the band. Kept pure so the node
// tests can lock the placement without a DOM.
export function layoutStageDesks(stages, floor = FLOOR) {
  const clusters = clusterStagesByPhase(stages);
  const nRows = clusters.length || 1;
  const pos = new Map();
  clusters.forEach((cluster, row) => {
    const baseY = floor.y + ((row + 0.5) / nRows) * floor.h;
    const m = cluster.members.length || 1;
    cluster.members.forEach((entry, col) => {
      const baseX = floor.x + ((col + 0.5) / m) * floor.w;
      // Bounded, deterministic jitter so the bay reads organic, not gridded. Two
      // seeds (col-biased x, row-biased y) keep the offset within the no-overlap
      // margin proven in DESK_JITTER_* above.
      const jx = jitterUnit(entry.seq * 73856093 + col) * DESK_JITTER_X;
      const jy = jitterUnit(entry.seq * 19349663 + row * 2) * DESK_JITTER_Y;
      pos.set(entry.seq, { x: baseX + jx, y: baseY + jy, col, row });
    });
  });
  return pos;
}

// Build a desk-per-stage model from the linear office stream. Each emitted stage
// becomes a desk laid out in its phase cluster (no central Lead: the linear
// pipeline has no orchestrator agent). Returns the SAME model shape the renderer
// consumes from buildDeskModel so the renderer stays one code path; `lead`
// is null for the office stream. `phases` carries the ordered cluster summary so
// the renderer can draw cluster headings.
export function buildStageDeskModel(progress) {
  const office = isOfficeProgress(progress);
  const stages = office ? progress.stages : [];
  const layout = layoutStageDesks(stages);

  const desks = stages.map((s, i) => {
    const p = layout.get(i) || { x: FLOOR.x, y: FLOOR.y, col: 0, row: 0 };
    const status = normalizeStatus(s && s.status);
    const label = s && s.label ? String(s.label) : String((s && s.id) || "");
    const phase = s && s.phase ? String(s.phase) : "";
    return {
      id: String((s && s.id) != null ? s.id : i),
      role: label,
      name: stageRoleName(s && s.id),
      code: stageCode(s && s.id),
      color: phaseColor(phase),
      x: p.x,
      y: p.y,
      ang: 0,
      col: p.col,
      row: p.row,
      lead: false,
      phase,
      status,
      tone: statusTone(status),
      activity: s && s.detail ? String(s.detail) : label,
      findings: null,
    };
  });

  const phases = clusterStagesByPhase(stages).map((c) => ({
    phase: c.phase,
    label: c.label,
    color: c.color,
    count: c.members.length,
  }));

  const resolved = desks.filter(
    (d) => d.status === "done" || d.status === "fallback" || d.status === "error"
  ).length;
  const overall = desks.length ? resolved / desks.length : 0;
  const allResolved = desks.length > 0 && resolved === desks.length;
  const hasError = desks.some((d) => d.status === "error");

  return { office, agentic: false, lead: null, desks, phases, overall, allResolved, hasError };
}

// Build the canonical desk model (the Lead plus every ring desk) from a live
// progress object. Always returns every desk in layout order so the office is stable across polls (a desk
// the run didn't plan stays queued rather than popping in/out). The caller is
// expected to gate on `agentic` and hide the panel when false.
export function buildDeskModel(progress) {
  const agentic = isAgenticProgress(progress);
  const byId = new Map();
  if (agentic) {
    for (const agent of progress.agents) {
      if (agent && agent.id != null) byId.set(String(agent.id), agent);
    }
  }
  const lead = (progress && progress.lead) || {};

  const desks = DESK_SLOTS.map((slot) => {
    if (slot.lead) {
      const status = normalizeLeadStatus(lead.status);
      const note = String(lead.note || "");
      return {
        id: slot.id,
        role: slot.role,
        color: slot.color,
        x: slot.x,
        y: slot.y,
        ang: slot.ang,
        lead: true,
        status,
        tone: statusTone(status),
        activity: note || QUEUED_ACTIVITY.lead,
        findings: null,
      };
    }
    const agent = byId.get(slot.id);
    const status = normalizeStatus(agent && agent.status);
    const activity = agent && agent.activity ? String(agent.activity) : "";
    return {
      id: slot.id,
      role: (agent && agent.role) ? String(agent.role) : slot.role,
      color: slot.color,
      x: slot.x,
      y: slot.y,
      ang: slot.ang,
      lead: false,
      status,
      tone: statusTone(status),
      activity: activity || QUEUED_ACTIVITY[slot.id] || "",
      findings: coerceFindings(agent && agent.findings),
    };
  });

  // Overall run progress: fraction of non-lead desks that are terminal
  // (done/fallback/error count as resolved; error still resolves the slot).
  const workers = desks.filter((d) => !d.lead);
  const resolved = workers.filter(
    (d) => d.status === "done" || d.status === "fallback" || d.status === "error"
  ).length;
  const overall = workers.length ? resolved / workers.length : 0;
  const allResolved = workers.length > 0 && resolved === workers.length;
  const hasError = desks.some((d) => d.status === "error");

  return { agentic, lead: desks[0], desks, overall, allResolved, hasError };
}

// ── Fractional desk placement (pure) ───────────────────────────────────────
//
// The two desk-model sources emit x/y in DIFFERENT virtual coordinate spaces:
// the agentic model rings the desks around OFFICE_GEO (center 440,300, ring
// 190), while the linear office grids them across the FLOOR box (150,104 +
// 940x576). The CSS/DOM renderer positions each desk with left/top percentages
// inside one `.office` shell, so it must normalize x/y against the model's OWN
// bounding box rather than a single fixed canvas: that keeps both layouts
// filling the shell. A small inset keeps edge desks (and their labels/bubbles)
// off the shell walls. Pure so the node tests lock the math without a DOM.
export const OFFICE_FRAC_PAD = 0.09;

// Bounding box of every desk's x/y in the model's virtual space. Falls back to
// a unit box when there are no desks so callers never divide by zero.
export function officeBounds(model) {
  const desks = (model && model.desks) || [];
  if (!desks.length) return { minX: 0, minY: 0, w: 1, h: 1 };
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const d of desks) {
    if (d.x < minX) minX = d.x;
    if (d.x > maxX) maxX = d.x;
    if (d.y < minY) minY = d.y;
    if (d.y > maxY) maxY = d.y;
  }
  return { minX, minY, w: maxX - minX || 1, h: maxY - minY || 1 };
}

// Normalize a desk's x/y to {leftPct, topPct} (0..100) inside the model's
// bounding box, inset by `pad` on every side so a desk never sits flush on the
// shell edge. A degenerate axis (all desks share an x or y) collapses to the
// near edge of the inset band rather than NaN.
export function officeFracPos(model, desk, pad = OFFICE_FRAC_PAD) {
  const { minX, minY, w, h } = officeBounds(model);
  const fx = ((desk && desk.x) - minX) / w;
  const fy = ((desk && desk.y) - minY) / h;
  const span = 1 - 2 * pad;
  return {
    leftPct: (pad + (Number.isFinite(fx) ? fx : 0) * span) * 100,
    topPct: (pad + (Number.isFinite(fy) ? fy : 0) * span) * 100,
  };
}

// ── Mesh-network edge model (pure) ─────────────────────────────────────────
//
// The office renders as a MESH NETWORK: an orchestrator hub joined to every
// worker (spokes) PLUS worker-to-worker links so the picture reads as agents
// chattering across a network, not a static star. officeEdges derives that edge
// set from the SAME desk model the renderer already consumes, so the renderer
// only turns edges into lines/pulses. Pure + numeric so the node tests lock it
// without a DOM. Each edge is {from, to, active, dir}.

// Worker-to-worker domain handoffs (the real data-flow between specialists). A
// pair is included ONLY when both endpoints exist in the model, so one table
// serves the agentic ring ("mitre") and the linear stage stream ("mitre_map",
// "nvd") without branching. Listed in data-flow direction.
const DOMAIN_HANDOFFS = [
  ["nvd", "stride"],
  ["stride", "dread"],
  ["stride", "mitre"],
  ["stride", "mitre_map"],
  ["dread", "mitigations"],
  ["mitigations", "test_cases"],
];

// Build the mesh edge set. hub = the real agentic Lead, or a synthesized
// "orchestrator" node at the centroid of the worker desks for the linear stream
// (so the mesh look is identical regardless of stream). edges = hub-to-every-
// worker spokes + worker-to-worker domain handoffs + ring-neighbor fill so no
// worker is connected to the hub alone, deduped (no self-loops, no doubled
// pairs). active = a live "working" endpoint (many light up during parallel
// work); dir = +1 forward (hub calling out / data-flow forward), -1 reverse (a
// terminal worker reporting back). Honest to status, never faked.
export function officeEdges(model) {
  const desks = (model && model.desks) || [];
  const workers = desks.filter((d) => !d.lead);

  // Worker status lookup + data-flow index (desk emission order).
  const statusOf = new Map();
  const indexOf = new Map();
  workers.forEach((d, i) => {
    statusOf.set(d.id, normalizeStatus(d.status));
    indexOf.set(d.id, i);
  });

  let hub;
  if (model && model.lead && model.lead.lead) {
    const L = model.lead;
    hub = { id: L.id, synthetic: false, x: L.x, y: L.y, status: normalizeStatus(L.status) };
  } else {
    let sx = 0;
    let sy = 0;
    for (const w of workers) {
      sx += w.x || 0;
      sy += w.y || 0;
    }
    const n = workers.length || 1;
    const running = !(model && model.allResolved);
    hub = { id: "orchestrator", synthetic: true, x: sx / n, y: sy / n, status: running ? "working" : "done" };
  }

  const isWorking = (id) =>
    id === hub.id ? hub.status === "working" : statusOf.get(id) === "working";
  const isTerminal = (id) =>
    id === hub.id ? isTerminalStatus(hub.status) : isTerminalStatus(statusOf.get(id));

  const edges = [];
  const seen = new Set();
  const addWorkerEdge = (a, b) => {
    if (a === b) return;
    if (!statusOf.has(a) || !statusOf.has(b)) return;
    // Orient earlier-index -> later-index so pulses travel the data-flow way.
    let from = a;
    let to = b;
    if (indexOf.get(from) > indexOf.get(to)) {
      from = b;
      to = a;
    }
    const key = `${from}|${to}`;
    if (seen.has(key)) return;
    seen.add(key);
    edges.push({ from, to, active: isWorking(from) || isWorking(to), dir: 1 });
  };

  // The LINEAR stage stream (no real Lead) is a sequential pipeline: stage i
  // hands to stage i+1. Drawing it as a hub-and-spoke star + ring-fill + domain
  // handoffs would light every crossing line at once and read as a tangle.
  // So for the linear stream we draw ONLY the consecutive stage-to-
  // stage links: a single clean flow line through the desks, no hub spokes, no
  // ring fill. The agentic stream (a real orchestrating Lead) keeps the mesh
  // below, because that one genuinely IS a hub dispatching to specialists.
  const agentic = !!(model && model.lead && model.lead.lead);
  if (!agentic) {
    for (let i = 0; i < workers.length - 1; i++) {
      addWorkerEdge(workers[i].id, workers[i + 1].id);
    }
    return {
      hub: { id: hub.id, synthetic: hub.synthetic, x: hub.x, y: hub.y },
      edges,
    };
  }

  // (a) Spokes: hub -> every worker. dir +1 while the worker is non-terminal
  // (hub calling out), -1 once it lands terminal (worker reporting back).
  for (const w of workers) {
    edges.push({
      from: hub.id,
      to: w.id,
      active: isWorking(hub.id) || isWorking(w.id),
      dir: isTerminal(w.id) ? -1 : 1,
    });
  }

  // (b) Worker-to-worker domain handoffs (only when both endpoints exist).
  for (const [a, b] of DOMAIN_HANDOFFS) addWorkerEdge(a, b);

  // (c) Ring-neighbor fill: connect adjacent workers in data-flow order so every
  // worker carries >=1 worker-worker link (mesh, not a star). addWorkerEdge dedups.
  for (let i = 0; i < workers.length - 1; i++) {
    addWorkerEdge(workers[i].id, workers[i + 1].id);
  }

  return {
    hub: { id: hub.id, synthetic: hub.synthetic, x: hub.x, y: hub.y },
    edges,
  };
}

// ── Display-state tween machine (pure) ─────────────────────────────────────
//
// The polled status is the TARGET. The office must always SHOW a desk passing
// through "working" before it lands "done", even when the pipeline completes a
// section between two polls (otherwise the desk would jump straight to its
// end state). So the renderer keeps a per-desk anim that advances every animation frame toward
// the target, withholding the terminal phase until a minimum working dwell has
// elapsed. This is intentionally DOM-free so the node tests can lock the timing.

// Tunables (ms). MIN_WORKING_MS is the guaranteed-visible "working" floor;
// RAMP_MS is how long the progress arc takes to fill; STAGGER_STEP_MS spaces
// desk starts so a single all-done poll still cascades rather than snapping.
export const MIN_WORKING_MS = 1400;
export const RAMP_MS = 1200;
export const STAGGER_STEP_MS = 360;

const TERMINAL = new Set(["done", "fallback", "error"]);

export function isTerminalStatus(value) {
  return TERMINAL.has(normalizeStatus(value));
}

// Index-based start offset so desks light up in sequence, not all at once.
export function staggerDelayMs(index, step = STAGGER_STEP_MS) {
  return Math.max(0, index | 0) * step;
}

export function initDeskAnim() {
  return { phase: "queued", prog: 0, workingMs: 0, elapsedMs: 0, settled: false };
}

// Advance one desk's display state toward `target` by `dtMs`. Returns a NEW anim
// object (callers keep it across frames). `opts.delayMs` staggers the start;
// `opts.minWorkingMs` / `opts.rampMs` override the dwell/ramp for tests.
export function advanceDeskAnim(prev, target, dtMs, opts = {}) {
  const minWorking = opts.minWorkingMs == null ? MIN_WORKING_MS : opts.minWorkingMs;
  const ramp = opts.rampMs == null ? RAMP_MS : opts.rampMs;
  const delay = opts.delayMs == null ? 0 : opts.delayMs;
  const dt = Number.isFinite(dtMs) && dtMs > 0 ? dtMs : 0;

  const base = prev && typeof prev === "object" ? prev : initDeskAnim();
  const a = {
    phase: base.phase || "queued",
    prog: base.prog || 0,
    workingMs: base.workingMs || 0,
    elapsedMs: (base.elapsedMs || 0) + dt,
    settled: false,
  };
  const tgt = normalizeStatus(target);

  // Target still queued: hold idle. Settled (nothing pending for this desk).
  if (tgt === "queued") {
    a.phase = "queued";
    a.prog = 0;
    a.workingMs = 0;
    a.settled = true;
    return a;
  }

  // Staggered start: not visible yet, hold queued but keep the loop alive.
  if (a.elapsedMs < delay) {
    a.phase = "queued";
    a.prog = 0;
    a.workingMs = 0;
    a.settled = false;
    return a;
  }

  const targetTerminal = TERMINAL.has(tgt);

  // Already landed on a terminal phase: stay (retarget if the status changed).
  if (TERMINAL.has(a.phase)) {
    a.phase = targetTerminal ? tgt : a.phase;
    a.prog = 1;
    a.settled = true;
    return a;
  }

  // Enter working from queued.
  if (a.phase === "queued") {
    a.phase = "working";
    a.workingMs = 0;
    a.prog = 0;
  }

  // In working: accumulate dwell + ramp the arc. Commit to terminal only after
  // the minimum working dwell AND a full ramp, so the working phase is always
  // visible even if the backend already reports done.
  a.workingMs += dt;
  a.prog = Math.min(1, a.prog + (ramp > 0 ? dt / ramp : 1));
  if (targetTerminal && a.workingMs >= minWorking && a.prog >= 1) {
    a.phase = tgt;
    a.prog = 1;
    a.settled = true;
  } else {
    a.settled = false;
    // Target is still "working": keep the arc shy of full so it reads as motion.
    if (!targetTerminal && a.prog >= 1) a.prog = 0.92;
  }
  return a;
}

// True once every anim in the collection has settled (run can stop animating).
export function allDeskAnimsSettled(anims) {
  const list = anims instanceof Map ? Array.from(anims.values()) : Object.values(anims || {});
  return list.length > 0 && list.every((a) => a && a.settled === true);
}
