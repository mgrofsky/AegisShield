// Tests for the office component's roster.js (the desk and stage models the
// office view draws), under node:test. Run by
// tests/aegisshield/ui/test_office_component.py, which copies roster.js next to this file
// as roster.mjs. Notes on the setup:
// - a small expect() on top of node:assert gives the matchers the file uses
// - the agentic roster has seven specialists (the five analysts plus the
//   Teammate Reviewer and the Rebuttal Analyst), so the desk count is eight,
//   the overall-progress fractions are over seven, and the fixtures list all seven
// - tests for the seven-desk ring layout are at the end

import { describe, it } from "node:test";
import assert from "node:assert/strict";

// The expect() matchers this file uses, on top of node:assert.
function expect(actual) {
  const m = {
    toBe: (v) => assert.ok(Object.is(actual, v), `expected ${JSON.stringify(actual)} to be ${JSON.stringify(v)}`),
    toEqual: (v) => assert.deepStrictEqual(actual, v),
    toBeNull: () => assert.equal(actual, null),
    toHaveLength: (n) => assert.equal(actual.length, n),
    toBeCloseTo: (v, digits = 2) => assert.ok(Math.abs(actual - v) < 10 ** -digits / 2, `${actual} not close to ${v}`),
    toBeGreaterThan: (v) => assert.ok(actual > v, `${actual} > ${v}`),
    toBeGreaterThanOrEqual: (v) => assert.ok(actual >= v, `${actual} >= ${v}`),
    toBeLessThan: (v) => assert.ok(actual < v, `${actual} < ${v}`),
    toBeLessThanOrEqual: (v) => assert.ok(actual <= v, `${actual} <= ${v}`),
  };
  m.not = {
    toBe: (v) => assert.ok(!Object.is(actual, v), `expected ${JSON.stringify(actual)} not to be ${JSON.stringify(v)}`),
  };
  return m;
}
import {
  buildDeskModel,
  buildStageDeskModel,
  isAgenticProgress,
  isOfficeProgress,
  clusterStagesByPhase,
  layoutStageDesks,
  minColumnSpacing,
  rowSpacing,
  DESK_FOOTPRINT_W,
  DESK_FOOTPRINT_H,
  DESK_JITTER_X,
  DESK_JITTER_Y,
  PHASE_ORDER,
  normalizeStatus,
  normalizeLeadStatus,
  statusLabel,
  statusTone,
  DESK_SLOTS,
  ROSTER_STATUSES,
  initDeskAnim,
  advanceDeskAnim,
  allDeskAnimsSettled,
  isTerminalStatus,
  staggerDelayMs,
  MIN_WORKING_MS,
  RAMP_MS,
  workerCapsule,
  WORKER_CAPSULE_COLORS,
  WORKER_CAPSULE_DEFAULT,
  WORKER_CAPSULE_GRAY,
  stageRoleName,
  officeFracPos,
  officeBounds,
  OFFICE_FRAC_PAD,
  officeEdges,
} from "./roster.mjs";

// The canonical backend stage list shape (id, label, phase) the worker emits
// under office:true. Mirrors workflow_service.THREAT_MODEL_STAGES; the 8 backend
// stages plus the 3 addon desks.
const STAGE_DEFS = [
  { id: "serialize", label: "Serializing app profile", phase: "enrichment" },
  { id: "nvd", label: "Querying NVD for CVEs", phase: "enrichment" },
  { id: "otx", label: "Querying OTX pulses", phase: "enrichment" },
  { id: "stride", label: "STRIDE threat generation", phase: "modeling" },
  { id: "mitre_load", label: "Loading MITRE ATT&CK corpus", phase: "modeling" },
  { id: "mitre_map", label: "Mapping threats to ATT&CK", phase: "modeling" },
  { id: "attack_tree", label: "Generating Mermaid attack tree", phase: "modeling" },
  { id: "markdown", label: "Rendering markdown tables", phase: "modeling" },
  { id: "mitigations", label: "Mitigation recommendations", phase: "scoring" },
  { id: "dread", label: "DREAD risk scoring", phase: "scoring" },
  { id: "test_cases", label: "Gherkin test cases", phase: "validation" },
];

function officeProgress(statuses = {}, current = "running") {
  return {
    office: true,
    current,
    stages: STAGE_DEFS.map((s) => ({
      id: s.id,
      label: s.label,
      phase: s.phase,
      status: statuses[s.id] || "queued",
    })),
  };
}

function agenticProgress(overrides = {}) {
  return {
    agentic: true,
    lead: { status: "working", note: "Coordinating the specialist team" },
    agents: [
      { id: "stride", role: "STRIDE Analyst", status: "done", activity: "Mapped checkout data paths", findings: 7 },
      { id: "mitre", role: "MITRE ATT&CK Mapper", status: "working", activity: "Aligning techniques", findings: null },
      { id: "dread", role: "DREAD Risk Scorer", status: "queued", activity: "", findings: null },
      { id: "mitigations", role: "Mitigations Engineer", status: "queued", activity: "", findings: null },
      { id: "test_cases", role: "Validation Engineer", status: "queued", activity: "", findings: null },
      // The two reviewers that follow the five analysts.
      { id: "teammate", role: "Teammate Reviewer", status: "queued", activity: "", findings: null },
      { id: "rebuttal", role: "Rebuttal Analyst", status: "queued", activity: "", findings: null },
    ],
    ...overrides,
  };
}

describe("isAgenticProgress", () => {
  it("is true only for an agentic progress object with an agents array", () => {
    expect(isAgenticProgress(agenticProgress())).toBe(true);
  });

  it("is false for non-agentic / linear progress", () => {
    expect(isAgenticProgress(null)).toBe(false);
    expect(isAgenticProgress(undefined)).toBe(false);
    expect(isAgenticProgress({})).toBe(false);
    expect(isAgenticProgress({ step: 1, total: 1, current: "complete" })).toBe(false);
    expect(isAgenticProgress({ agentic: true })).toBe(false); // no agents array
    expect(isAgenticProgress({ agentic: false, agents: [] })).toBe(false);
  });
});

describe("normalizeStatus", () => {
  it("passes known statuses through", () => {
    for (const s of ROSTER_STATUSES) expect(normalizeStatus(s)).toBe(s);
  });

  it("lowercases and defaults unknown/empty to queued", () => {
    expect(normalizeStatus("WORKING")).toBe("working");
    expect(normalizeStatus("")).toBe("queued");
    expect(normalizeStatus(undefined)).toBe("queued");
    expect(normalizeStatus("bogus")).toBe("queued");
  });
});

describe("statusLabel / statusTone", () => {
  it("maps every status to a human label", () => {
    expect(statusLabel("queued")).toBe("Queued");
    expect(statusLabel("working")).toBe("Working");
    expect(statusLabel("done")).toBe("Done");
    expect(statusLabel("fallback")).toBe("Skipped");
    expect(statusLabel("error")).toBe("Error");
  });

  it("maps fallback and error to distinct tones so they are not dropped", () => {
    expect(statusTone("working")).toBe("accent");
    expect(statusTone("done")).toBe("good");
    expect(statusTone("fallback")).toBe("warn");
    expect(statusTone("error")).toBe("bad");
    expect(statusTone("queued")).toBe("idle");
  });
});

describe("buildDeskModel", () => {
  it("returns all eight desks in fixed layout order regardless of agent order", () => {
    const model = buildDeskModel(agenticProgress());
    expect(model.desks).toHaveLength(8); // Lead + seven specialists
    expect(model.desks.map((d) => d.id)).toEqual(DESK_SLOTS.map((s) => s.id));
    expect(model.lead.id).toBe("lead");
    expect(model.lead.lead).toBe(true);
  });

  it("threads lead note into the lead desk activity", () => {
    const model = buildDeskModel(agenticProgress());
    expect(model.lead.status).toBe("working");
    expect(model.lead.activity).toBe("Coordinating the specialist team");
  });

  it("falls back to an idle activity line when a desk has none", () => {
    const model = buildDeskModel(agenticProgress());
    const dread = model.desks.find((d) => d.id === "dread");
    expect(dread.status).toBe("queued");
    expect(dread.activity).toBe("Waiting on mapped threats");
  });

  it("carries findings counts through and coerces bad values to null", () => {
    const model = buildDeskModel(
      agenticProgress({
        agents: [
          { id: "stride", status: "done", findings: 7 },
          { id: "mitre", status: "done", findings: "oops" },
          { id: "dread", status: "done", findings: 0 },
        ],
      })
    );
    expect(model.desks.find((d) => d.id === "stride").findings).toBe(7);
    expect(model.desks.find((d) => d.id === "mitre").findings).toBeNull();
    expect(model.desks.find((d) => d.id === "dread").findings).toBe(0);
  });

  it("surfaces fallback and error statuses instead of dropping them", () => {
    const model = buildDeskModel(
      agenticProgress({
        agents: [
          { id: "stride", status: "done" },
          { id: "mitre", status: "error", activity: "MITRE mapper unavailable" },
          { id: "dread", status: "fallback", activity: "DREAD skipped" },
          { id: "mitigations", status: "done" },
          { id: "test_cases", status: "done" },
        ],
      })
    );
    const mitre = model.desks.find((d) => d.id === "mitre");
    const dread = model.desks.find((d) => d.id === "dread");
    expect(mitre.status).toBe("error");
    expect(mitre.tone).toBe("bad");
    expect(dread.status).toBe("fallback");
    expect(dread.tone).toBe("warn");
    expect(model.hasError).toBe(true);
  });

  it("computes overall progress from resolved worker desks", () => {
    // 3 of 7 workers terminal (done/fallback/error all resolve).
    const model = buildDeskModel(
      agenticProgress({
        lead: { status: "working", note: "" },
        agents: [
          { id: "stride", status: "done" },
          { id: "mitre", status: "error" },
          { id: "dread", status: "fallback" },
          { id: "mitigations", status: "working" },
          { id: "test_cases", status: "queued" },
          { id: "teammate", status: "queued" },
          { id: "rebuttal", status: "queued" },
        ],
      })
    );
    expect(model.overall).toBeCloseTo(3 / 7, 5);
    expect(model.allResolved).toBe(false);
  });

  it("marks the run resolved only when all workers are terminal", () => {
    const model = buildDeskModel(
      agenticProgress({
        lead: { status: "done", note: "Threat model complete" },
        agents: [
          { id: "stride", status: "done" },
          { id: "mitre", status: "done" },
          { id: "dread", status: "done" },
          { id: "mitigations", status: "done" },
          { id: "test_cases", status: "done" },
          // The two reviewers.
          { id: "teammate", status: "done" },
          { id: "rebuttal", status: "done" },
        ],
      })
    );
    expect(model.allResolved).toBe(true);
    expect(model.overall).toBe(1);
    expect(model.hasError).toBe(false);
  });

  it("defaults a non-agentic progress to a stable queued office (caller gates visibility)", () => {
    const model = buildDeskModel({ step: 1, total: 1, current: "complete" });
    expect(model.agentic).toBe(false);
    expect(model.desks).toHaveLength(8); // eight desks
    expect(model.desks.every((d) => d.status === "queued")).toBe(true);
  });

  it("carries a ring angle through every desk so the renderer can place tokens", () => {
    const model = buildDeskModel(agenticProgress());
    expect(model.lead.ang).toBe(0);
    for (const d of model.desks.filter((x) => !x.lead)) {
      expect(typeof d.ang).toBe("number");
    }
  });
});

describe("normalizeLeadStatus", () => {
  it("maps lifecycle words to working so the Lead reads as active", () => {
    for (const s of ["orchestrating", "synthesizing", "planning", "gathering"]) {
      expect(normalizeLeadStatus(s)).toBe("working");
    }
  });

  it("passes done through and defaults unknown to queued", () => {
    expect(normalizeLeadStatus("done")).toBe("done");
    expect(normalizeLeadStatus("")).toBe("queued");
    expect(normalizeLeadStatus("nonsense")).toBe("queued");
  });
});

describe("advanceDeskAnim: guaranteed-visible working phase", () => {
  it("holds queued while the target is queued (settled, nothing pending)", () => {
    const a = advanceDeskAnim(initDeskAnim(), "queued", 100);
    expect(a.phase).toBe("queued");
    expect(a.settled).toBe(true);
  });

  it("enters working immediately when the target is non-queued", () => {
    const a = advanceDeskAnim(initDeskAnim(), "done", 16);
    expect(a.phase).toBe("working");
    expect(a.settled).toBe(false);
  });

  it("withholds the terminal phase until the minimum working dwell elapses", () => {
    // A backend that jumps straight to done must still animate through working.
    let a = initDeskAnim();
    const dt = 100;
    let elapsed = 0;
    // Step until just before the dwell+ramp threshold.
    const threshold = Math.max(MIN_WORKING_MS, RAMP_MS);
    while (elapsed + dt < threshold) {
      a = advanceDeskAnim(a, "done", dt);
      elapsed += dt;
      expect(a.phase).toBe("working");
      expect(a.settled).toBe(false);
    }
    // A few more steps push past both the dwell and the ramp: now it commits.
    for (let i = 0; i < 5; i++) a = advanceDeskAnim(a, "done", dt);
    expect(a.phase).toBe("done");
    expect(a.prog).toBe(1);
    expect(a.settled).toBe(true);
  });

  it("clamps a still-working target shy of full so the arc keeps moving", () => {
    let a = initDeskAnim();
    for (let i = 0; i < 40; i++) a = advanceDeskAnim(a, "working", 100);
    expect(a.phase).toBe("working");
    expect(a.prog).toBeLessThan(1);
    expect(a.settled).toBe(false);
  });

  it("respects a stagger delay before a desk starts animating", () => {
    const a = advanceDeskAnim(initDeskAnim(), "done", 100, { delayMs: 500 });
    expect(a.phase).toBe("queued");
    expect(a.settled).toBe(false);
  });

  it("stays settled once it has reached a terminal phase", () => {
    let a = initDeskAnim();
    for (let i = 0; i < 60; i++) a = advanceDeskAnim(a, "done", 100);
    expect(a.phase).toBe("done");
    const again = advanceDeskAnim(a, "done", 100);
    expect(again.phase).toBe("done");
    expect(again.settled).toBe(true);
  });

  it("reaches fallback and error terminal phases too, never dropping them", () => {
    for (const target of ["fallback", "error"]) {
      let a = initDeskAnim();
      for (let i = 0; i < 60; i++) a = advanceDeskAnim(a, target, 100);
      expect(a.phase).toBe(target);
      expect(a.settled).toBe(true);
    }
  });
});

describe("allDeskAnimsSettled / staggerDelayMs / isTerminalStatus", () => {
  it("is true only when every anim has settled", () => {
    const m = new Map();
    m.set("a", { settled: true });
    m.set("b", { settled: false });
    expect(allDeskAnimsSettled(m)).toBe(false);
    m.set("b", { settled: true });
    expect(allDeskAnimsSettled(m)).toBe(true);
  });

  it("is false for an empty collection (run not yet started)", () => {
    expect(allDeskAnimsSettled(new Map())).toBe(false);
  });

  it("staggers desk start by index", () => {
    expect(staggerDelayMs(0)).toBe(0);
    expect(staggerDelayMs(2)).toBeGreaterThan(staggerDelayMs(1));
  });

  it("classifies terminal statuses", () => {
    expect(isTerminalStatus("done")).toBe(true);
    expect(isTerminalStatus("fallback")).toBe(true);
    expect(isTerminalStatus("error")).toBe(true);
    expect(isTerminalStatus("working")).toBe(false);
    expect(isTerminalStatus("queued")).toBe(false);
  });
});

// ── linear-path office stream (office:true, desk per pipeline stage) ──

describe("isOfficeProgress", () => {
  it("is true only for an office stream with a stages array", () => {
    expect(isOfficeProgress(officeProgress())).toBe(true);
  });

  it("is false for agentic / linear-step / empty progress", () => {
    expect(isOfficeProgress(null)).toBe(false);
    expect(isOfficeProgress(undefined)).toBe(false);
    expect(isOfficeProgress({})).toBe(false);
    expect(isOfficeProgress({ step: 1, total: 1, current: "complete" })).toBe(false);
    expect(isOfficeProgress({ office: true })).toBe(false); // no stages array
    expect(isOfficeProgress(agenticProgress())).toBe(false); // agentic, not office
  });
});

describe("clusterStagesByPhase", () => {
  it("groups stages into the canonical phase order, never dropping any", () => {
    const clusters = clusterStagesByPhase(officeProgress().stages);
    expect(clusters.map((c) => c.phase)).toEqual(PHASE_ORDER);
    // Every stage lands in exactly one cluster.
    const total = clusters.reduce((n, c) => n + c.members.length, 0);
    expect(total).toBe(STAGE_DEFS.length);
    // Enrichment holds the three enrichment stages, in emitted order.
    const enrichment = clusters.find((c) => c.phase === "enrichment");
    expect(enrichment.members.map((m) => m.stage.id)).toEqual(["serialize", "nvd", "otx"]);
  });

  it("preserves emitted sequence inside a cluster via the seq index", () => {
    const clusters = clusterStagesByPhase(officeProgress().stages);
    const modeling = clusters.find((c) => c.phase === "modeling");
    // seq is the index in the ORIGINAL emitted order, so it is monotonic here.
    const seqs = modeling.members.map((m) => m.seq);
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
  });

  it("places an unknown phase in a trailing cluster rather than dropping it", () => {
    const stages = [
      { id: "x", label: "X", phase: "modeling", status: "queued" },
      { id: "y", label: "Y", phase: "exotic", status: "queued" },
    ];
    const clusters = clusterStagesByPhase(stages);
    expect(clusters.map((c) => c.phase)).toEqual(["modeling", "exotic"]);
    expect(clusters[1].label).toBe("exotic");
  });

  it("returns no clusters for an empty stage list", () => {
    expect(clusterStagesByPhase([])).toEqual([]);
  });
});

describe("layoutStageDesks", () => {
  it("assigns one row per phase cluster, top to bottom", () => {
    const stages = officeProgress().stages;
    const pos = layoutStageDesks(stages);
    // serialize (enrichment) sits in row 0; stride (modeling) in row 1.
    expect(pos.get(0).row).toBe(0);
    expect(pos.get(3).row).toBe(1); // stride is index 3
    // Rows increase y top-to-bottom across phases.
    expect(pos.get(3).y).toBeGreaterThan(pos.get(0).y);
  });

  it("seats stages within a cluster in distinct columns with increasing x", () => {
    const stages = officeProgress().stages;
    const pos = layoutStageDesks(stages);
    // serialize/nvd/otx share the enrichment row in columns 0/1/2.
    expect([pos.get(0).col, pos.get(1).col, pos.get(2).col]).toEqual([0, 1, 2]);
    expect(pos.get(1).x).toBeGreaterThan(pos.get(0).x);
    // Same-row desks share a row band; bounded jitter offsets each y by at most
    // DESK_JITTER_Y, so they are within (not exactly equal to) the band y.
    expect(Math.abs(pos.get(0).y - pos.get(1).y)).toBeLessThanOrEqual(2 * DESK_JITTER_Y);
  });
});

describe("layoutStageDesks organic jitter", () => {
  // Desks are offset off a clean grid by a bounded, deterministic jitter so a
  // bay reads as a lived-in cluster, not a sterile matrix. The offset must stay
  // inside the no-overlap margin proven by the spacing assertions below.
  it("is deterministic across calls (no RNG)", () => {
    const stages = officeProgress().stages;
    const a = [...layoutStageDesks(stages).entries()];
    const b = [...layoutStageDesks(stages).entries()];
    expect(a).toEqual(b);
  });

  it("actually offsets desks off the clean grid centers", () => {
    const stages = officeProgress().stages;
    const jittered = layoutStageDesks(stages);
    // A zero-jitter grid would place serialize/nvd/otx at exact band fractions;
    // at least one desk must differ, proving the jitter is applied.
    const FLOOR = { x: 150, y: 104, w: 940, h: 576 };
    let anyOffset = false;
    const cluster = clusterStagesByPhase(stages)[0]; // enrichment, 3 cols
    cluster.members.forEach((entry, col) => {
      const gridX = FLOOR.x + ((col + 0.5) / cluster.members.length) * FLOOR.w;
      if (Math.abs(jittered.get(entry.seq).x - gridX) > 0.001) anyOffset = true;
    });
    expect(anyOffset).toBe(true);
  });

  it("keeps every desk offset within the bounded jitter envelope", () => {
    const stages = officeProgress().stages;
    const jittered = layoutStageDesks(stages);
    const clusters = clusterStagesByPhase(stages);
    const nRows = clusters.length;
    const FLOOR = { x: 150, y: 104, w: 940, h: 576 };
    clusters.forEach((cluster, row) => {
      const baseY = FLOOR.y + ((row + 0.5) / nRows) * FLOOR.h;
      const m = cluster.members.length;
      cluster.members.forEach((entry, col) => {
        const baseX = FLOOR.x + ((col + 0.5) / m) * FLOOR.w;
        const p = jittered.get(entry.seq);
        expect(Math.abs(p.x - baseX)).toBeLessThanOrEqual(DESK_JITTER_X);
        expect(Math.abs(p.y - baseY)).toBeLessThanOrEqual(DESK_JITTER_Y);
      });
    });
  });
});

describe("desk spacing keeps all 11 stages distinctly countable", () => {
  // The cold-viewer bug was two desks merging so the room read 9, not 11. The
  // layout is overlap-free iff (a) within the densest row, the per-column
  // spacing clears the seated-worker WIDTH, and (b) between phase rows, the
  // vertical spacing clears the seated-worker HEIGHT. These assert both against
  // the same footprints the renderer draws at (0.92 desk scale).
  it("spaces columns wider than a seated worker in every row (no horizontal merge)", () => {
    const stages = officeProgress().stages;
    expect(minColumnSpacing(stages)).toBeGreaterThan(DESK_FOOTPRINT_W);
  });

  it("spaces phase rows taller than a seated worker (no vertical merge)", () => {
    const stages = officeProgress().stages;
    expect(rowSpacing(stages)).toBeGreaterThan(DESK_FOOTPRINT_H);
  });

  it("places no two desks within a worker footprint of each other", () => {
    const stages = officeProgress().stages;
    const pos = [...layoutStageDesks(stages).values()];
    expect(pos).toHaveLength(11); // all 11 stages laid out
    for (let i = 0; i < pos.length; i++) {
      for (let j = i + 1; j < pos.length; j++) {
        const dx = Math.abs(pos[i].x - pos[j].x);
        const dy = Math.abs(pos[i].y - pos[j].y);
        // Two desks merge only if they are close on BOTH axes. A clear gap on
        // either axis (column spacing OR row spacing) keeps them countable.
        const clear = dx >= DESK_FOOTPRINT_W || dy >= DESK_FOOTPRINT_H;
        expect(clear).toBe(true);
      }
    }
  });
});

describe("buildStageDeskModel", () => {
  it("builds one desk per emitted stage, lead-less, with the office flag", () => {
    const model = buildStageDeskModel(officeProgress());
    expect(model.office).toBe(true);
    expect(model.agentic).toBe(false);
    expect(model.lead).toBeNull();
    expect(model.desks).toHaveLength(STAGE_DEFS.length);
    expect(model.desks.map((d) => d.id)).toEqual(STAGE_DEFS.map((s) => s.id));
  });

  it("colors desks by phase and carries a short code + cluster coords", () => {
    const model = buildStageDeskModel(officeProgress());
    const serialize = model.desks.find((d) => d.id === "serialize");
    const stride = model.desks.find((d) => d.id === "stride");
    expect(serialize.phase).toBe("enrichment");
    expect(stride.phase).toBe("modeling");
    expect(serialize.color).not.toBe(stride.color); // distinct phase tone
    expect(serialize.code).toBe("PREP");
    expect(typeof serialize.col).toBe("number");
    expect(typeof serialize.row).toBe("number");
  });

  it("gives every canonical stage a unique, legible nameplate code", () => {
    const model = buildStageDeskModel(officeProgress());
    const byId = (id) => model.desks.find((d) => d.id === id).code;
    // Explicit per-id mapping (no first-3-alnum collisions).
    expect(byId("serialize")).toBe("PREP");
    expect(byId("nvd")).toBe("NVD");
    expect(byId("otx")).toBe("OTX");
    expect(byId("stride")).toBe("STRIDE");
    expect(byId("mitre_load")).toBe("MITRE");
    expect(byId("mitre_map")).toBe("ATT&CK");
    expect(byId("attack_tree")).toBe("TREE");
    expect(byId("markdown")).toBe("DRAFT");
    expect(byId("mitigations")).toBe("MITIG");
    expect(byId("dread")).toBe("DREAD");
    expect(byId("test_cases")).toBe("TESTS");
    // A 3-letter slice would collapse mitre_load / mitre_map / mitigations to "MIT".
    const codes = model.desks.map((d) => d.code);
    expect(new Set(codes).size).toBe(codes.length); // all unique
    expect(codes.filter((c) => c === "MIT")).toHaveLength(0);
  });

  it("summarizes the ordered phase clusters for cluster headings", () => {
    const model = buildStageDeskModel(officeProgress());
    expect(model.phases.map((p) => p.phase)).toEqual(PHASE_ORDER);
    const enrichment = model.phases.find((p) => p.phase === "enrichment");
    expect(enrichment.count).toBe(3);
    expect(enrichment.label).toBe("Enrichment");
  });

  it("computes overall progress + resolution across all stage desks", () => {
    // 8 backend stages done, 3 addon desks still queued -> 8/11 resolved.
    const done = {};
    for (const id of ["serialize", "nvd", "otx", "stride", "mitre_load", "mitre_map", "attack_tree", "markdown"]) {
      done[id] = "done";
    }
    const model = buildStageDeskModel(officeProgress(done));
    expect(model.overall).toBeCloseTo(8 / 11, 5);
    expect(model.allResolved).toBe(false);
    expect(model.hasError).toBe(false);
  });

  it("surfaces fallback and error stage statuses with the right tone", () => {
    const model = buildStageDeskModel(
      officeProgress({ nvd: "fallback", stride: "error" })
    );
    const nvd = model.desks.find((d) => d.id === "nvd");
    const stride = model.desks.find((d) => d.id === "stride");
    expect(nvd.status).toBe("fallback");
    expect(nvd.tone).toBe("warn");
    expect(stride.status).toBe("error");
    expect(stride.tone).toBe("bad");
    expect(model.hasError).toBe(true);
  });

  it("marks the run resolved only when every stage desk is terminal", () => {
    const done = {};
    for (const s of STAGE_DEFS) done[s.id] = "done";
    const model = buildStageDeskModel(officeProgress(done));
    expect(model.allResolved).toBe(true);
    expect(model.overall).toBe(1);
  });

  it("settles when skipped stages read fallback (no NVD/OTX key, add-on not selected)", () => {
    // The job reports skipped lookups and unselected add-ons as "fallback"
    // rather than "done"; the view must still settle.
    const statuses = {};
    for (const s of STAGE_DEFS) statuses[s.id] = "done";
    statuses.nvd = "fallback";
    statuses.otx = "fallback";
    statuses.dread = "fallback";
    const model = buildStageDeskModel(officeProgress(statuses, "complete"));
    expect(model.allResolved).toBe(true);
    expect(model.overall).toBe(1);
    expect(model.hasError).toBe(false);
    expect(model.desks.find((d) => d.id === "nvd").status).toBe("fallback");
  });

  it("returns an empty, non-resolved model for non-office progress", () => {
    const model = buildStageDeskModel({ step: 1, total: 1, current: "complete" });
    expect(model.office).toBe(false);
    expect(model.desks).toHaveLength(0);
    expect(model.allResolved).toBe(false);
    expect(model.overall).toBe(0);
  });
});

describe("N-stage tween drives buildStageDeskModel desks", () => {
  // The tween machine is keyed by desk id, so it scales from the agentic 6 to
  // the linear 8 (or 11 with addons) desks with no change. This locks that a
  // full set of stage desks all pass through working before settling done.
  it("advances every stage desk through working then done, then settles", () => {
    const done = {};
    for (const s of STAGE_DEFS) done[s.id] = "done";
    const model = buildStageDeskModel(officeProgress(done));
    const anim = new Map();
    for (const d of model.desks) anim.set(d.id, initDeskAnim());

    // First tick: every desk (no stagger here) enters working, none terminal.
    for (const d of model.desks) {
      anim.set(d.id, advanceDeskAnim(anim.get(d.id), d.status, 16));
    }
    expect([...anim.values()].every((a) => a.phase === "working")).toBe(true);
    expect(allDeskAnimsSettled(anim)).toBe(false);

    // Drive well past MIN_WORKING_MS + RAMP_MS: all desks commit to done.
    const ticks = Math.ceil((MIN_WORKING_MS + RAMP_MS) / 100) + 5;
    for (let i = 0; i < ticks; i++) {
      for (const d of model.desks) {
        anim.set(d.id, advanceDeskAnim(anim.get(d.id), d.status, 100));
      }
    }
    expect([...anim.values()].every((a) => a.phase === "done")).toBe(true);
    expect(allDeskAnimsSettled(anim)).toBe(true);
  });

  it("staggers stage desk starts by index so a snap-complete run cascades", () => {
    // With a stagger delay, a later desk is still queued on the first tick even
    // when its target is terminal (the cascade the renderer plays per index).
    const model = buildStageDeskModel(officeProgress());
    expect(model.desks.length).toBeGreaterThan(1);
    const a0 = advanceDeskAnim(initDeskAnim(), "done", 100, { delayMs: staggerDelayMs(0) });
    const aN = advanceDeskAnim(initDeskAnim(), "done", 100, { delayMs: staggerDelayMs(5) });
    expect(a0.phase).toBe("working"); // index 0: no delay, starts immediately
    expect(aN.phase).toBe("queued"); // later index: held by its stagger delay
  });
});

// The CSS/DOM renderer positions every desk with left/top
// percentages inside one .office shell, so it normalizes desk x/y against the
// model's OWN bounding box (the agentic ring and the linear floor grid use
// different virtual spaces). Lock the pure normalization here.
describe("officeFracPos: normalize desk x/y into the office shell", () => {
  it("derives the bounding box from the model's desks", () => {
    const model = {
      desks: [
        { id: "a", x: 100, y: 200 },
        { id: "b", x: 300, y: 600 },
      ],
    };
    const b = officeBounds(model);
    expect(b).toEqual({ minX: 100, minY: 200, w: 200, h: 400 });
  });

  it("returns a safe unit box for an empty model (no divide-by-zero)", () => {
    expect(officeBounds({ desks: [] })).toEqual({ minX: 0, minY: 0, w: 1, h: 1 });
    expect(officeBounds(null)).toEqual({ minX: 0, minY: 0, w: 1, h: 1 });
  });

  it("maps the min corner to the inset pad and the max corner to its mirror", () => {
    const model = {
      desks: [
        { id: "a", x: 100, y: 200 },
        { id: "b", x: 300, y: 600 },
      ],
    };
    const pad = OFFICE_FRAC_PAD * 100;
    const min = officeFracPos(model, model.desks[0]);
    const max = officeFracPos(model, model.desks[1]);
    expect(min.leftPct).toBeCloseTo(pad, 5);
    expect(min.topPct).toBeCloseTo(pad, 5);
    expect(max.leftPct).toBeCloseTo(100 - pad, 5);
    expect(max.topPct).toBeCloseTo(100 - pad, 5);
  });

  it("keeps every desk inside the inset band [pad, 100-pad]", () => {
    const model = buildStageDeskModel(officeProgress());
    const pad = OFFICE_FRAC_PAD * 100;
    for (const d of model.desks) {
      const p = officeFracPos(model, d);
      expect(p.leftPct).toBeGreaterThanOrEqual(pad - 1e-6);
      expect(p.leftPct).toBeLessThanOrEqual(100 - pad + 1e-6);
      expect(p.topPct).toBeGreaterThanOrEqual(pad - 1e-6);
      expect(p.topPct).toBeLessThanOrEqual(100 - pad + 1e-6);
    }
  });

  it("works for the agentic ring model too (lead centered, specialists around)", () => {
    const model = buildDeskModel(agenticProgress());
    const pad = OFFICE_FRAC_PAD * 100;
    const lead = officeFracPos(model, model.desks.find((d) => d.lead));
    // The lead sits at the ring center, so it lands mid-shell, not on an edge.
    expect(lead.leftPct).toBeGreaterThan(pad);
    expect(lead.leftPct).toBeLessThan(100 - pad);
  });

  it("collapses a degenerate axis to the near inset edge instead of NaN", () => {
    // All desks share the same y: the y fraction is undefined (0/0) and must
    // resolve to the pad edge, never NaN.
    const model = { desks: [{ id: "a", x: 0, y: 50 }, { id: "b", x: 10, y: 50 }] };
    const p = officeFracPos(model, model.desks[0]);
    const pad = OFFICE_FRAC_PAD * 100;
    expect(Number.isNaN(p.topPct)).toBe(false);
    expect(p.topPct).toBeCloseTo(pad, 5);
  });
});

// The consistent programmatic capsule worker. The office draws ONE character
// recolored per agent. The geometry is identical
// for every desk regardless of index/phase; fill color is the ONLY variation.
describe("workerCapsule: one consistent character, recolored by phase", () => {
  const geomOf = ({ fill, ...geom }) => geom; // strip the only allowed variant

  it("returns IDENTICAL geometry across every phase (no per-index variant table)", () => {
    const phases = PHASE_ORDER;
    const base = geomOf(workerCapsule(phases[0]));
    for (const phase of phases) {
      expect(geomOf(workerCapsule(phase))).toEqual(base);
    }
    // Unknown phase + skipped also keep the same geometry.
    expect(geomOf(workerCapsule("nonsense"))).toEqual(base);
    expect(geomOf(workerCapsule("modeling", { skipped: true }))).toEqual(base);
  });

  it("has a head circle AND a body so it reads as a person, not a pill", () => {
    const c = workerCapsule("enrichment");
    expect(c.headR).toBeGreaterThan(0); // head present
    expect(c.bodyW).toBeGreaterThan(0);
    expect(c.bodyH).toBeGreaterThan(0);
    expect(c.headCy).toBeLessThan(0); // head sits ABOVE the body top
    expect(c.stroke).toBeGreaterThan(0); // white outline width
  });

  it("fill color == the phase color, the ONLY per-desk variation", () => {
    for (const phase of PHASE_ORDER) {
      expect(workerCapsule(phase).fill).toBe(WORKER_CAPSULE_COLORS[phase]);
    }
  });

  it("falls back to the default fill for an unknown phase", () => {
    expect(workerCapsule("").fill).toBe(WORKER_CAPSULE_DEFAULT);
    expect(workerCapsule("bogus").fill).toBe(WORKER_CAPSULE_DEFAULT);
  });

  it("SKIPPED forces the gray fill regardless of phase", () => {
    for (const phase of PHASE_ORDER) {
      expect(workerCapsule(phase, { skipped: true }).fill).toBe(WORKER_CAPSULE_GRAY);
    }
  });
});

// Every desk carries a readable role NAME, and the working desk's activity
// bubble text is the REAL emitted stage label, so a viewer can tell who each
// desk is and what it is doing. Both are locked here so the renderer stays thin.
describe("stageRoleName: a readable, unique name for every pipeline stage", () => {
  const ALL_IDS = STAGE_DEFS.map((s) => s.id);

  it("maps every canonical stage id to a non-empty name", () => {
    for (const id of ALL_IDS) {
      const name = stageRoleName(id);
      expect(typeof name).toBe("string");
      expect(name.trim().length).toBeGreaterThan(0);
    }
  });

  it("gives every stage a DISTINCT name (no collisions)", () => {
    const names = ALL_IDS.map((id) => stageRoleName(id));
    expect(new Set(names).size).toBe(names.length);
  });

  it("never returns the raw stage id as the name (it is a human role)", () => {
    for (const id of ALL_IDS) {
      expect(stageRoleName(id)).not.toBe(id);
    }
  });

  it("falls back to a Title-cased id for an unknown stage, never empty", () => {
    expect(stageRoleName("some_new_stage")).toBe("Some New Stage");
    expect(stageRoleName("")).toBe("Worker");
  });
});

describe("buildStageDeskModel: desks carry name + the real activity label", () => {
  it("puts the stageRoleName on every desk", () => {
    const model = buildStageDeskModel(officeProgress());
    expect(model.desks.length).toBe(STAGE_DEFS.length);
    for (const desk of model.desks) {
      expect(desk.name).toBe(stageRoleName(desk.id));
      expect(desk.name.trim().length).toBeGreaterThan(0);
    }
  });

  it("uses the EMITTED stage label as the activity bubble text (not hardcoded)", () => {
    const model = buildStageDeskModel(officeProgress());
    const byId = new Map(STAGE_DEFS.map((s) => [s.id, s.label]));
    for (const desk of model.desks) {
      expect(desk.activity).toBe(byId.get(desk.id));
    }
  });

  it("prefers a live per-stage detail string over the static label when present", () => {
    const prog = officeProgress({ nvd: "working" }, "nvd");
    const nvd = prog.stages.find((s) => s.id === "nvd");
    nvd.detail = "Checking Python 3.13";
    const model = buildStageDeskModel(prog);
    const nvdDesk = model.desks.find((d) => d.id === "nvd");
    expect(nvdDesk.activity).toBe("Checking Python 3.13");
  });

  it("falls back to the static label when a stage carries no detail (null/absent)", () => {
    const prog = officeProgress({ nvd: "working" }, "nvd");
    prog.stages.find((s) => s.id === "nvd").detail = null;
    const model = buildStageDeskModel(prog);
    const nvdDesk = model.desks.find((d) => d.id === "nvd");
    // null detail -> static emitted label
    expect(nvdDesk.activity).toBe("Querying NVD for CVEs");
    // a stage with no detail key at all also falls back
    const otxDesk = model.desks.find((d) => d.id === "otx");
    expect(otxDesk.activity).toBe("Querying OTX pulses");
  });
});

describe("officeEdges: mesh network (hub spokes + worker-worker handoffs)", () => {
  const pairKey = (e) => [e.from, e.to].sort().join("|");

  it("agentic: hub is the real Lead, with a spoke to every worker", () => {
    const model = buildDeskModel(agenticProgress());
    const { hub, edges } = officeEdges(model);

    expect(hub.id).toBe("lead");
    expect(hub.synthetic).toBe(false);

    const workers = model.desks.filter((d) => !d.lead);
    const spokeTargets = edges.filter((e) => e.from === "lead").map((e) => e.to).sort();
    expect(spokeTargets).toEqual(workers.map((w) => w.id).sort());

    // Domain handoffs present in the agentic ring.
    const wkw = new Set(edges.filter((e) => e.from !== "lead").map(pairKey));
    expect(wkw.has("dread|stride")).toBe(true);
    expect(wkw.has("mitre|stride")).toBe(true);
    expect(wkw.has("dread|mitigations")).toBe(true);
    expect(wkw.has("mitigations|test_cases")).toBe(true);

    // No self-loops, no duplicate edges.
    expect(edges.every((e) => e.from !== e.to)).toBe(true);
    const keys = edges.map((e) => `${e.from}->${e.to}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("linear: a single clean pipeline, ONLY consecutive stage-to-stage edges", () => {
    // The linear stage stream (no real Lead) must NOT draw the hub-and-spoke
    // star + ring fill + domain handoffs (that reads as a tangle).
    // It draws only workers[i] -> workers[i+1], a single flow line.
    const model = buildStageDeskModel(officeProgress());
    expect(model.lead).toBeNull();
    const { hub, edges } = officeEdges(model);

    // Hub is still synthesized at the worker centroid and returned in the shape,
    // but NO spoke edges originate from it.
    expect(hub.id).toBe("orchestrator");
    expect(hub.synthetic).toBe(true);
    const workers = model.desks; // linear model has no lead
    const cx = workers.reduce((s, d) => s + d.x, 0) / workers.length;
    const cy = workers.reduce((s, d) => s + d.y, 0) / workers.length;
    expect(hub.x).toBeCloseTo(cx, 6);
    expect(hub.y).toBeCloseTo(cy, 6);
    expect(edges.some((e) => e.from === "orchestrator" || e.to === "orchestrator")).toBe(false);

    // Exactly the consecutive worker pairs, in order, and nothing else.
    expect(edges).toHaveLength(workers.length - 1);
    const expected = [];
    for (let i = 0; i < workers.length - 1; i++) {
      expected.push(`${workers[i].id}->${workers[i + 1].id}`);
    }
    expect(edges.map((e) => `${e.from}->${e.to}`)).toEqual(expected);

    // No DOMAIN_HANDOFFS-only pairs leaked in (e.g. the nvd|stride handoff is
    // NOT a consecutive pair, so it must be absent).
    const keys = new Set(edges.map(pairKey));
    expect(keys.has("nvd|stride")).toBe(false);
    expect(keys.has("stride|dread")).toBe(false);
    expect(keys.has("mitre|stride")).toBe(false);

    // Pipeline coverage: still no orphan, every stage carries >= 1 link.
    for (const w of workers) {
      expect(edges.some((e) => e.from === w.id || e.to === w.id)).toBe(true);
    }

    // No self-loops, no duplicates.
    expect(edges.every((e) => e.from !== e.to)).toBe(true);
    expect(new Set(edges.map((e) => `${e.from}->${e.to}`)).size).toBe(edges.length);
  });

  it("linear: consecutive edges stay honest to status (active + dir)", () => {
    // stride working, otx done: the otx->stride edge lights active; an edge
    // between two non-working desks stays inactive. dir is always forward (+1).
    const model = buildStageDeskModel(
      officeProgress({ serialize: "done", nvd: "done", otx: "done", stride: "working" })
    );
    const { edges } = officeEdges(model);

    const otxStride = edges.find((e) => e.from === "otx" && e.to === "stride");
    expect(otxStride.active).toBe(true); // stride is working
    expect(otxStride.dir).toBe(1);

    const serializeNvd = edges.find((e) => e.from === "serialize" && e.to === "nvd");
    expect(serializeNvd.active).toBe(false); // both done, neither working

    expect(edges.every((e) => e.dir === 1)).toBe(true);
  });

  it("active flags follow a real working endpoint", () => {
    // mitre working, stride done -> the stride-mitre edge and the mitre spoke active.
    const model = buildDeskModel(agenticProgress());
    const { edges } = officeEdges(model);

    const mitreSpoke = edges.find((e) => e.from === "lead" && e.to === "mitre");
    expect(mitreSpoke.active).toBe(true); // mitre is working

    const dreadMit = edges.find(
      (e) => e.from !== "lead" && pairKey(e) === "dread|mitigations"
    );
    expect(dreadMit.active).toBe(false); // both queued

    // All-queued model -> no worker-worker edge is active.
    const idle = buildStageDeskModel(officeProgress({}));
    const idleEdges = officeEdges(idle).edges.filter((e) => e.from !== "orchestrator");
    expect(idleEdges.some((e) => e.active)).toBe(false);
  });

  it("dir is honest to status: terminal worker reports back (-1), else calls out (+1)", () => {
    const model = buildDeskModel(agenticProgress());
    const { edges } = officeEdges(model);

    // stride is done -> its spoke points back to the hub.
    const strideSpoke = edges.find((e) => e.from === "lead" && e.to === "stride");
    expect(strideSpoke.dir).toBe(-1);

    // dread is queued -> hub still calling out.
    const dreadSpoke = edges.find((e) => e.from === "lead" && e.to === "dread");
    expect(dreadSpoke.dir).toBe(1);
  });

  it("every edge endpoint is the hub or a real desk id", () => {
    const model = buildStageDeskModel(officeProgress());
    const { hub, edges } = officeEdges(model);
    const valid = new Set(model.desks.map((d) => d.id));
    valid.add(hub.id);
    for (const e of edges) {
      expect(valid.has(e.from)).toBe(true);
      expect(valid.has(e.to)).toBe(true);
    }
  });
});

// The ring layout for the seven-specialist roster.
describe("seven specialists on the ring", () => {
  const ids = ["stride", "mitre", "dread", "mitigations", "test_cases", "teammate", "rebuttal"];

  it("seats the Lead plus every specialist the pipeline can plan", () => {
    expect(DESK_SLOTS.map((s) => s.id)).toEqual(["lead", ...ids]);
    const model = buildDeskModel(agenticProgress());
    expect(model.desks.find((d) => d.id === "teammate").role).toBe("Teammate Reviewer");
    expect(model.desks.find((d) => d.id === "rebuttal").role).toBe("Rebuttal Analyst");
    expect(model.desks.find((d) => d.id === "rebuttal").activity).toBe("Waiting on the review");
  });

  it("spaces the seven seats evenly around the Lead", () => {
    const ring = DESK_SLOTS.filter((s) => !s.lead);
    const step = (Math.PI * 2) / ring.length;
    ring.forEach((s, i) => expect(s.ang).toBeCloseTo(-Math.PI / 2 + i * step, 9));
  });

  it("gives every desk its own color", () => {
    const colors = DESK_SLOTS.map((s) => s.color);
    expect(new Set(colors).size).toBe(colors.length);
  });

  it("keeps every pair of desks well apart in the room", () => {
    // In the room's own percentages, the closest pair must stay farther apart
    // than a head plus its label (about 12 percent of a 1024 px wide room).
    const model = buildDeskModel(agenticProgress());
    const pos = model.desks.map((d) => officeFracPos(model, d));
    let min = Infinity;
    for (let i = 0; i < pos.length; i++) for (let j = i + 1; j < pos.length; j++) {
      min = Math.min(min, Math.hypot(pos[i].leftPct - pos[j].leftPct, pos[i].topPct - pos[j].topPct));
    }
    expect(min).toBeGreaterThan(30);
  });

  it("links every specialist to the Lead and chains the reviewers after validation", () => {
    const model = buildDeskModel(agenticProgress());
    const { edges } = officeEdges(model);
    for (const id of ids) expect(edges.some((e) => e.from === "lead" && e.to === id)).toBe(true);
    expect(edges.some((e) => e.from === "test_cases" && e.to === "teammate")).toBe(true);
    expect(edges.some((e) => e.from === "teammate" && e.to === "rebuttal")).toBe(true);
  });
});
