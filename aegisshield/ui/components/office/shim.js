// The Streamlit side of the office: builds the roster panel and its header,
// starts the vector renderer, and feeds it desk models.
//
// Streamlit calls the default export on mount and again each time the data
// sent from Python changes. The office host is built once per mount and kept
// in a WeakMap keyed by parentElement; every later call only builds a desk
// model from the record and hands it to officeRenderSync, so the animation
// loop and the packets carry on.
//
// The two import lines are replaced at load time by __init__.py, which
// wraps roster.js and office_vector.js in their own scopes. Record text
// reaches the page only through textContent and createElement, here and in
// office_vector.js.

import { buildDeskModel, DESK_SLOTS, isAgenticProgress } from "./roster.js";
import { officeRenderInit, officeRenderSync, officeRenderHide } from "./office_vector.js";

const FONT_ID = "aegis-deck-fonts"; // shared with the deck, so the page loads them once
const FONT_HREF =
  "https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800" +
  "&family=JetBrains+Mono:wght@400;500;600&display=swap";
// office_vector.js step() looks the panel up by this id and stops its loop
// when the panel is missing or hidden.
const PANEL_ID = "tmAgentRoster";
const TERMINAL = new Set(["complete", "failed", "cancelled"]);
const CHIP = { idle: "Idle", queued: "Queued", running: "Live", complete: "Complete", failed: "Failed", cancelled: "Cancelled" };
const TEXT_MAX = 300;
const INSTANCES = new WeakMap();
let current = null; // the instance office_vector.js draws into (it is a module singleton)
let stageSerial = 0;
const probe = __aegisProbe.probe;

function loadFonts() {
  if (document.getElementById(FONT_ID)) return;
  const link = document.createElement("link");
  link.id = FONT_ID;
  link.rel = "stylesheet";
  link.href = FONT_HREF;
  document.head.append(link);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function clip(value) {
  const s = typeof value === "string" ? value : "";
  return s.length > TEXT_MAX ? `${s.slice(0, TEXT_MAX - 3)}...` : s;
}

function mount(parentElement) {
  loadFonts();
  // One office per page: a panel left by an earlier mount gives up the id.
  const stale = document.getElementById(PANEL_ID);
  if (stale) stale.removeAttribute("id");

  const root = el("div", "aegis-office-root");
  const panel = el("section", "agent-roster");
  panel.id = PANEL_ID;
  panel.setAttribute("aria-label", "Threat model agent team");

  const head = el("header", "agent-roster-head");
  const titles = el("div", "ao-titles");
  titles.append(
    el("span", "agent-roster-title", "Security operations room"),
    el("span", "agent-roster-sub", "Agentic threat model \u00b7 live floorplan"),
  );
  const stateBox = el("div", "ao-state");
  const count = el("span", "ao-count", "");
  const meter = el("div", "ao-meter");
  const fill = el("i");
  meter.append(fill);
  const chip = el("span", "ao-chip", CHIP.idle);
  chip.dataset.state = "idle";
  stateBox.append(count, meter, chip);
  head.append(titles, stateBox);

  const error = el("p", "ao-error");
  error.hidden = true;
  const sr = el("p", "ao-sr");
  sr.setAttribute("role", "status");
  sr.setAttribute("aria-live", "polite");

  const frame = el("div", "agent-office");
  const stage = el("div");
  stageSerial += 1;
  stage.id = `aegis-office-stage-${stageSerial}`;
  stage.setAttribute("role", "img");
  stage.setAttribute("aria-label", "Live top-down floorplan of the threat model agent team at work");
  frame.append(stage);

  panel.append(head, error, sr, frame);
  root.append(panel);
  parentElement.append(root);

  probe.mounts += 1;
  root.dataset.mounts = String(probe.mounts);
  __aegisProbe.note("mount", { mounts: probe.mounts });
  const inst = {
    root, panel, stage, count, fill, chip, error, sr,
    seq: -1, nonce: null, mode: "", run: null, ready: false, pending: null, model: null, srText: "",
  };
  current = inst;
  // officeRenderInit is async; nothing is synced until it has resolved
  // (officeRenderSync returns early before then and would drop the record).
  officeRenderInit(stage.id).then((ok) => {
    if (!ok) return;
    inst.ready = true;
    probe.inits += 1;
    root.dataset.inits = String(probe.inits);
    __aegisProbe.note("init", { inits: probe.inits });
    if (inst.pending && current === inst) {
      const data = inst.pending;
      inst.pending = null;
      render(inst, data);
    }
  });
  return inst;
}

// Every specialist waiting and the Lead idle: the preview before a run.
function previewModel() {
  return buildDeskModel({ agentic: true, lead: { status: "queued", note: "" }, agents: [] });
}

// The record as the office should show it.
// - A specialist the Lead left out of its plan is missing from the record
//   (the pipeline lists planned sections only). roster.js's model then
//   keeps it queued, so the run never reads as resolved and the loop never
//   stops; here it reads as skipped.
// - A failed or cancelled job leaves agents queued or working; they read as
//   error or skipped so the room settles instead of animating forever.
function shapeProgress(progress, status) {
  const agents = progress.agents.filter((a) => a && typeof a === "object");
  const lead = progress.lead && typeof progress.lead === "object" ? { ...progress.lead } : {};
  const ids = new Set(agents.map((a) => String(a.id)));
  const shaped = agents.map((a) => ({ ...a }));
  if (agents.length) {
    for (const slot of DESK_SLOTS) {
      if (slot.lead || ids.has(slot.id)) continue;
      shaped.push({ id: slot.id, role: slot.role, status: "fallback", activity: "Not in the Lead's plan", findings: null });
    }
  }
  if (status === "failed" || status === "cancelled") {
    const stopped = status === "failed" ? "error" : "fallback";
    for (const a of shaped) {
      if (a.status === "working") a.status = stopped;
      else if (a.status !== "done" && a.status !== "fallback" && a.status !== "error") a.status = "fallback";
    }
    lead.status = stopped;
  }
  return { ...progress, lead, agents: shaped };
}

function paintHeader(inst, status, error, model, live) {
  const workers = model ? model.desks.filter((d) => !d.lead) : [];
  const tally = (s) => workers.filter((d) => d.status === s).length;
  const done = tally("done");
  const skipped = tally("fallback");
  const failed = tally("error");
  const resolved = done + skipped + failed;
  const parts = [`${done} of ${workers.length} specialists done`];
  if (failed) parts.push(`${failed} failed`);
  if (skipped) parts.push(`${skipped} skipped`);
  inst.count.textContent = workers.length ? parts.join(", ") : "";
  inst.fill.style.width = `${Math.round((workers.length ? resolved / workers.length : 0) * 100)}%`;
  inst.chip.textContent = CHIP[status] || CHIP.running;
  inst.chip.dataset.state = status;
  inst.error.hidden = !error;
  inst.error.textContent = error || "";
  const text = live || CHIP[status] || "";
  if (text !== inst.srText) {
    inst.srText = text;
    inst.sr.textContent = text;
  }
}

// Clear the desks and their tweens, so the next model starts from queued.
function resetDesks() {
  officeRenderSync({ desks: [] });
}

function render(inst, data) {
  const status = typeof data.status === "string" && CHIP[data.status] ? data.status : "running";
  const error = typeof data.error === "string" && data.error ? clip(data.error) : null;
  const run = data.run === undefined ? null : data.run;
  const progress = data.progress;

  if (!isAgenticProgress(progress)) {
    // A room already showing this run keeps it and takes the status (a job
    // that failed before its first roster record, or a plain frame).
    if (inst.mode === "run" && run === inst.run && status !== "idle" && status !== "queued") {
      paintHeader(inst, status, error, inst.model, null);
      return;
    }
    // The preview is a still frame: the desks are built, then the loop the
    // sync asked for is cancelled, so an idle page draws nothing.
    const mode = status === "queued" ? "queued" : "idle";
    if (inst.mode === "run" || inst.mode === "") resetDesks();
    const model = previewModel();
    officeRenderSync(model);
    officeRenderHide();
    inst.mode = mode;
    inst.run = run;
    inst.model = model;
    // A job that is running or already over before its first roster record
    // keeps the preview but says so.
    paintHeader(inst, status === "idle" || status === "queued" ? mode : status, error, model, null);
    return;
  }

  // A roster record. A different run id starts a fresh room on this mount.
  const fresh = inst.mode !== "run" || run !== inst.run;
  if (fresh) {
    resetDesks();
    __aegisProbe.note("run", { fresh: true });
  }
  const model = buildDeskModel(shapeProgress(progress, status));
  officeRenderSync(model);
  inst.mode = "run";
  inst.run = run;
  inst.model = model;
  paintHeader(inst, status, error, model, clip(progress.current));
  if (TERMINAL.has(status)) __aegisProbe.note("terminal", { status });
}

// Bring the live view to the top of the main area once per run, on the
// run's first "running" record (the page has laid out by then). Streamlit
// scrolls [data-testid="stMain"], not the window. Never again for that run:
// the visitor's own scrolling is left alone.
const SCROLL_GAP = 64; // Streamlit's header is 60px; a little air below it
let scrolledRun = null;
function bringIntoView(root, data) {
  if (data.run == null || data.status !== "running" || data.run === scrolledRun) return;
  scrolledRun = data.run;
  requestAnimationFrame(() => {
    const main = root.closest('[data-testid="stMain"]');
    if (!main || !root.isConnected) return;
    const mainTop = main.getBoundingClientRect().top;
    // When the main area already starts below the header, a small gap will do.
    const gap = Math.max(8, SCROLL_GAP - mainTop);
    const top = Math.max(0, main.scrollTop + root.getBoundingClientRect().top - mainTop - gap);
    if (Math.abs(top - main.scrollTop) >= 1) main.scrollTo({ top, behavior: "auto" });
    __aegisProbe.note("scroll", { top: Math.round(top) });
  });
}

function apply(inst, data) {
  // A superseded call can arrive after a newer one: keep the newest only.
  // The counter restarts when Python's nonce changes (a new session, or
  // cleared session state, reaching this same mount).
  const seq = Number(data.seq);
  if (Number.isFinite(seq)) {
    if (data.nonce !== inst.nonce) {
      inst.nonce = data.nonce;
      inst.seq = -1;
    }
    if (seq <= inst.seq) return;
    inst.seq = seq;
  }
  bringIntoView(inst.root, data);
  if (__aegisProbe.looping()) probe.updatesInLoop += 1;
  probe.updates += 1;
  inst.root.dataset.updates = String(probe.updates);
  if (!inst.ready) {
    inst.pending = data;
    return;
  }
  render(inst, data);
}

export default function (component) {
  const { data, parentElement } = component;
  probe.calls = (probe.calls || 0) + 1;
  let inst = INSTANCES.get(parentElement);
  if (!inst || !inst.root.isConnected) {
    inst = mount(parentElement);
    INSTANCES.set(parentElement, inst);
  }
  current = inst;
  apply(inst, data && typeof data === "object" ? data : {});
  // Streamlit runs the function returned by the last call when it unmounts,
  // and runs a superseded call's function at once while still mounted. Tear
  // down only when the host has really left the page.
  const mine = inst;
  return () => {
    setTimeout(() => {
      if (mine.root.isConnected) return;
      if (INSTANCES.get(parentElement) === mine) INSTANCES.delete(parentElement);
      if (current !== mine) return;
      current = null;
      officeRenderHide();
      __aegisProbe.note("unmount");
    }, 0);
  };
}
