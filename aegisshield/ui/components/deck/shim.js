// The Streamlit side of the deck: mounts the deck view, seeds it before a
// run starts, and feeds it each progress record.
//
// Streamlit calls the default export on mount and again each time the data
// sent from Python changes (BidiComponent bundle, the JS effect lists data
// in its dependencies). The deck host is built once per mount and kept in a
// WeakMap keyed by parentElement; every later call only feeds the record to
// deckSync, so the animation loop and the packet flights carry on.
//
// The two import lines are replaced at load time by __init__.py, which
// wraps deck.js and deck_view.js in their own scopes. Record text reaches
// the page only through deck_view.js (textContent and createElement).

import { isDeckProgress } from "./deck.js";
import { deckInit, deckSync, deckHide } from "./deck_view.js";

const FONT_ID = "aegis-deck-fonts";
const FONT_HREF =
  "https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800" +
  "&family=JetBrains+Mono:wght@400;500;600&display=swap";
const TERMINAL = new Set(["complete", "failed", "cancelled"]);
const INSTANCES = new WeakMap();
let current = null; // the instance deck_view.js draws into (it is a module singleton)
const probe = __aegisProbe.probe;

// Geist and JetBrains Mono, loaded once into the document head. Offline the
// stylesheet fails and the deck keeps its fallback stack.
function loadFonts() {
  if (document.getElementById(FONT_ID)) return;
  const link = document.createElement("link");
  link.id = FONT_ID;
  link.rel = "stylesheet";
  link.href = FONT_HREF;
  document.head.append(link);
}

// Every agent waiting, nothing on the board.
function seedRecord(stages) {
  if (!Array.isArray(stages) || !stages.length) return null;
  return {
    office: true,
    stages: stages.map((s) => ({ id: s.id, label: s.label, name: s.name, term: s.term, phase: s.phase, status: "queued" })),
    current: "running",
    deck: { t: 0, threats: [], techniques: {}, tree: { root: null, links: 0, steps: {} }, fixes: {}, scores: {}, tests: {}, live: null },
  };
}

function mount(parentElement) {
  loadFonts();
  const root = document.createElement("div");
  root.className = "aegis-deck-root";
  const host = document.createElement("section");
  host.className = "dk";
  host.hidden = true;
  host.setAttribute("aria-label", "Agents at work");
  const sr = document.createElement("p");
  sr.className = "dk-sr";
  sr.setAttribute("role", "status");
  sr.setAttribute("aria-live", "polite");
  host.append(sr);
  root.append(host);
  parentElement.append(root);
  probe.mounts += 1;
  root.dataset.mounts = String(probe.mounts);
  __aegisProbe.note("mount", { mounts: probe.mounts });
  // hooks: what deck_view.js registered outside the host for this mount
  // (hooks.js), released when the mount leaves the page.
  const inst = { root, host, seq: -1, nonce: null, mode: "", run: null, lastT: -1, hooks: [] };
  current = inst;
  return inst;
}

function init(inst) {
  __aegisHooks.collect(inst.hooks, () => deckInit(inst.host));
  probe.inits += 1;
  inst.root.dataset.inits = String(probe.inits);
  __aegisProbe.note("init", { inits: probe.inits });
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

function deckTime(progress) {
  const t = progress && progress.deck ? Number(progress.deck.t) : NaN;
  return Number.isFinite(t) ? t : -1;
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

  const status = typeof data.status === "string" ? data.status : "running";
  const error = typeof data.error === "string" ? data.error : null;
  const run = data.run === undefined ? null : data.run;
  const progress = data.progress;

  if (!isDeckProgress(progress)) {
    // A deck already showing a run keeps it and takes the status (an early
    // plain frame, or a job that failed before its first stage record).
    if (inst.mode === "run" && run === inst.run && !(status === "idle" || status === "queued")) {
      deckSync(progress, status, error);
      return;
    }
    // Otherwise the preview: "idle" before a run, "queued" once one starts.
    const seed = seedRecord(data.stages);
    if (!seed) return;
    const mode = status === "queued" ? "queued" : "idle";
    if (inst.mode !== mode || run !== inst.run) init(inst);
    deckSync(seed, mode, null);
    inst.mode = mode;
    inst.run = run;
    inst.lastT = -1;
    return;
  }

  // A deck record. A new run starts a fresh feed: a different run id, the
  // idle preview going live, or (with no run id) the record clock going back.
  const t = deckTime(progress);
  const fresh =
    inst.mode === "" ||
    inst.mode === "idle" ||
    run !== inst.run ||
    (run === null && inst.mode === "run" && t >= 0 && t + 1 < inst.lastT);
  if (fresh) init(inst);
  deckSync(progress, status, error);
  inst.mode = "run";
  inst.run = run;
  inst.lastT = t;
  if (TERMINAL.has(status)) __aegisProbe.note("terminal", { status });
}

export default function (component) {
  const { data, parentElement } = component;
  probe.calls = (probe.calls || 0) + 1;
  let inst = INSTANCES.get(parentElement);
  if (!inst || !inst.root.isConnected) {
    inst = mount(parentElement);
    INSTANCES.set(parentElement, inst);
  }
  apply(inst, data && typeof data === "object" ? data : {});
  // Streamlit runs the function returned by the last call when it unmounts,
  // and runs a superseded call's function at once while still mounted. Tear
  // down only when the host has really left the page.
  const mine = inst;
  return () => {
    setTimeout(() => {
      if (mine.root.isConnected) return;
      __aegisHooks.release(mine.hooks);
      if (INSTANCES.get(parentElement) === mine) INSTANCES.delete(parentElement);
      if (current !== mine) return;
      current = null;
      deckHide();
      __aegisProbe.note("unmount");
    }, 0);
  };
}
