// The "agents at work" deck: thin DOM and one canvas over deck.js.
//
// deck.js decides what is shown; this file draws it, for a live run.
//
// CSP-clean: every node is made with createElement / createElementNS and
// every string from the progress record reaches the page through textContent
// or a text node. Styles are set through the CSSOM only.

import { createDeckFeed, fmtClock, MAX_PIPS, nvdLink } from "./deck.js";

const NS = "http://www.w3.org/2000/svg";
const KEY_LIST = "aegisDeckStepList";
const KEY_REDUCE = "aegisDeckReduceMotion";
const STATUS_EVERY_MS = 5000;
const TIGHT_COLUMN_PX = 168;

const PHASES = {
  gather: { name: "Gather", color: "#22d3ee", text: "#67e8f9" },
  model: { name: "Model", color: "#3b82f6", text: "#8ab4ff" },
  score: { name: "Score", color: "#f472b6", text: "#f9a8d4" },
  check: { name: "Check", color: "#a78bfa", text: "#c4b5fd" },
};

const EMBLEMS = {
  serialize: "M6 1v6M3.5 4.5 6 7l2.5-2.5M1.5 8v2.5h9V8",
  nvd: "M8.2 5a3.2 3.2 0 1 1-6.4 0 3.2 3.2 0 0 1 6.4 0zM7.4 7.4l3.1 3.1",
  otx: "M6 9.6v.1M3.6 7.3a3.4 3.4 0 0 1 4.8 0M1.6 5.2a6.2 6.2 0 0 1 8.8 0",
  stride: "M2 10l.9-3.1 5.6-5.6 2.2 2.2-5.6 5.6zM7.3 2.5l2.2 2.2",
  mitre_load: "M6 1.4l4.6 2.3L6 6 1.4 3.7zM1.4 6.2 6 8.5l4.6-2.3M1.4 8.6 6 10.9l4.6-2.3",
  mitre_map: "M9.4 6a3.4 3.4 0 1 1-6.8 0 3.4 3.4 0 0 1 6.8 0zM6 .8v2M6 9.2v2M.8 6h2M9.2 6h2",
  attack_tree: "M6 1.2v3.3M6 4.5 2.2 8M6 4.5 9.8 8M6 4.5v3.6M2.2 8v2.4M6 8.1v2.3M9.8 8v2.4",
  markdown: "M1.5 2h9v8h-9zM1.5 5h9M5 2v8",
  mitigations: "M6 1.1l4 1.5v3c0 2.4-1.6 4.3-4 5.2-2.4-.9-4-2.8-4-5.2v-3zM4.2 6l1.3 1.3L8 4.8",
  dread: "M1.4 9a4.6 4.6 0 0 1 9.2 0M6 9l2.4-3.4",
  test_cases: "M1.4 3.1l1 1 1.8-2M6 3h4.6M1.4 8.1l1 1 1.8-2M6 8h4.6",
};
const EMBLEM_OTHER = "M6 1.6v8.8M1.6 6h8.8";

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function sv(tag, attrs) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function setText(e, s) {
  if (e.textContent !== s) e.textContent = s;
}
function rgba(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
}
function clamp(x, a, b) {
  return x < a ? a : x > b ? b : x;
}
function stored(key) {
  try {
    const v = window.localStorage.getItem(key);
    return v === "1" ? true : v === "0" ? false : null;
  } catch (_e) {
    return null;
  }
}
function store(key, on) {
  try {
    window.localStorage.setItem(key, on ? "1" : "0");
  } catch (_e) {
    /* storage is off: the choice lasts for this page only */
  }
}

// ── the robot ───────────────────────────────────────────────────────────

function makeSprite(emblem) {
  const s = sv("svg", { viewBox: "0 0 48 56", class: "dk-sprite", "aria-hidden": "true", focusable: "false" });
  const thr = sv("ellipse", { cx: 24, cy: 53, rx: 8, ry: 1.8, class: "dk-sp-thr" });
  const body = sv("g", { class: "dk-sp-body" });
  const antl = sv("line", { x1: 24, y1: 9, x2: 24, y2: 4.5, class: "dk-sp-antl" });
  const ant = sv("circle", { cx: 24, cy: 3.4, r: 2.3, class: "dk-sp-ant" });
  const armL = sv("rect", { x: 5.5, y: 31, width: 4.5, height: 11, rx: 2.2, class: "dk-sp-arm" });
  const armR = sv("rect", { x: 38, y: 31, width: 4.5, height: 11, rx: 2.2, class: "dk-sp-arm" });
  const eyes = sv("g", {});
  eyes.append(
    sv("path", { d: "M17.2 17.5a1.9 1.9 0 1 0 3.8 0 1.9 1.9 0 0 0-3.8 0zM27 17.5a1.9 1.9 0 1 0 3.8 0 1.9 1.9 0 0 0-3.8 0z", class: "dk-eye dk-eye-open" }),
    sv("path", { d: "M17 17.6h4M27 17.6h4", class: "dk-eye dk-eye-flat" }),
    sv("path", { d: "M17 18.8q2-3.2 4 0M27 18.8q2-3.2 4 0", class: "dk-eye dk-eye-happy" }),
    sv("path", { d: "M17.3 15.9l3.4 3.4M20.7 15.9l-3.4 3.4M27.3 15.9l3.4 3.4M30.7 15.9l-3.4 3.4", class: "dk-eye dk-eye-x" })
  );
  const emb = sv("path", { d: (typeof emblem === "string" && Object.hasOwn(EMBLEMS, emblem) && EMBLEMS[emblem]) || EMBLEM_OTHER, class: "dk-sp-emb", transform: "translate(18 33)" });
  const badge = sv("g", { class: "dk-sp-badge" });
  badge.append(
    sv("circle", { cx: 40, cy: 9, r: 6.6 }),
    sv("path", { d: "M36.9 9.2l2.2 2.2 3.9-4.4", class: "dk-b-check" }),
    sv("path", { d: "M36.6 6.4 39.2 9l-2.6 2.6M40.6 6.4 43.2 9l-2.6 2.6", class: "dk-b-skip" }),
    sv("path", { d: "M37.4 6.4l5.2 5.2M42.6 6.4l-5.2 5.2", class: "dk-b-x" })
  );
  body.append(
    antl, ant, armL, armR,
    sv("rect", { x: 21, y: 26.5, width: 6, height: 4, class: "dk-sp-neck" }),
    sv("rect", { x: 9, y: 8, width: 30, height: 19, rx: 7, class: "dk-sp-head" }),
    sv("rect", { x: 13, y: 12.5, width: 22, height: 10, rx: 5, class: "dk-sp-visor" }),
    eyes,
    sv("rect", { x: 12, y: 30, width: 24, height: 18, rx: 6, class: "dk-sp-torso" }),
    emb, badge
  );
  s.append(thr, body);
  return { svg: s, body, armL, armR, eyes, ant, thr };
}

/** ``c`` is the animation clock in seconds, or null for the rest pose. */
function poseSprite(sp, c) {
  if (c == null) {
    sp.body.removeAttribute("transform");
    sp.eyes.removeAttribute("transform");
    sp.armL.removeAttribute("transform");
    sp.armR.removeAttribute("transform");
    sp.ant.removeAttribute("opacity");
    sp.thr.setAttribute("rx", 8);
    return;
  }
  sp.body.setAttribute("transform", "translate(0 " + (Math.sin(c * 3.1) * 1.3).toFixed(2) + ")");
  sp.eyes.setAttribute("transform", "translate(" + (Math.sin(c * 2.2) * 2).toFixed(2) + " 0)");
  sp.armL.setAttribute("transform", "rotate(" + (24 + Math.sin(c * 13) * 16).toFixed(1) + " 7.75 32)");
  sp.armR.setAttribute("transform", "rotate(" + (-24 + Math.sin(c * 13 + 1.7) * 16).toFixed(1) + " 40.25 32)");
  sp.ant.setAttribute("opacity", Math.sin(c * 6) > 0 ? 1 : 0.4);
  sp.thr.setAttribute("rx", (8 + Math.sin(c * 8) * 1.3).toFixed(2));
}

// ── module state: one deck per page ─────────────────────────────────────

let host = null;
let ui = null; // the built DOM
let feed = null;
let vm = null;
let raf = 0;
let lastTs = 0;
let animClock = 0;
let reduce = false;
let listMode = false;
let geo = null;
let geoDirty = true;
let rows = []; // one per stage: { id, row, head, sp, sb, sd, reason, state, li, st, why, seg, fill, tech, tl, lookup }
let stageSig = "";
let colSig = "";
let colEls = new Map(); // column key -> { col, head, wrap }
let cardEls = new Map(); // threat id -> card nodes
let logVersion = -1;
let logShown = 0;
let logEnd = "";
let logSigs = []; // one per row in the log, in order
let activeCard = ""; // the card the arrow keys are on
let detailId = ""; // the card shown in the detail area ("lk:nvd" or "lk:otx" for a lookup agent), or ""
let detailBy = ""; // what opened it: "key", "hover", or "click"
let detailOwner = null; // the element that opened it: the board, or a lookup agent
let detailSig = "";
let quietLookup = false; // the next focus on a lookup agent does not reopen the detail
let announced = new Set(); // lookup results the status line has said
let quietFocus = false; // the next focus on the board does not reopen the detail
let tallySig = "";
let statusKey = "";
let statusAt = 0;
let lastFocus = "";
let userScrollAt = -Infinity;
let summarySig = "";

function fxOn() {
  return !reduce && !listMode;
}
function visible() {
  return !!host && !host.hidden && host.getClientRects().length > 0 && !document.hidden;
}

// ── build once ──────────────────────────────────────────────────────────

function build() {
  const app = el("div", "dk-app");

  const hud = el("header", "dk-hud");
  const top = el("div", "dk-hud-top");
  const brand = el("div", "dk-brand");
  const mark = el("span", "dk-brand-mark");
  mark.setAttribute("aria-hidden", "true");
  const names = el("div");
  names.append(el("h3", "dk-title", "Risk assessment: agents at work"), el("p", "dk-subtitle", "Each agent is one step of this run. The board fills as they work."));
  brand.append(mark, names);
  const controls = el("div", "dk-controls");
  controls.setAttribute("role", "group");
  controls.setAttribute("aria-label", "View options");
  const btnList = el("button", "dk-btn", "Step list");
  btnList.type = "button";
  const btnReduce = el("button", "dk-btn", "Reduce motion");
  btnReduce.type = "button";
  controls.append(btnList, btnReduce);
  top.append(brand, controls);
  const track = el("div", "dk-hud-track");
  const clock = el("div", "dk-clock");
  const clockNow = el("span", "dk-clock-now", "00:00");
  clock.append(clockNow, el("small", null, "elapsed"));
  const timeline = el("div", "dk-timeline");
  timeline.setAttribute("role", "progressbar");
  timeline.setAttribute("aria-label", "Run progress");
  timeline.setAttribute("aria-valuemin", "0");
  timeline.setAttribute("aria-valuemax", "100");
  timeline.setAttribute("aria-valuenow", "0");
  const step = el("div", "dk-step");
  track.append(clock, timeline, step);
  hud.append(top, track);

  const main = el("div", "dk-main");
  const cv = el("canvas", "dk-flow");
  cv.setAttribute("aria-hidden", "true");
  const rail = el("section", "dk-panel dk-rail");
  rail.setAttribute("aria-label", "Agents");
  const stepPanel = el("section", "dk-panel dk-steplist");
  stepPanel.setAttribute("aria-label", "Step list");
  stepPanel.hidden = true;
  const sl = el("ol", "dk-sl");
  const slNow = el("div");
  stepPanel.append(el("h4", "dk-ptitle", "Steps"), sl, slNow);
  const summary = el("div", "dk-summary");
  summary.hidden = true;

  const board = el("section", "dk-panel dk-board");
  board.setAttribute("aria-label", "Threat board");
  const bar = el("div", "dk-board-bar");
  const rootChip = el("span", "dk-root-chip");
  const boardCount = el("span", "dk-board-count");
  bar.append(el("h4", "dk-ptitle", "Threat board"), rootChip, boardCount);
  const cols = el("div", "dk-cols");
  // scrolls when a category holds more than three threats: reachable by keyboard
  cols.tabIndex = 0;
  cols.setAttribute("role", "group");
  cols.setAttribute("aria-label", "Threat cards by category");
  board.append(bar, cols);

  const strip = el("div", "dk-strip");
  const logPanel = el("section", "dk-panel");
  logPanel.setAttribute("aria-label", "Event log");
  const log = el("div", "dk-log");
  log.tabIndex = 0;
  log.setAttribute("role", "log");
  log.setAttribute("aria-label", "Event log");
  log.setAttribute("aria-live", "off");
  logPanel.append(el("h4", "dk-ptitle", "Event log"), log);
  const tallyPanel = el("section", "dk-panel");
  tallyPanel.setAttribute("aria-label", "Tally");
  const tally = el("div", "dk-tally");
  tallyPanel.append(el("h4", "dk-ptitle", "Tally"), tally);
  const legendPanel = el("section", "dk-panel");
  legendPanel.setAttribute("aria-label", "Legend");
  const legend = el("div", "dk-legend-row");
  const legendNote = el("p", "dk-legend-note");
  const phases = el("div", "dk-phases");
  legendPanel.append(el("h4", "dk-ptitle", "Agent states"), legend, legendNote, phases);
  strip.append(logPanel, tallyPanel, legendPanel);

  // one detail area for reading a threat in full. It sits in the
  // bottom strip's grid cell, over the log, tally, and legend while it is
  // open: it never covers the working agent's panel and never moves the layout.
  const detail = el("section", "dk-panel dk-detail");
  detail.id = "dkThreatDetail";
  detail.setAttribute("aria-label", "Threat details");
  detail.hidden = true;
  const detailTitle = el("h4", "dk-detail-title");
  const detailNote = el("p", "dk-detail-note");
  detailNote.hidden = true;
  const detailRows = el("dl", "dk-detail-rows");
  detail.append(detailTitle, detailNote, detailRows);
  cols.setAttribute("aria-describedby", "dkThreatHelp");
  const help = el("p", "dk-sr", "Use the arrow keys to move between threat cards and read each one in full. Escape closes it.");
  help.id = "dkThreatHelp";
  board.append(help);
  const lookupHelp = el("p", "dk-sr", "Opens the full list of what this lookup found. Tab moves into the list, Escape closes it.");
  lookupHelp.id = "dkLookupHelp";
  // not in the rail: the rail is rebuilt when the stages change
  board.append(lookupHelp);

  // next in the tab order after the board while it is open, so a long text
  // can be scrolled from the keyboard
  detail.tabIndex = 0;
  main.append(cv, rail, stepPanel, board, detail, strip);
  app.append(hud, main);

  // legend: the five states on the shared body, then the phase colors
  [["waiting", "Waiting"], ["working", "Working"], ["done", "Done"], ["skipped", "Skipped"], ["failed", "Failed"]].forEach((p) => {
    const it = el("div", "dk-legend-item");
    const sp = makeSprite("stride");
    it.style.setProperty("--c", PHASES.model.color);
    sp.svg.setAttribute("data-state", p[0]);
    if (p[0] === "working") poseSprite(sp, 0.9);
    it.append(sp.svg, el("span", null, p[1]));
    legend.append(it);
  });
  Object.keys(PHASES).forEach((k) => {
    const s = el("span");
    const i = el("i");
    i.style.setProperty("--c", PHASES[k].color);
    s.append(i, document.createTextNode(PHASES[k].name));
    phases.append(s);
  });

  // work panel: one node, moved to wherever the working agent is
  const work = {
    box: el("div", "dk-work"), head: el("div", "dk-work-head"), sub: el("div", "dk-work-sub"), body: el("p", "dk-work-body"),
    text: document.createTextNode(""), cursor: el("span", "dk-work-cursor"), rows: el("ul", "dk-work-rows"), sig: "", at: null,
    line: el("span", "dk-work-line"),
  };
  // the text and its cursor sit in one line box, anchored to the bottom of the
  // body: when a short deck cannot show the whole tail, the oldest words are
  // the ones cut, never the newest
  work.line.append(work.text, work.cursor);
  work.body.append(work.line);
  work.box.append(work.head, work.sub, work.body, work.rows);

  cols.addEventListener("keydown", onBoardKey);
  cols.addEventListener("focus", () => {
    if (activeCard && !quietFocus) openDetail(activeCard, "key");
    quietFocus = false;
  });
  cols.addEventListener("blur", (e) => {
    if (detailBy === "key" && e.relatedTarget !== detail) closeDetail();
  });
  // focus leaving the detail closes it, unless it moves to what opened it or
  // stays inside (a lookup's list has links)
  detail.addEventListener("focusout", (e) => {
    const to = e.relatedTarget;
    if (detailBy === "key" && !(to && (detail.contains(to) || to === detailOwner))) closeDetail();
  });
  detail.addEventListener("keydown", onDetailKey);
  for (const box of [rail, sl]) {
    box.addEventListener("focusin", (e) => {
      const owner = lookupOwner(e.target);
      if (!owner || e.target !== owner) return;
      if (quietLookup) quietLookup = false;
      else openLookup(owner, "key");
    });
    box.addEventListener("focusout", (e) => {
      const owner = lookupOwner(e.target);
      const to = e.relatedTarget;
      if (owner && detailOwner === owner && detailBy === "key" && !(to && (detail.contains(to) || to === owner))) closeDetail();
    });
    box.addEventListener("keydown", onLookupKey);
    box.addEventListener("click", (e) => {
      const owner = lookupOwner(e.target);
      if (!owner) return;
      if (detailOwner === owner && detailBy === "click") closeDetail();
      else openLookup(owner, "click");
    });
    box.addEventListener("mouseover", (e) => {
      const owner = lookupOwner(e.target);
      // a list or card pinned by a click, or opened from the keyboard, stays
      if (owner && detailBy !== "click" && detailBy !== "key" && detailOwner !== owner) openLookup(owner, "hover");
    });
    box.addEventListener("mouseout", (e) => {
      const owner = lookupOwner(e.target);
      if (owner && detailBy === "hover" && detailOwner === owner && !owner.contains(e.relatedTarget)) closeDetail();
    });
  }
  // a list opened by a click stays until it is clicked again, Escape, or a click elsewhere
  app.addEventListener("click", (e) => {
    if (detailBy === "click" && isLookupDetail() && !detail.contains(e.target) && !(detailOwner && detailOwner.contains(e.target))) closeDetail();
  });
  cols.addEventListener("mouseover", (e) => {
    const card = e.target.closest ? e.target.closest(".dk-card") : null;
    if (card && !card.classList.contains("dk-incoming")) openDetail(card.id.slice(8), detailBy === "click" ? "click" : "hover");
  });
  cols.addEventListener("mouseleave", () => {
    if (detailBy === "hover" || detailBy === "click") closeDetail();
  });
  cols.addEventListener("click", (e) => {
    const card = e.target.closest ? e.target.closest(".dk-card") : null;
    if (!card || card.classList.contains("dk-incoming")) return;
    setActive(card.id.slice(8));
    openDetail(card.id.slice(8), "click");
  });
  app.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && detailId) {
      const inside = detail.contains(document.activeElement);
      const owner = detailOwner;
      const lookup = isLookupDetail();
      closeDetail();
      if (inside) {
        // back to what opened it, with the detail closed
        if (lookup && owner) {
          quietLookup = true;
          owner.focus();
        } else {
          quietFocus = true;
          cols.focus();
        }
      }
      e.stopPropagation();
    }
  });

  btnList.addEventListener("click", () => setModes(reduce, !listMode, "list"));
  // Reduce motion changes motion only: the reader's own Step list choice stays as it is
  btnReduce.addEventListener("click", () => setModes(!reduce, listMode, "reduce"));
  const noteScroll = () => {
    userScrollAt = performance.now();
  };
  cols.addEventListener("wheel", noteScroll, { passive: true });
  cols.addEventListener("pointerdown", noteScroll, { passive: true });
  cols.addEventListener("scroll", () => {
    geoDirty = true;
    if (!raf) redraw();
  }, { passive: true });

  return {
    app, main, cv, ctx: cv.getContext("2d"), rail, stepPanel, sl, slNow, summary, board, rootChip, boardCount, cols,
    log, tally, legendNote, clockNow, timeline, step, btnList, btnReduce, work, tallyRows: null,
    detail, detailTitle, detailNote, detailRows,
  };
}

/** ``remember`` names the one choice the reader just made ("reduce" or
    "list"), which is saved; anything else saves nothing. */
function setModes(nextReduce, nextList, remember) {
  reduce = nextReduce;
  listMode = nextList;
  geoDirty = true;
  if (remember === "reduce") store(KEY_REDUCE, reduce);
  if (remember === "list") store(KEY_LIST, listMode);
  if (!ui) return;
  ui.btnList.setAttribute("aria-pressed", String(listMode));
  ui.btnReduce.setAttribute("aria-pressed", String(reduce));
  host.classList.toggle("dk-reduce", reduce);
  ui.rail.hidden = listMode;
  ui.stepPanel.hidden = !listMode;
  rows.forEach((r) => poseSprite(r.sp, r.state === "working" ? 0.9 : null));
  redraw();
  start();
}

// ── stages: rail rows, step list rows, timeline segments ────────────────

function buildStages(stages) {
  ui.rail.textContent = "";
  ui.sl.textContent = "";
  ui.timeline.textContent = "";
  ui.work.at = null;
  rows = stages.map((s, k) => {
    const ph = PHASES[s.phase] || PHASES.model;
    const row = el("div", "dk-agent");
    row.style.setProperty("--c", ph.color);
    row.style.setProperty("--ct", ph.text);
    const head = el("div", "dk-agent-head");
    const wrap = el("div", "dk-sprite-wrap");
    const sp = makeSprite(s.id);
    wrap.append(sp.svg);
    const plate = el("div", "dk-plate");
    const tech = el("div", "dk-ptech", s.term);
    plate.append(el("div", "dk-pname", s.name), tech);
    const status = el("div", "dk-pstatus");
    const sb = el("b");
    const sd = el("span");
    status.append(sb, sd);
    const reason = el("div", "dk-preason");
    reason.hidden = true;
    head.append(wrap, plate, status, reason);
    row.append(head);
    ui.rail.append(row);

    const li = el("li");
    const nm = el("div", "dk-nm");
    nm.append(el("b", null, s.name));
    // a list item keeps its role: a lookup's button is the name inside it
    const st = el("div", "dk-st");
    const why = el("div", "dk-why");
    why.hidden = true;
    const tl = el("div", "dk-tech", s.term);
    li.append(el("div", "dk-n", k + 1 + "."), nm, st, tl, why);
    ui.sl.append(li);

    const seg = el("div", "dk-tl-seg");
    seg.style.setProperty("--c", ph.color);
    const fill = el("div", "dk-tl-fill");
    seg.append(fill);
    ui.timeline.append(seg);
    return { id: s.id, phase: ph, row, head, sp, sb, sd, reason, state: "", li, nm, st, why, seg, fill, tech, tl, lookup: false };
  });
  geoDirty = true;
}

function renderStages(view) {
  const sig = view.stages.map((s) => s.id + "\u0001" + s.name + "\u0001" + s.term + "\u0001" + s.phase).join("\u0002");
  if (sig !== stageSig) {
    stageSig = sig;
    buildStages(view.stages);
  }
  view.stages.forEach((st, k) => {
    const r = rows[k];
    if (r.state !== st.state) {
      r.state = st.state;
      geoDirty = true;
      r.row.setAttribute("data-state", st.state);
      r.sp.svg.setAttribute("data-state", st.state);
      poseSprite(r.sp, st.state === "working" ? 0.9 : null);
      r.li.setAttribute("data-state", st.state);
      r.seg.setAttribute("data-state", st.state);
    }
    setText(r.sb, st.label);
    setText(r.sd, st.dur);
    if (r.reason.textContent !== st.reason) {
      r.reason.textContent = st.reason;
      r.reason.hidden = !st.reason;
      r.why.textContent = st.reason ? "Reason: " + st.reason : "";
      r.why.hidden = !st.reason;
      geoDirty = true;
    }
    setText(r.st, st.label + (st.dur ? ", " + st.dur : ""));
    // a lookup agent's result stays on its row, after its term
    const termText = st.note ? (st.noteTerm || st.term) + " · " + st.note : st.term;
    if (r.tech.textContent !== termText) {
      r.tech.textContent = termText;
      r.tl.textContent = termText;
      // with a result on it the line holds to one row (an ellipsis for the
      // worst cases; the full sentence is in the list and the status line)
      r.tech.classList.toggle("dk-noted", !!st.note);
      r.tl.classList.toggle("dk-noted", !!st.note);
      geoDirty = true;
    }
    setLookupOwner(r, view.lookupStages.includes(st.id));
    const busy = st.state === "working" && st.frac === null;
    r.seg.classList.toggle("dk-busy", busy);
    r.fill.style.width = busy ? "" : ((st.frac || 0) * 100).toFixed(2) + "%";
    r.seg.title = st.name + ": " + st.label.toLowerCase() + (st.dur ? ", " + st.dur : "");
  });
}

// ── reading what a lookup found ─────────────────────────────────────────

/** Make a lookup agent's row (and its step list row) open its list, or not. */
function setLookupOwner(r, on) {
  if (r.lookup === on) return;
  r.lookup = on;
  for (const node of [r.head, r.nm]) {
    if (on) {
      node.setAttribute("data-lookup", r.id);
      node.tabIndex = 0;
      node.setAttribute("role", "button");
      node.setAttribute("aria-controls", "dkThreatDetail");
      node.setAttribute("aria-expanded", "false");
      node.setAttribute("aria-describedby", "dkLookupHelp");
    } else {
      for (const a of ["data-lookup", "tabindex", "role", "aria-controls", "aria-expanded", "aria-describedby"]) node.removeAttribute(a);
    }
  }
}

function lookupOwner(target) {
  const node = target && target.closest ? target.closest("[data-lookup]") : null;
  return node && host && host.contains(node) ? node : null;
}

function isLookupDetail() {
  return detailId.startsWith("lk:");
}

function openLookup(owner, by) {
  if (!feed || !owner) return;
  const d = feed.lookupDetail(owner.getAttribute("data-lookup"));
  if (!d) return;
  if (detailOwner && detailOwner !== owner) detailOwner.setAttribute("aria-expanded", "false");
  detailId = d.id;
  detailBy = by;
  detailOwner = owner;
  owner.setAttribute("aria-expanded", "true");
  fillDetail(d);
  ui.detail.hidden = false;
}

/** The element after ``node`` in the deck's tab order, outside the detail. */
function nextTabStop(node) {
  const all = [...host.querySelectorAll("button, a[href], [tabindex]")].filter(
    (e) => e.tabIndex >= 0 && !ui.detail.contains(e) && e.getClientRects().length > 0,
  );
  const i = all.indexOf(node);
  return i >= 0 ? all[i + 1] || null : null;
}

function onLookupKey(e) {
  const owner = lookupOwner(e.target);
  if (!owner || e.target !== owner) return;
  if (e.key === "Enter" || e.key === " ") {
    const open = detailOwner === owner && !ui.detail.hidden;
    // focus has just opened it: Enter or Space moves into the list rather
    // than closing it (Escape closes); a list pinned by a click toggles
    if (open && detailBy === "key") ui.detail.focus();
    else if (open) closeDetail();
    else openLookup(owner, "key");
    e.preventDefault();
  } else if (e.key === "Tab" && !e.shiftKey && detailOwner === owner && !ui.detail.hidden) {
    // into the list, so its links can be reached
    e.preventDefault();
    ui.detail.focus();
  }
}

function onDetailKey(e) {
  if (e.key !== "Tab" || !isLookupDetail() || !detailOwner) return;
  const stops = [ui.detail, ...ui.detail.querySelectorAll("a[href]")];
  const i = stops.indexOf(document.activeElement);
  if (e.shiftKey && i === 0) {
    e.preventDefault();
    quietLookup = true;
    detailOwner.focus();
  } else if (!e.shiftKey && i === stops.length - 1) {
    // out of the list: on to whatever follows the agent that opened it
    const next = nextTabStop(detailOwner);
    if (next) {
      e.preventDefault();
      next.focus();
    }
  }
}

function renderWork(view) {
  const w = view.work;
  const work = ui.work;
  const hostNode = !w ? null : listMode ? ui.slNow : rows[view.cur].row;
  let moved = false;
  if (work.at !== hostNode) {
    moved = true;
    work.at = hostNode;
    geoDirty = true;
    if (hostNode) hostNode.append(work.box);
    else work.box.remove();
  }
  if (!w) return;
  const ph = rows[view.cur].phase;
  work.box.style.setProperty("--c", ph.color);
  work.box.style.setProperty("--ct", ph.text);
  setText(work.head, w.head);
  setText(work.sub, w.sub);
  work.sub.hidden = !w.sub;
  let changed = false;
  if (work.text.nodeValue !== w.body) {
    work.text.nodeValue = w.body;
    changed = true;
  }
  work.body.hidden = !w.body && !w.cursor;
  work.body.classList.toggle("dk-oneline", w.oneLine === true);
  work.cursor.hidden = !w.cursor;
  const sig = w.rows.map((r) => r.k + "|" + r.v).join("\n");
  if (sig !== work.sig) {
    work.sig = sig;
    work.rows.textContent = "";
    w.rows.forEach((r) => {
      const li = el("li", (r.dim ? "dk-dim" : "") + (r.spare ? " dk-spare" : "") + (r.keep ? " dk-keep" : ""));
      if (r.k) li.append(el("b", null, r.k), document.createTextNode(" "));
      li.append(document.createTextNode(r.v));
      work.rows.append(li);
    });
    changed = true;
  }
  // never clip: the history rows are secondary, so the oldest go first when the live text needs the room
  const cramped = () =>
    work.box.scrollHeight > work.box.clientHeight + 1 || (!work.body.hidden && work.line.offsetHeight > work.body.clientHeight + 1);
  // a row marked spare goes before any other; a row marked keep never goes
  if (changed || moved) {
    while (cramped()) {
      const drop = work.rows.querySelector(".dk-spare") || work.rows.querySelector("li:not(.dk-keep)");
      if (!drop) break;
      drop.remove();
    }
    clampKeptRow(cramped);
  }
  if (changed || moved) fitWorkLines();
}

// A kept row that still does not fit (a very long product name) shows the
// whole lines that fit and ends in an ellipsis, never a half line.
function clampKeptRow(cramped) {
  const keep = ui.work.rows.querySelector(".dk-keep");
  if (!keep) return;
  keep.classList.remove("dk-clamped");
  keep.style.removeProperty("-webkit-line-clamp");
  if (!cramped()) return;
  const lh = parseFloat(getComputedStyle(keep).lineHeight);
  if (!(lh > 0)) return;
  const box = ui.work.box;
  const room = box.getBoundingClientRect().bottom - parseFloat(getComputedStyle(box).paddingBottom) - keep.getBoundingClientRect().top;
  keep.classList.add("dk-clamped");
  keep.style.setProperty("-webkit-line-clamp", String(Math.max(1, Math.floor((room + 1) / lh))));
}

// When the live text is longer than its room, show a whole number of its
// newest lines: the body is cut on a line boundary, so no half line peeks
// out under the title.
function fitWorkLines() {
  const { body, line } = ui.work;
  body.style.removeProperty("max-height");
  if (body.hidden || line.offsetHeight <= body.clientHeight + 1) return;
  const lh = parseFloat(getComputedStyle(body).lineHeight);
  if (!(lh > 0)) return;
  const lines = Math.max(1, Math.floor((body.clientHeight + 1) / lh));
  body.style.setProperty("max-height", (lines * lh).toFixed(2) + "px");
}

function renderSummary(view) {
  const s = view.summary;
  const sig = s ? [s.tone, s.title, s.text, s.error, s.top ? s.top.id + s.top.text : ""].join("\u0001") : "";
  const home = listMode ? ui.stepPanel : ui.rail;
  if (ui.summary.parentNode !== home) {
    home.append(ui.summary);
    geoDirty = true;
  }
  if (sig === summarySig) return;
  summarySig = sig;
  geoDirty = true;
  ui.summary.hidden = !s;
  ui.summary.textContent = "";
  if (!s) return;
  ui.summary.setAttribute("data-tone", s.tone);
  ui.summary.append(el("strong", null, s.title));
  if (s.error) ui.summary.append(document.createTextNode(s.error));
  if (s.text) ui.summary.append(document.createTextNode(s.text + " "));
  if (s.top) ui.summary.append(document.createTextNode("Highest risk score: "), el("b", null, s.top.id + ", " + s.top.text), document.createTextNode("."));
}

// ── board ───────────────────────────────────────────────────────────────

function makeCard(id) {
  const card = el("article", "dk-card");
  card.id = "dk-card-" + id;
  const top = el("div", "dk-card-top");
  const score = el("span", "dk-score");
  top.append(el("span", "dk-cid", id), score);
  const title = el("p", "dk-ctitle");
  const chip = el("div", "dk-chip");
  const marks = el("div", "dk-marks");
  const mp = el("span", "dk-mark dk-path");
  const mf = el("span", "dk-mark dk-fix");
  const mt = el("span", "dk-mark dk-test");
  marks.append(mp, mf, mt);
  const ghost = el("div", "dk-ghost");
  card.append(top, title, chip, marks, ghost);
  return { el: card, score, title, chip, chipSig: "", mp, mf, mt, ghost, col: "" };
}

function setMark(node, m) {
  node.hidden = !m;
  if (!m) return;
  node.classList.toggle("dk-on", m.on);
  setText(node, m.text);
}

// ── reading a threat: keyboard, hover, click ────────────────────────────

/** The landed cards, column by column, as the board shows them. */
function cardGrid() {
  if (!vm) return [];
  return vm.board.columns.map((c) => c.cards.filter((card) => card.landed).map((card) => card.id)).filter((c) => c.length);
}

function setActive(id) {
  if (activeCard === id) return;
  const old = activeCard ? cardEls.get(activeCard) : null;
  if (old) {
    old.el.classList.remove("dk-active");
    old.el.removeAttribute("aria-describedby");
  }
  activeCard = id;
  const n = id ? cardEls.get(id) : null;
  if (n) {
    n.el.classList.add("dk-active");
    n.el.setAttribute("aria-describedby", "dkThreatDetail");
    ui.cols.setAttribute("aria-activedescendant", n.el.id);
    keepCardInView(n);
  } else ui.cols.removeAttribute("aria-activedescendant");
}

function keepCardInView(n) {
  const box = ui.cols.getBoundingClientRect();
  const r = n.el.getBoundingClientRect();
  const head = colEls.get(n.col);
  const headH = (head ? head.head.getBoundingClientRect().height : 24) + 8;
  if (r.top < box.top + headH) ui.cols.scrollTop += r.top - box.top - headH;
  else if (r.bottom > box.bottom) ui.cols.scrollTop += r.bottom - box.bottom + 4;
  if (r.left < box.left) ui.cols.scrollLeft += r.left - box.left - 4;
  else if (r.right > box.right) ui.cols.scrollLeft += r.right - box.right + 4;
  userScrollAt = performance.now();
}

function onBoardKey(e) {
  const keys = { ArrowUp: [0, -1], ArrowDown: [0, 1], ArrowLeft: [-1, 0], ArrowRight: [1, 0], Home: null, End: null };
  if (e.key === "Escape") {
    if (detailId) {
      closeDetail();
      e.preventDefault();
      e.stopPropagation();
    }
    return;
  }
  if (e.key === "Enter" || e.key === " ") {
    if (activeCard) {
      if (detailId) closeDetail();
      else openDetail(activeCard, "key");
      e.preventDefault();
    }
    return;
  }
  if (!Object.hasOwn(keys, e.key)) return;
  const grid = cardGrid();
  if (!grid.length) return;
  e.preventDefault();
  let ci = grid.findIndex((c) => c.includes(activeCard));
  let ri = ci >= 0 ? grid[ci].indexOf(activeCard) : -1;
  if (ci < 0) {
    ci = 0;
    ri = 0;
  } else if (e.key === "Home") {
    ri = 0;
  } else if (e.key === "End") {
    ri = grid[ci].length - 1;
  } else {
    const [dx, dy] = keys[e.key];
    if (dx) {
      ci = Math.max(0, Math.min(grid.length - 1, ci + dx));
      ri = Math.min(ri, grid[ci].length - 1);
    } else ri = Math.max(0, Math.min(grid[ci].length - 1, ri + dy));
  }
  setActive(grid[ci][ri]);
  openDetail(activeCard, "key");
}

function openDetail(id, by) {
  if (!feed || !id) return;
  const d = feed.detail(id);
  if (!d) return;
  if (detailOwner && detailOwner !== ui.cols) detailOwner.setAttribute("aria-expanded", "false");
  detailId = id;
  detailBy = by;
  detailOwner = ui.cols;
  fillDetail(d);
  ui.detail.hidden = false;
}

function closeDetail() {
  if (detailOwner && detailOwner !== ui.cols) detailOwner.setAttribute("aria-expanded", "false");
  detailId = "";
  detailBy = "";
  detailOwner = null;
  detailSig = "";
  ui.detail.hidden = true;
}

const linkIds = new WeakMap(); // each link in the detail list -> its CVE id

function fillDetail(d) {
  const linkSig = (r) => (r.links ? r.links.map((l) => l.id + "\u0003" + l.text).join("\u0003") + "\u0001" + (r.more || "") : "");
  const sig = d.title + "\u0002" + (d.note || "") + "\u0002" + d.rows.map((r) => r.k + "\u0001" + r.v + "\u0001" + linkSig(r)).join("\u0002");
  if (sig === detailSig) return;
  // keep keyboard focus on the same link (by its id) when the list
  // refreshes, or on the list box when that link is gone. Focus moves to the
  // box before the rows are emptied, so it never leaves the list (which
  // would close it) or falls to the page.
  const active = document.activeElement;
  const inside = ui.detail.contains(active);
  const focused = inside && linkIds.has(active) ? linkIds.get(active) : null;
  const scroll = ui.detail.scrollTop;
  if (inside && active !== ui.detail) ui.detail.focus({ preventScroll: true });
  detailSig = sig;
  ui.detail.setAttribute("aria-label", isLookupDetail() ? "Lookup details" : "Threat details");
  ui.detailTitle.textContent = d.title;
  ui.detailNote.textContent = d.note || "";
  ui.detailNote.hidden = !d.note;
  ui.detailRows.textContent = "";
  let refocus = null;
  for (const r of d.rows) {
    const dd = el("dd", null, r.v);
    const links = (r.links || []).filter((l) => nvdLink(l.id));
    if (links.length) {
      const list = el("span", "dk-detail-ids");
      links.forEach((l, i) => {
        if (i) list.append(document.createTextNode(", "));
        const a = el("a", "dk-detail-link", l.text);
        // built here again from an id that passed the pattern, never taken as given
        a.href = nvdLink(l.id);
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        linkIds.set(a, l.id);
        if (focused !== null && l.id === focused) refocus = a;
        list.append(a);
      });
      if (r.more) list.append(document.createTextNode(" " + r.more));
      dd.append(list);
    } else if (r.more) dd.append(el("span", "dk-detail-ids", r.more));
    // a product name or a date is shown as written, not as an upper-case label
    ui.detailRows.append(el("dt", r.kind === "tech" || r.kind === "report" ? "dk-plain" : null, r.k), dd);
  }
  if (inside) {
    ui.detail.scrollTop = scroll;
    if (refocus) refocus.focus({ preventScroll: true });
  } else ui.detail.scrollTop = 0;
}

/** Keep the detail area in step with the record while it is open. */
function renderDetail() {
  if (!detailId) return;
  if (isLookupDetail()) {
    const d = detailOwner ? feed.lookupDetail(detailOwner.getAttribute("data-lookup")) : null;
    if (!d || !detailOwner.isConnected || !detailOwner.hasAttribute("data-lookup")) closeDetail();
    else fillDetail(d);
    return;
  }
  const d = feed.detail(detailId);
  if (!d || !cardEls.has(detailId)) {
    closeDetail();
    return;
  }
  fillDetail(d);
}

function renderBoard(view) {
  const b = view.board;
  const sig = b.columns.map((c) => c.key).join("");
  if (sig !== colSig) {
    colSig = sig;
    geoDirty = true;
    const keep = new Set(b.columns.map((c) => c.key));
    for (const [key, c] of colEls) {
      if (!keep.has(key)) {
        c.col.remove();
        colEls.delete(key);
      }
    }
    b.columns.forEach((c) => {
      if (colEls.has(c.key)) return;
      const col = el("div", "dk-col");
      const head = el("div", "dk-col-head", c.name);
      head.title = c.name;
      const wrap = el("div", "dk-col-cards");
      col.append(head, wrap);
      ui.cols.append(col);
      colEls.set(c.key, { col, head, wrap });
    });
    ui.cols.style.setProperty("--dk-ncols", String(b.columns.length));
  }
  if (ui.cols.style.getPropertyValue("--dk-rows") !== String(b.rows)) {
    ui.cols.style.setProperty("--dk-rows", String(b.rows));
    geoDirty = true;
  }
  if (ui.cols.classList.contains("dk-compact") !== b.compact) {
    ui.cols.classList.toggle("dk-compact", b.compact);
    geoDirty = true;
  }
  const fc = view.work && rows[view.cur] ? rows[view.cur].phase.color : PHASES.model.color;
  const seen = new Set();
  let focus = "";
  b.columns.forEach((c) => {
    const wrap = colEls.get(c.key).wrap;
    c.cards.forEach((card, i) => {
      seen.add(card.id);
      let n = cardEls.get(card.id);
      if (!n) {
        n = makeCard(card.id);
        cardEls.set(card.id, n);
        geoDirty = true;
      }
      if (wrap.children[i] !== n.el) {
        wrap.insertBefore(n.el, wrap.children[i] || null);
        geoDirty = true;
      }
      n.col = c.key;
      n.el.classList.toggle("dk-incoming", card.incoming);
      n.el.classList.toggle("dk-focus", card.focus);
      if (card.focus) n.el.style.setProperty("--fc", fc);
      if (card.focus || card.ghost) focus = card.id;
      setText(n.ghost, card.ghost);
      setText(n.title, card.title);
      if (n.el.title !== card.scenario) n.el.title = card.scenario;
      setMark(n.score, card.score);
      setMark(n.mp, card.path);
      setMark(n.mf, card.fix);
      setMark(n.mt, card.test);
      const chipSig = (card.chip.on ? "1" : "0") + card.chip.id + "\u0001" + card.chip.name + "\u0001" + card.chip.text;
      if (chipSig !== n.chipSig) {
        n.chipSig = chipSig;
        n.chip.classList.toggle("dk-on", card.chip.on);
        n.chip.textContent = "";
        if (card.chip.on && card.chip.id && card.chip.name) n.chip.append(el("b", null, card.chip.id), document.createTextNode(" " + card.chip.name));
        else n.chip.textContent = card.chip.text;
        n.chip.title = card.chip.on ? card.chip.text : "";
      }
    });
  });
  for (const [id, n] of cardEls) {
    if (!seen.has(id)) {
      n.el.remove();
      cardEls.delete(id);
      geoDirty = true;
      if (id === activeCard) setActive("");
    }
  }
  setText(ui.rootChip, b.rootText);
  ui.rootChip.title = b.rootText;
  ui.rootChip.classList.toggle("dk-on", !!b.rootText);
  setText(ui.boardCount, b.countText);

  // keep the card being worked on in view, unless the reader is scrolling
  if (focus !== lastFocus) {
    lastFocus = focus;
    const n = focus ? cardEls.get(focus) : null;
    if (n && b.compact && performance.now() - userScrollAt > 4000) {
      const box = ui.cols.getBoundingClientRect();
      const r = n.el.getBoundingClientRect();
      const head = colEls.get(n.col);
      const headH = (head ? head.head.getBoundingClientRect().height : 24) + 8;
      if (r.top < box.top + headH) ui.cols.scrollTop += r.top - box.top - headH;
      else if (r.bottom > box.bottom) ui.cols.scrollTop += r.bottom - box.bottom + 4;
    }
  }

  if (!reduce) {
    view.justLanded.forEach((j) => {
      const n = cardEls.get(j.id);
      const r = rows.find((x) => x.id === j.stage);
      if (!n) return;
      n.el.style.setProperty("--hc", r ? r.phase.color : PHASES.model.color);
      n.el.classList.remove("dk-hit");
      void n.el.offsetWidth;
      n.el.classList.add("dk-hit");
    });
  }
}

// ── HUD, log, tally ─────────────────────────────────────────────────────

function renderHud(view) {
  setText(ui.clockNow, view.clockText);
  // while polls are failing, the step line says so in one plain line
  const reconnecting = view.link === "retrying" && !!view.linkText;
  const txt = reconnecting ? view.linkText : view.stepText + " · " + view.stepName;
  if (ui.step.getAttribute("data-txt") !== txt) {
    ui.step.setAttribute("data-txt", txt);
    ui.step.textContent = "";
    if (reconnecting) ui.step.append(el("b", null, view.linkText));
    else ui.step.append(el("b", null, view.stepText), document.createTextNode(" · " + view.stepName));
    ui.step.title = txt;
    ui.step.classList.toggle("dk-step-warn", reconnecting || view.link === "lost");
  }
  ui.timeline.setAttribute("aria-valuenow", String(Math.round(view.progress * 100)));
  let note;
  if (view.failedStages) note = view.failedStages === 1 ? "1 stage failed in this run." : view.failedStages + " stages failed in this run.";
  else if (view.rerunStages) note = view.rerunStages === 1 ? "1 stage failed and was run again." : view.rerunStages + " stages failed and were run again.";
  else if (view.failed) note = "This run failed.";
  else if (view.terminal) note = "No stage failed in this run.";
  else if (view.status === "idle") note = "";
  else note = "No stage has failed so far.";
  setText(ui.legendNote, note);
}

function renderStatus(view, now) {
  const el2 = host.querySelector(":scope > .dk-sr");
  if (!el2) return;
  // a lookup step's result is said once, ahead of the usual line
  const fresh = view.announce.filter((a) => !announced.has(a.key));
  if (fresh.length) {
    for (const a of fresh) announced.add(a.key);
    statusKey = view.statusKey;
    statusAt = now;
    setText(el2, fresh.map((a) => a.text).join(" ") + (view.statusLine ? " " + view.statusLine : ""));
    return;
  }
  if (view.statusKey !== statusKey || now - statusAt >= STATUS_EVERY_MS) {
    statusKey = view.statusKey;
    statusAt = now;
    setText(el2, view.statusLine);
  }
}

function eventSig(e) {
  return e.kind + "\u0001" + e.t + "\u0001" + e.text;
}

function logRow(e) {
  const row = el("div", "dk-log-row dk-k-" + e.kind);
  row.append(el("time", null, fmtClock(e.t)), el("span", null, e.text));
  return row;
}

function renderLog(view) {
  const l = view.log;
  const log = ui.log;
  const endSig = l.end ? l.end.kind + l.end.text : "";
  if (l.version === logVersion && l.shown === logShown && endSig === logEnd) return;
  const stick = log.scrollHeight - log.scrollTop - log.clientHeight < 24;
  // Rows already on screen that still match the events are kept; only the
  // rows from the first difference on are replaced, so a poll that adds
  // events adds rows instead of rebuilding the log.
  if (logEnd) {
    log.lastChild.remove();
    logSigs.pop();
  }
  let keep = 0;
  while (keep < logSigs.length && keep < l.shown && logSigs[keep] === eventSig(l.events[keep])) keep += 1;
  while (logSigs.length > keep) {
    log.lastChild.remove();
    logSigs.pop();
  }
  for (let i = keep; i < l.shown; i += 1) {
    log.append(logRow(l.events[i]));
    logSigs.push(eventSig(l.events[i]));
  }
  if (l.end) {
    log.append(logRow(l.end));
    logSigs.push(eventSig(l.end));
  }
  logVersion = l.version;
  logShown = l.shown;
  logEnd = endSig;
  if (stick) log.scrollTop = log.scrollHeight;
}

function renderTally(view) {
  const t = view.tally;
  const sig = t.rows.map((r) => [r.key, r.n, r.total, r.text, r.off].join("|")).join(";") + "#" + t.notes.join(";");
  if (sig === tallySig) return;
  tallySig = sig;
  ui.tally.textContent = "";
  t.rows.forEach((r) => {
    const mid = el("div", "dk-pips");
    mid.style.setProperty("--c", (PHASES[r.phase] || PHASES.model).color);
    if (!r.plain && !r.off) {
      const size = r.total === null ? r.n : r.total;
      if (size > MAX_PIPS) {
        const bar = el("div", "dk-bar");
        const fill = el("i");
        fill.style.width = (r.total ? clamp(r.n / r.total, 0, 1) * 100 : 100).toFixed(1) + "%";
        bar.append(fill);
        mid.append(bar);
      } else {
        for (let i = 0; i < size; i += 1) mid.append(el("i", "dk-pip" + (i < r.n ? " dk-on" : "")));
      }
    }
    ui.tally.append(el("div", "dk-lab", r.label), mid, el("div", "dk-num" + (r.off ? " dk-off" : ""), r.text));
  });
  t.notes.forEach((n) => ui.tally.append(el("div", "dk-note", n + ".")));
}

// ── canvas: channel, packets, attack-tree links ─────────────────────────

function measure() {
  const m = ui.main.getBoundingClientRect();
  const R = (e) => {
    const r = e.getBoundingClientRect();
    return { l: r.left - m.left, t: r.top - m.top, r: r.right - m.left, b: r.bottom - m.top, x: (r.left + r.right) / 2 - m.left, y: (r.top + r.bottom) / 2 - m.top, w: r.width };
  };
  const dpr = window.devicePixelRatio || 1;
  const cw = Math.round(m.width * dpr);
  const ch = Math.round(m.height * dpr);
  if (ui.cv.width !== cw || ui.cv.height !== ch) {
    ui.cv.width = cw;
    ui.cv.height = ch;
  }
  // Columns too narrow for the three marks side by side get the tight card layout.
  const firstCol = colEls.values().next().value;
  if (firstCol) {
    const colW = firstCol.col.getBoundingClientRect().width;
    if (colW > 0) ui.app.classList.toggle("dk-tight", colW < TIGHT_COLUMN_PX);
  }
  geo = { w: m.width, h: m.height, dpr, agents: {}, cards: new Map(), heads: new Map(), root: R(ui.rootChip), clip: R(ui.cols) };
  for (const [id, n] of cardEls) geo.cards.set(id, R(n.el));
  for (const [key, c] of colEls) geo.heads.set(key, R(c.head));
  const railR = R(ui.rail).r;
  rows.forEach((r) => {
    const g = R(r.head);
    g.r = railR - 3;
    geo.agents[r.id] = g;
  });
  geoDirty = false;
}
function curve(a, b) {
  const dx = Math.max(50, (b.x - a.x) * 0.5);
  return [a.x, a.y, a.x + dx, a.y, b.x - dx, b.y, b.x, b.y];
}
function bez(c, u) {
  const v = 1 - u;
  const a = v * v * v;
  const b = 3 * v * v * u;
  const d = 3 * v * u * u;
  const e = u * u * u;
  return [a * c[0] + b * c[2] + d * c[4] + e * c[6], a * c[1] + b * c[3] + d * c[5] + e * c[7]];
}
/** A card's point, kept inside the board when the card is scrolled out of view. */
function cardPoint(c, left) {
  return { x: left ? c.l : c.x, y: clamp(c.y, geo.clip.t + 8, geo.clip.b - 8) };
}

function drawFlow(view) {
  if (!geo) return;
  const ctx = ui.ctx;
  ctx.setTransform(geo.dpr, 0, 0, geo.dpr, 0, 0);
  ctx.clearRect(0, 0, geo.w, geo.h);
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  const stageRow = (id) => rows.find((r) => r.id === id);

  // attack-tree links: root -> category -> threat. Part of the result, so they stay (dim) afterwards.
  if (view.board.tree.started) {
    const blue = PHASES.model.color;
    const hot = view.board.tree.active;
    ctx.save();
    ctx.strokeStyle = rgba(blue, hot ? 0.85 : 0.3);
    ctx.lineWidth = hot ? 1.6 : 1.1;
    if (hot && fxOn()) {
      ctx.shadowColor = blue;
      ctx.shadowBlur = 8;
    }
    const linkedCols = new Set();
    ctx.beginPath();
    view.board.columns.forEach((c) => {
      if (c.cards.some((k) => k.linked)) linkedCols.add(c.key);
    });
    if (geo.root.w > 0) {
      linkedCols.forEach((key) => {
        const h = geo.heads.get(key);
        if (!h) return;
        ctx.moveTo(geo.root.x, geo.root.b);
        ctx.bezierCurveTo(geo.root.x, geo.root.b + 10, h.x, h.t - 12, h.x, h.t);
      });
    }
    ctx.stroke();
    ctx.beginPath();
    ctx.rect(geo.clip.l - 6, geo.clip.t, geo.clip.r - geo.clip.l + 12, geo.clip.b - geo.clip.t);
    ctx.clip();
    ctx.beginPath();
    view.board.columns.forEach((c) => {
      const h = geo.heads.get(c.key);
      if (!h) return;
      c.cards.forEach((k) => {
        const g = k.linked ? geo.cards.get(k.id) : null;
        if (!g) return;
        const x = h.l - 3;
        ctx.moveTo(h.l, h.t + 1);
        ctx.lineTo(x, h.t + 1);
        ctx.lineTo(x, g.t + 12);
        ctx.lineTo(g.l, g.t + 12);
      });
    });
    ctx.stroke();
    ctx.restore();
  }
  if (!fxOn()) return;

  // open channel: the working agent to the thing it is working on
  const w = view.work;
  const tg = w && w.target;
  const a = w && geo.agents[w.stage];
  if (tg && a && a.w > 0) {
    const row = stageRow(w.stage);
    const col = row ? row.phase.color : PHASES.model.color;
    const card = tg.root ? null : geo.cards.get(tg.card);
    const end = tg.root ? { x: geo.root.l, y: geo.root.y } : card ? cardPoint(card, true) : null;
    if (end && (!tg.root || geo.root.w > 0)) {
      const c = curve({ x: a.r + 2, y: a.y }, end);
      ctx.save();
      ctx.strokeStyle = rgba(col, 0.42);
      ctx.lineWidth = 1.2;
      ctx.setLineDash([4, 8]);
      ctx.lineDashOffset = -animClock * 42;
      ctx.beginPath();
      ctx.moveTo(c[0], c[1]);
      ctx.bezierCurveTo(c[2], c[3], c[4], c[5], c[6], c[7]);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = col;
      ctx.shadowColor = col;
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(end.x, end.y, 3, 0, 6.3);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(a.r + 2, a.y, 2.5, 0, 6.3);
      ctx.fill();
      ctx.restore();
    }
  }

  // packets: one per delivered item, agent -> card
  view.flights.forEach((f) => {
    const from = geo.agents[f.stage];
    const to = geo.cards.get(f.id);
    if (!from || !to || !(from.w > 0)) return;
    const row = stageRow(f.stage);
    const col = row ? row.phase.color : PHASES.model.color;
    const c = curve({ x: from.r + 2, y: from.y }, cardPoint(to, false));
    const u = clamp(f.u, 0, 1);
    const e = u * u * (3 - 2 * u);
    ctx.save();
    for (let k = 10; k >= 1; k -= 1) {
      const p0 = bez(c, Math.max(0, e - k * 0.022));
      const p1 = bez(c, Math.max(0, e - (k - 1) * 0.022));
      ctx.strokeStyle = rgba(col, 0.75 * (1 - k / 11));
      ctx.lineWidth = 2.6 * (1 - k / 14);
      ctx.beginPath();
      ctx.moveTo(p0[0], p0[1]);
      ctx.lineTo(p1[0], p1[1]);
      ctx.stroke();
    }
    const p = bez(c, e);
    ctx.shadowColor = col;
    ctx.shadowBlur = 14;
    ctx.fillStyle = "#fff";
    ctx.beginPath();
    ctx.arc(p[0], p[1], 3.2, 0, 6.3);
    ctx.fill();
    ctx.restore();
  });
}

// ── frame loop ──────────────────────────────────────────────────────────

function render(view, now) {
  renderHud(view);
  renderStages(view);
  renderWork(view);
  renderSummary(view);
  renderBoard(view);
  renderLog(view);
  renderTally(view);
  renderDetail();
  renderStatus(view, now);
  if (geoDirty) measure();
  drawFlow(view);
}

function tick(ts) {
  vm = feed.view(ts, { motion: !reduce });
  if (!vm) return false;
  if (fxOn() && vm.work && rows[vm.cur]) poseSprite(rows[vm.cur].sp, animClock);
  render(vm, ts);
  return true;
}

function frame(ts) {
  raf = 0;
  if (!feed || !visible()) return;
  const dt = Math.min(0.1, Math.max(0, (ts - lastTs) / 1000));
  lastTs = ts;
  animClock += dt;
  if (!tick(ts)) return;
  if (!vm.idle) raf = requestAnimationFrame(frame);
}

function start() {
  if (raf || !feed || !visible()) return;
  if (vm && vm.idle) return;
  lastTs = performance.now();
  raf = requestAnimationFrame(frame);
}
function stop() {
  if (raf) {
    cancelAnimationFrame(raf);
    raf = 0;
  }
}
/** Draw once, now, without advancing the animation clock. */
function redraw() {
  if (!feed || !ui || !visible()) return;
  tick(performance.now());
}

// ── the three calls app.js makes ────────────────────────────────────────

/** Build the deck inside ``host`` (once) and start a fresh run. */
export function deckInit(hostEl) {
  if (!hostEl) return false;
  if (host !== hostEl || !ui) {
    stop();
    host = hostEl;
    ui = build();
    host.append(ui.app);
    const mq = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
    const wantsCalm = !!(mq && mq.matches);
    const savedReduce = stored(KEY_REDUCE);
    const savedList = stored(KEY_LIST);
    if (mq && mq.addEventListener) {
      mq.addEventListener("change", (e) => setModes(e.matches, e.matches ? true : listMode, false));
    }
    // a pinned lookup list closes on a click outside the deck, and on
    // Escape wherever focus is (inside the deck the app's own handlers act)
    document.addEventListener("click", (e) => {
      if (ui && detailId && isLookupDetail() && detailBy === "click" && !host.contains(e.target)) closeDetail();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && ui && detailId && isLookupDetail() && !ui.app.contains(e.target)) closeDetail();
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop();
      else {
        redraw();
        start();
      }
    });
    if (window.ResizeObserver) {
      // fires on resize, and when the step panel holding the deck is shown again
      new ResizeObserver(() => {
        geoDirty = true;
        if (!raf) {
          redraw();
          start();
        }
      }).observe(host);
    } else {
      window.addEventListener("resize", () => {
        geoDirty = true;
        if (!raf) redraw();
      });
    }
    reduce = wantsCalm || savedReduce === true;
    listMode = savedList === null ? reduce : savedList;
    setModes(reduce, listMode, false);
  }
  feed = createDeckFeed();
  vm = null;
  stageSig = "";
  colSig = "";
  for (const c of colEls.values()) c.col.remove();
  colEls = new Map();
  cardEls = new Map();
  ui.log.textContent = "";
  logSigs = [];
  activeCard = "";
  ui.cols.removeAttribute("aria-activedescendant");
  closeDetail();
  logVersion = -1;
  logShown = 0;
  logEnd = "";
  tallySig = "";
  statusKey = "";
  statusAt = 0;
  announced = new Set();
  quietLookup = false;
  lastFocus = "";
  summarySig = "\u0000";
  geoDirty = true;
  return true;
}

/** Take one polled job: its progress record, status, and error text. */
export function deckSync(progress, jobStatus, jobError) {
  if (!host || !feed) return false;
  if (!feed.push(progress, jobStatus, jobError, performance.now())) return false;
  host.hidden = false;
  if (vm) vm.idle = false;
  if (raf) return true;
  redraw();
  start();
  return true;
}

/** Whether motion should be cut: the deck's Reduce motion toggle is on, or
    the system asks for reduced motion right now. */
export function deckReducedMotion() {
  if (reduce) return true;
  const mq = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  return !!(mq && mq.matches);
}

/** Say how polling is going: "ok", "retrying" (with the line to show), or
    "lost" (with the sentence to show; the deck stops and stays stopped). */
export function deckLink(mode, message) {
  if (!feed || !feed.setLink(mode, message, performance.now())) return false;
  redraw();
  start();
  return true;
}

/** A failed add-on was run again from the results and succeeded: the deck
    says so wherever it said that add-on failed. */
export function deckAddonRerun(stageId) {
  if (!feed || !feed.markRerun(stageId)) return false;
  redraw();
  start();
  return true;
}

/** Hide the deck and stop drawing. The run's state is kept. */
export function deckHide() {
  stop();
  if (host) host.hidden = true;
}
