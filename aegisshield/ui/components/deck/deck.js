// The "agents at work" deck: everything that decides what is shown.
//
// Pure: no page globals, no timers, no clock of its own. The caller passes
// each polled progress record with the time it arrived, and asks for a view
// model on each animation tick with the time of that tick (milliseconds, any
// monotonic origin). deck_view.js draws the view model.
//
// Every string in a progress record is untrusted (model output or user text).
// Nothing here builds markup; strings are only cut, cleaned, and passed on.

export const FLIGHT_MS = 700; // one packet, agent to card, at normal speed
export const GAP_MS = 450; // usual time between two landings
export const GAP_FLOOR_MS = 250; // never closer than this while the job runs
export const BACKLOG_HANDFUL = 5; // more waiting than this shortens the gap
export const BACKLOG_FLOOD = 40; // far more than a handful: the floor gives way
export const DRAIN_MS = 2000; // after the job ends, everything lands within this
export const DRAIN_FLIGHT_MS = 350;
export const REATTACH_GAP_MS = 3000; // no tick for this long: catch up at once
export const MAX_PIPS = 24;

const KIND_STAGE = { w: "stride", m: "mitre_map", p: "attack_tree", f: "mitigations", s: "dread", t: "test_cases" };
const KIND_ORDER = "wmpfst";
const STAGE_KIND = { mitre_map: "m", mitigations: "f", dread: "s", test_cases: "t" };
const PHASE = { enrichment: "gather", modeling: "model", scoring: "score", validation: "check" };
const STAGE_STATUS = new Set(["queued", "working", "done", "fallback", "error"]);
// "idle" is not a job status: it is the preview shown before a run exists.
const JOB_STATUS = new Set(["idle", "queued", "running", "complete", "failed", "cancelled"]);
const TERMINAL = new Set(["complete", "failed", "cancelled"]);
const RESOLVED = new Set(["done", "fallback", "error"]);
const ID_RE = /^TC-[A-Z]\d{2,4}$/;

export const COLUMNS = [
  { key: "S", name: "Spoofing" },
  { key: "T", name: "Tampering" },
  { key: "R", name: "Repudiation" },
  { key: "I", name: "Information Disclosure" },
  { key: "D", name: "Denial of Service" },
  { key: "E", name: "Elevation of Privilege" },
];
const OTHER = { key: "O", name: "Other" };
const COLUMN_BY_TYPE = new Map(COLUMNS.map((c) => [c.name.toLowerCase(), c.key]));
const COLUMN_NAME = new Map([...COLUMNS, OTHER].map((c) => [c.key, c.name]));

const FIELD_LABEL = { Scenario: "scenario", "Potential Impact": "potential impact", Recommendations: "recommendations" };
const AXES = [
  ["damage", "Damage"],
  ["reproducibility", "Reproducibility"],
  ["exploitability", "Exploitability"],
  ["affected_users", "Affected users"],
  ["discoverability", "Discoverability"],
];

// ── small helpers ───────────────────────────────────────────────────────

function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
// bidirectional controls (U+202A to U+202E, U+2066 to U+2069) can make text
// read in a different order than it is written: never shown
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/g;
const COUNT_CAP = 9999;
const CLOCK_LEAD_S = 3; // the clock never runs more than this past the last answered poll
const LINK_MODES = new Set(["ok", "retrying", "lost"]);
const RERUN_REASON = "Failed, then run again from the results";

// ── what the lookups found (progress.deck.lookups) ──────────────────────
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const NVD_STATES = new Set(["found", "none", "unknown", "failed"]);
const NVD_TOTALS = ["checked", "returned", "used", "failed", "unknown"];
const OTX_STATES = new Set(["found", "none", "failed", "off"]);
const LOOKUP_TECHS = 25;
const LOOKUP_IDS = 5;
const LOOKUP_REPORTS = 10;
const LOOKUP_USED = 10; // NVD passes on at most ten per product
const LOOKUP_SCAN = 50; // raw list items looked at before giving up
const LOOKUP_STAGES = ["nvd", "otx"];
const NVD_NOTE = "This is what NVD returned for each product and version. Some entries may not apply to your system.";
const OTX_NOTE = "These are public community reports that matched the sector name.";
// about our side, so true whatever stopped the lookup
const NVD_FAILED = "The NVD lookup did not finish";
const OTX_FAILED = "The OTX lookup did not finish";
const NVD_UNKNOWN = "NVD has no entry for this product and version";
// a lookup step that ended "error" by itself, with one of these reasons,
// did not stop the run (the job carries on past it)
const LOOKUP_OWN_FAILURE = new Set(["The NVD lookup did not finish.", "The OTX lookup did not finish."]);
const TO_WRITER = " to the threat writer";
// lookup strings also lose zero-width and direction marks, line and
// paragraph separators, the byte order mark, DEL, and the C1 controls;
// newline and tab read as a space
const LOOKUP_STRIP_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u061C\u2028\u2029\uFEFF]/g;
const LOOKUP_SPACE_RE = /[\n\t]/g;

/** The NVD page for ``id``, or "" when ``id`` is not exactly a CVE id. */
export function nvdLink(id) {
  return typeof id === "string" && CVE_RE.test(id) ? "https://nvd.nist.gov/vuln/detail/" + id : "";
}
function str(v, cap) {
  if (typeof v !== "string") return "";
  const clean = v.replace(BIDI_RE, "");
  return clean.length > cap ? clean.slice(0, cap) : clean;
}
function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
/** A score or score axis: a number from 0 to 10, or null. */
function score10(v) {
  const n = num(v);
  return n === null || n < 0 || n > 10 ? null : n;
}
function count(v) {
  const n = num(v);
  return n === null || n < 0 ? 0 : Math.min(COUNT_CAP, Math.floor(n));
}
/** ``table[key]`` only for the table's own keys: ``constructor``,
    ``toString``, and ``__proto__`` read as unknown. */
function own(table, key) {
  return typeof key === "string" && Object.hasOwn(table, key) ? table[key] : undefined;
}
function clamp(x, a, b) {
  return x < a ? a : x > b ? b : x;
}
/** ``obj[key]`` only when ``obj`` is a plain object that owns ``key``. */
function prop(obj, key) {
  return isObj(obj) && Object.hasOwn(obj, key) ? obj[key] : undefined;
}
function pad2(n) {
  return (n < 10 ? "0" : "") + n;
}
function plural(n, one, many) {
  return n + " " + (n === 1 ? one : many);
}
/** A lookup count as words: a count at the cap is shown as a floor. */
function fmtN(n) {
  return n >= COUNT_CAP ? "9,999 or more" : String(n);
}
function pluralN(n, one, many) {
  return fmtN(n) + " " + (n === 1 ? one : many);
}
/** A lookup string from the record, cleaned more strictly than ``str``. */
function lookupStr(v, cap) {
  if (typeof v !== "string") return "";
  return str(v.replace(LOOKUP_SPACE_RE, " ").replace(LOOKUP_STRIP_RE, ""), cap).trim();
}

export function fmtClock(seconds) {
  const s = Math.min(5999, Math.max(0, Math.floor((Number(seconds) || 0) + 1e-6)));
  return pad2(Math.floor(s / 60)) + ":" + pad2(s % 60);
}

export function fmtDur(seconds) {
  const d = Math.max(0, Number(seconds) || 0);
  if (d >= 60) return Math.floor(d / 60) + " min " + Math.floor(d % 60) + " s";
  return (d < 10 ? d.toFixed(1) : String(Math.round(d))) + " s";
}

export function isDeckProgress(progress) {
  return isObj(progress) && progress.office === true && isObj(progress.deck);
}

// ── bringing the deck into view ──────────────────────────────────────────

/** The gap, in px, left between the sticky top bar and the deck's top edge. */
export const DECK_SCROLL_GAP = 8;

const JOB_ENDED = new Set(["complete", "failed", "cancelled"]);

/** Whether a polled job should bring the deck into view: once per run
    (``scrolled`` says it already happened), and only while the job is still
    queued or running, never when it has already finished or failed. */
export function deckWantsScroll(jobStatus, scrolled) {
  if (scrolled) return false;
  return typeof jobStatus === "string" && jobStatus !== "" && !JOB_ENDED.has(jobStatus);
}

/** The page scroll offset that puts the deck's top edge ``gap`` px below the
    sticky top bar. ``deckTop`` and ``barBottom`` are viewport positions (a
    bounding rect's top and bottom), ``scrollY`` the page's current offset.
    Returns null when a number is missing, and never less than 0. */
export function deckScrollTarget(deckTop, scrollY, barBottom, gap = DECK_SCROLL_GAP) {
  const values = [deckTop, scrollY, barBottom, gap].map((v) => (typeof v === "number" ? v : NaN));
  if (!values.every(Number.isFinite)) return null;
  const [top, y, bar, g] = values;
  return Math.max(0, Math.round(y + top - Math.max(0, bar) - Math.max(0, g)));
}

// ── card titles ─────────────────────────────────────────────────────────

const TITLE_MIN = 6;
const TITLE_MAX = 9;
const DANGLING = new Set([
  "a", "an", "the", "of", "to", "and", "or", "for", "in", "on", "with", "that", "by", "via", "from", "into", "at",
  "as", "is", "are", "its", "their", "which", "who", "so", "but", "than", "then", "because", "e.g", "i.e", "etc",
  "when", "while", "where", "if", "not", "be", "been", "can", "may", "will", "has", "have", "does", "do",
]);

function bare(word) {
  return word.toLowerCase().replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, "");
}

/** A short card title cut from a scenario: six to nine of its own words, in
    order, ending on a word boundary. Words are only dropped, never added; a
    leading article goes, text in parentheses goes, and a cut title ends "…". */
export function shortTitle(scenario) {
  const text = String(scenario == null ? "" : scenario)
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\.\.\.$/, "")
    .trim();
  if (!text) return "";
  let words = text
    .replace(/\s*\([^)]*\)/g, "")
    .replace(/\s*\([^)]*$/, "")
    .split(" ")
    .filter(Boolean);
  if (words.length < TITLE_MIN) words = text.split(" ");
  if (words.length > TITLE_MIN && /^(an?|the)$/i.test(words[0])) {
    words = words.slice(1);
    words[0] = words[0].charAt(0).toUpperCase() + words[0].slice(1);
  }
  const tidy = (list) => list.join(" ").replace(/[,;:.!?]+$/, "");
  if (words.length <= TITLE_MAX) return tidy(words);
  let n = 0;
  for (let i = TITLE_MIN - 1; i < TITLE_MAX; i += 1) {
    if (/[,;:.!?]$/.test(words[i]) && !DANGLING.has(bare(words[i]))) {
      n = i + 1;
      break;
    }
  }
  if (!n) {
    n = TITLE_MAX;
    while (n > TITLE_MIN && DANGLING.has(bare(words[n - 1]))) n -= 1;
  }
  return tidy(words.slice(0, n)) + "…";
}

// ── readable lines from the raw tail of what a model is writing ─────────

function cleanInline(text) {
  return String(text)
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/[`*|[\]{}]/g, " ")
    .replace(/["']{2,}/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function tailLines(text) {
  const raw = String(text == null ? "" : text);
  const lines = raw.split("\n");
  // A clipped tail opens with "..." in the middle of a line: drop the marker.
  if (lines.length && lines[0].startsWith("...")) lines[0] = lines[0].slice(3);
  return lines;
}

const TREE_SKIP = /^(%%|graph\s|flowchart\s|```|classDef\s|class\s|style\s|linkStyle\s|subgraph\s|end$)/;

function treeLabel(rawLine) {
  const line = rawLine.trim();
  if (!line || TREE_SKIP.test(line)) return "";
  const segs = line.split(/-->|-\.->|==>|---/);
  let seg = segs[segs.length - 1].trim();
  if (seg.startsWith("|")) {
    const close = seg.indexOf("|", 1);
    seg = close > 0 ? seg.slice(close + 1).trim() : "";
  }
  const m = /^[A-Za-z0-9_]+\s*(.*)$/.exec(seg);
  if (!m || !/^[[({>]/.test(m[1])) return "";
  return cleanInline(m[1].replace(/^[[({>]+/, "").replace(/[\])};]+\s*$/, "").replace(/^\s*["']|["']\s*$/g, ""));
}

/** The node label being written in a Mermaid tail, and the labels before it. */
export function treeLive(text) {
  const lines = tailLines(text).filter((l) => l.trim());
  const labels = lines.map(treeLabel);
  const current = labels.length ? labels[labels.length - 1] : "";
  const done = labels.slice(0, -1).filter(Boolean);
  return { current, done };
}

/** The fix sentence being written in a markdown table tail. */
export function fixLive(text) {
  const lines = tailLines(text).filter((l) => l.trim());
  if (!lines.length) return "";
  const line = lines[lines.length - 1].trim();
  if (/^\|?[\s:|-]+\|?$/.test(line)) return "";
  let cells = line.split("|").map((c) => c.trim());
  if (line.startsWith("|")) cells = cells.slice(1);
  if (cells.length > 1 && /^(\*\*)?TC-[A-Za-z]\d+(\*\*)?$/.test(cells[0])) cells = cells.slice(1);
  else if (cells.length > 1 && /^(threat|id|threat id)$/i.test(cells[0])) return "";
  return cleanInline(cells.filter(Boolean).join(" "));
}

/** The feature line, scenario line, and step being written in a gherkin tail. */
export function testLive(text) {
  const lines = tailLines(text).map((l) => l.trim());
  let feature = "";
  let scenario = "";
  let step = "";
  for (const line of lines) {
    if (!line || line.startsWith("```") || line.startsWith("#")) continue;
    const f = /^Feature:\s*(.*)$/.exec(line);
    const s = /^Scenario(?: Outline)?:\s*(.*)$/.exec(line);
    if (f) {
      feature = cleanInline(f[1]);
      scenario = "";
      step = "";
    } else if (s) {
      scenario = cleanInline(s[1]);
      step = "";
    } else if (/^(Given|When|Then|And|But)\b/.test(line)) {
      step = cleanInline(line);
    }
  }
  const out = [];
  if (feature) out.push("Feature: " + feature);
  if (scenario) out.push("Scenario: " + scenario);
  if (step) out.push(step);
  return out.join("\n");
}

/** The readable text for the working stage's live tail. */
export function readableLive(live) {
  if (!isObj(live)) return "";
  const text = str(live.text, 4000);
  if (live.stage === "stride") return text.replace(/^\.\.\./, "").replace(/\s+/g, " ").trim();
  if (live.stage === "attack_tree") return treeLive(text).current;
  if (live.stage === "mitigations") return fixLive(text);
  if (live.stage === "test_cases") return testLive(text);
  return "";
}

/** Where typing resumes when the readable text changes from ``prev`` to
    ``next``, given ``pos`` characters of ``prev`` were shown. A continuation
    keeps its place; a tail that slid forward keeps the overlap; anything else
    keeps only the common start. */
export function retarget(prev, next, pos) {
  if (next.startsWith(prev)) return Math.min(pos, next.length);
  const least = Math.min(20, next.length);
  for (let d = 1; d <= prev.length - least; d += 1) {
    if (next.startsWith(prev.slice(d))) return clamp(pos - d, 0, next.length);
  }
  let common = 0;
  const top = Math.min(prev.length, next.length);
  while (common < top && prev.charCodeAt(common) === next.charCodeAt(common)) common += 1;
  return Math.min(pos, common);
}

/** The most recent ``win`` characters of ``text``, starting on a word. */
export function windowed(text, win) {
  if (text.length <= win) return text;
  const cut = text.length - win;
  const sp = text.indexOf(" ", cut);
  return "…" + text.slice(sp >= 0 && sp < text.length - 1 ? sp + 1 : cut);
}

// ── the record, checked and reshaped ────────────────────────────────────

function columnFor(type) {
  return COLUMN_BY_TYPE.get(String(type).trim().toLowerCase()) || OTHER.key;
}
function columnForId(id) {
  const letter = id.charAt(3);
  return COLUMN_NAME.has(letter) && letter !== OTHER.key ? letter : OTHER.key;
}

function normalize(progress, titles) {
  const d = progress.deck;
  const stages = (Array.isArray(progress.stages) ? progress.stages : []).filter(isObj).map((s, i) => ({
    index: i,
    id: str(s.id, 40) || "stage" + i,
    name: str(s.name, 60) || str(s.label, 60) || str(s.id, 40) || "Stage " + (i + 1),
    term: str(s.term, 60),
    phase: own(PHASE, s.phase) || "model",
    status: STAGE_STATUS.has(s.status) ? s.status : "queued",
    detail: str(s.detail, 200),
    reason: str(s.reason, 200),
    started: num(s.started_s),
    finished: num(s.finished_s),
  }));
  const threats = [];
  const byId = new Map();
  for (const t of Array.isArray(d.threats) ? d.threats : []) {
    if (!isObj(t) || typeof t.id !== "string" || !ID_RE.test(t.id) || byId.has(t.id)) continue;
    const scenario = str(t.scenario, 700);
    let title = titles.get(scenario);
    if (title === undefined) {
      title = shortTitle(scenario);
      titles.set(scenario, title);
    }
    const type = str(t.type, 40);
    const entry = { id: t.id, index: threats.length, type, col: columnFor(type), scenario, title, t: num(t.t) || 0 };
    byId.set(t.id, entry);
    threats.push(entry);
  }
  const part = (source, shape) => {
    const out = new Map();
    if (!isObj(source)) return out;
    for (const id of Object.keys(source)) {
      if (byId.has(id) && isObj(source[id])) out.set(id, shape(source[id]));
    }
    return out;
  };
  const tree = isObj(d.tree) ? d.tree : {};
  const steps = new Map();
  if (isObj(tree.steps)) {
    for (const id of Object.keys(tree.steps)) if (byId.has(id)) steps.set(id, count(tree.steps[id]));
  }
  const um = isObj(d.unmatched) ? d.unmatched : {};
  const live = isObj(d.live)
    ? {
        stage: str(d.live.stage, 40),
        item: typeof d.live.item === "string" && ID_RE.test(d.live.item) ? d.live.item : null,
        text: str(d.live.text, 4000),
        field: own(FIELD_LABEL, d.live.field) ? d.live.field : null,
      }
    : null;
  return {
    stages,
    stageById: new Map(stages.map((s) => [s.id, s])),
    t: num(d.t) || 0,
    threats,
    byId,
    techniques: part(d.techniques, (v) => ({ id: str(v.id, 120), name: str(v.name, 120), t: num(v.t) || 0 })),
    fixes: part(d.fixes, (v) => ({ text: str(v.text, 400), t: num(v.t) || 0 })),
    scores: part(d.scores, (v) => ({
      risk: score10(v.risk),
      axes: AXES.map(([key]) => score10(v[key])),
      t: num(v.t) || 0,
    })),
    tests: part(d.tests, (v) => ({ title: str(v.title, 240), t: num(v.t) || 0 })),
    root: str(tree.root, 200),
    links: count(tree.links),
    steps,
    live,
    unmatched: { fixes: count(um.fixes), scores: count(um.scores), tests: count(um.tests), tree: count(um.tree) },
    truncated: d.truncated === true,
    lookups: readLookups(prop(d, "lookups")),
  };
}

// ── lookup wording: always about the source, never "your system has" ──────

function productName(e) {
  return e.version ? e.tech + " " + e.version : e.tech;
}
/** One product's result. ``to`` follows "passed on" (the detail list says
    in full where the entries went). */
function nvdLine(e, to = "") {
  if (e.state === "failed") return NVD_FAILED;
  if (e.state === "unknown") return NVD_UNKNOWN;
  if (!e.returned) return "NVD returned none";
  const head = "NVD returned " + fmtN(e.returned) + ", ";
  if (!e.used) return head + "none passed on" + to;
  if (e.used >= e.returned) return head + (e.used === 1 ? "passed on" : "all " + fmtN(e.used) + " passed on") + to;
  return head + "the " + fmtN(e.used) + " highest-scored passed on" + to;
}
/** "at least" when the search hit its limit (a count at the cap already says "or more"). */
function atLeast(o) {
  return o.atLeast && o.returned < COUNT_CAP ? "at least " : "";
}
function otxMatched(o) {
  return atLeast(o) + pluralN(o.returned, "public report", "public reports");
}
function otxLine(o, to = "") {
  if (o.state === "failed") return OTX_FAILED;
  if (o.state === "off") return "OTX is switched off (offline mode)";
  const where = o.sector ? " matched " + o.sector : " matched";
  if (o.state === "none" || !o.returned) return "no public reports" + where;
  const head = otxMatched(o) + where + ", ";
  if (!o.used) return head + "none passed on" + to;
  if (o.used >= o.returned && !o.atLeast) return head + (o.used === 1 ? "passed on" : "all " + fmtN(o.used) + " passed on") + to;
  return head + "the " + fmtN(o.used) + " newest passed on" + to;
}
function nvdTotals(lk) {
  const t = lk.total;
  return { ...t, answered: Math.max(0, t.checked - t.failed - t.unknown) };
}
/** What every product came to, for a status line or the log. */
function nvdSummary(lk, products) {
  const n = nvdTotals(lk);
  const of = products ? " for " + pluralN(n.checked, "product", "products") : "";
  let text = n.returned ? "NVD returned " + fmtN(n.returned) + of + ", " + fmtN(n.used) + " passed on" : n.answered ? "NVD returned none" + of : "";
  const extra = [];
  if (n.failed) extra.push(fmtN(n.failed) + " did not finish");
  if (n.unknown) extra.push(fmtN(n.unknown) + " had no entry in NVD");
  // nothing answered: say what the products came to
  if (!text) return extra.length ? "of " + pluralN(n.checked, "product", "products") + ", " + extra.join(", ") : "";
  return extra.length ? text + ", " + extra.join(", ") : text;
}
/** The short result on a lookup agent's row once its step is done: short
    enough for one line at ordinary values ("used" is "passed on"). */
/** A count for the row note, where every character counts. */
function shortN(n) {
  return n >= COUNT_CAP ? "9,999+" : String(n);
}

/**
 * The short result on an agent's row: "12 of 52 used" (12 of the 52 the
 * source returned were passed to the threat writer). Kept short enough to
 * fit one line beside a step time of over a minute; the log, the status
 * line, and the detail list carry the full sentences. A lookup that failed
 * leads the note, so an ellipsis on a narrow row can never hide it.
 */
function lookupNote(id, lk) {
  if (!lk) return "";
  if (id === "nvd") {
    const n = nvdTotals(lk);
    if (!n.checked) return "";
    const parts = n.failed ? [shortN(n.failed) + " failed"] : [];
    if (n.returned) parts.push(shortN(n.used) + " of " + shortN(n.returned) + " used");
    else if (n.answered) parts.push("none returned");
    if (!parts.length && n.unknown) parts.push("no entry");
    return parts.join(", ");
  }
  const o = lk.otx;
  if (!o || o.state === "failed" || o.state === "off") return "";
  if (o.state === "none" || !o.returned || !o.used) return "no reports matched";
  const more = o.atLeast && o.returned < COUNT_CAP ? "+" : "";
  return shortN(o.used) + " of " + shortN(o.returned) + more + " " + (o.returned === 1 ? "report" : "reports") + " used";
}

function readNvd(e) {
  if (!isObj(e)) return null;
  const state = prop(e, "state");
  if (typeof state !== "string" || !NVD_STATES.has(state)) return null;
  const returned = count(prop(e, "returned"));
  const top = [];
  const raw = prop(e, "top");
  if (Array.isArray(raw)) {
    for (const item of raw.slice(0, LOOKUP_SCAN)) {
      const id = prop(item, "id");
      if (typeof id !== "string" || !CVE_RE.test(id)) continue;
      top.push({ id, score: score10(prop(item, "score")) });
      if (top.length >= LOOKUP_IDS) break;
    }
  }
  return {
    tech: lookupStr(prop(e, "tech"), 60),
    version: lookupStr(prop(e, "version"), 30),
    state,
    returned,
    used: Math.min(count(prop(e, "used")), returned, LOOKUP_USED),
    top,
    t: Math.max(0, num(prop(e, "t")) || 0),
  };
}

function readOtx(o) {
  if (!isObj(o)) return null;
  const state = prop(o, "state");
  if (typeof state !== "string" || !OTX_STATES.has(state)) return null;
  const returned = count(prop(o, "returned"));
  const reports = [];
  const raw = prop(o, "reports");
  if (Array.isArray(raw)) {
    for (const r of raw.slice(0, LOOKUP_SCAN)) {
      if (!isObj(r)) continue;
      // a report with no name is still a report: the list agrees with the count
      const title = lookupStr(prop(r, "title"), 120) || "Untitled report";
      const date = prop(r, "date");
      reports.push({ title, date: typeof date === "string" && DATE_RE.test(date) ? date : null });
      if (reports.length >= LOOKUP_REPORTS) break;
    }
  }
  return {
    sector: lookupStr(prop(o, "sector"), 60),
    state,
    returned,
    used: Math.min(count(prop(o, "used")), returned),
    atLeast: prop(o, "at_least") === true,
    reports,
    t: Math.max(0, num(prop(o, "t")) || 0),
  };
}

/** ``deck.lookups`` checked and reshaped, or null when the record has none. */
function readLookups(v) {
  if (!isObj(v)) return null;
  const nvd = [];
  const raw = prop(v, "nvd");
  let extra = 0;
  if (Array.isArray(raw)) {
    for (const e of raw.slice(0, LOOKUP_TECHS)) {
      const entry = readNvd(e);
      if (entry) nvd.push(entry);
    }
    extra = Math.max(0, raw.length - LOOKUP_TECHS);
  }
  const more = Math.min(COUNT_CAP, count(prop(v, "nvd_more")) + extra);
  return { nvd, more, total: readTotals(prop(v, "nvd_total"), nvd, more), otx: readOtx(prop(v, "otx")) };
}

/** Totals over every product, listed or not (``nvd_total``). A record
    without them, or with ones that cannot be true, sums the listed ones. */
function readTotals(v, nvd, more) {
  const listed = { checked: Math.min(COUNT_CAP, nvd.length + more), returned: 0, used: 0, failed: 0, unknown: 0 };
  for (const e of nvd) {
    listed.returned = Math.min(COUNT_CAP, listed.returned + e.returned);
    listed.used = Math.min(COUNT_CAP, listed.used + e.used);
    if (e.state === "failed" || e.state === "unknown") listed[e.state] += 1;
  }
  if (!isObj(v)) return listed;
  const t = {};
  for (const k of NVD_TOTALS) t[k] = count(prop(v, k));
  const fits =
    t.checked >= nvd.length &&
    t.returned >= listed.returned &&
    t.used >= listed.used &&
    t.failed >= listed.failed &&
    t.unknown >= listed.unknown &&
    t.failed + t.unknown <= t.checked;
  if (!fits) return listed;
  t.used = Math.min(t.used, t.returned);
  return t;
}

function techLabel(tech) {
  return tech.id && tech.name ? tech.id + " " + tech.name : tech.id || tech.name;
}
function scoreText(score) {
  return score.risk === null ? "scored" : score.risk.toFixed(2);
}

// ── the feed ────────────────────────────────────────────────────────────

/** Takes polled records, paces what they deliver, and returns view models. */
export function createDeckFeed() {
  const titles = new Map();
  const items = new Map(); // key -> { key, kind, id, t, start, land, instant }
  const pathSeen = new Map(); // threat id -> the record time its path became ready
  let rec = null;
  let status = "queued";
  let error = "";
  let first = true;
  let lastStart = -Infinity;
  let lastView = null;
  let terminalAt = null;
  let anchorT = 0;
  let anchorAt = 0;
  let shownClock = 0;
  let pushGap = 1000;
  let lastPush = null;
  // the connection to the job: "ok", "retrying" (polls are failing and the
  // page is trying again), or "lost" (it gave up; final for this feed)
  let link = "ok";
  let linkMessage = "";
  // add-on stages that failed in the job and were then run again from the
  // results, successfully
  const reruns = new Set();
  let events = [];
  let eventsSig = null;
  let version = 0;
  const typing = { stage: "", text: "", pos: 0, rate: 60 };

  function stage(id) {
    return rec.stageById.get(id) || null;
  }
  function stageStatus(id) {
    const s = stage(id);
    return s ? s.status : "queued";
  }

  /** Every item the record holds now, oldest first. */
  function wanted() {
    const out = [];
    for (const th of rec.threats) out.push({ key: "w" + th.id, kind: "w", id: th.id, t: th.t });
    const add = (kind, map) => {
      for (const [id, v] of map) out.push({ key: kind + id, kind, id, t: v.t });
    };
    add("m", rec.techniques);
    add("f", rec.fixes);
    add("s", rec.scores);
    add("t", rec.tests);
    // A path has no time in the record. It is ready once the builder has moved
    // on to another threat (or finished), and is stamped with the record's
    // time at the first poll that shows it ready.
    const tree = stage("attack_tree");
    const building = tree && tree.status === "working";
    const liveItem = building && rec.live && rec.live.stage === "attack_tree" ? rec.live.item : null;
    for (const id of [...pathSeen.keys()]) if (!rec.steps.has(id)) pathSeen.delete(id);
    for (const [id] of rec.steps) {
      if (!pathSeen.has(id)) {
        if (building && id === liveItem) continue;
        const done = tree && tree.finished !== null ? tree.finished : rec.t;
        pathSeen.set(id, first && !building ? done : rec.t);
      }
      out.push({ key: "p" + id, kind: "p", id, t: pathSeen.get(id) });
    }
    const idx = (it) => rec.byId.get(it.id).index;
    out.sort((a, b) => a.t - b.t || KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || idx(a) - idx(b));
    return out;
  }

  function syncItems(now) {
    const want = wanted();
    const keys = new Set(want.map((w) => w.key));
    for (const key of [...items.keys()]) if (!keys.has(key)) items.delete(key);
    let added = false;
    for (const w of want) {
      const have = items.get(w.key);
      if (have) {
        have.t = w.t;
        continue;
      }
      added = true;
      if (first) {
        items.set(w.key, { ...w, start: now, land: now, instant: true });
        continue;
      }
      let waiting = 0;
      for (const it of items.values()) if (it.start > now) waiting += 1;
      let gap = GAP_MS;
      if (waiting > BACKLOG_FLOOD) gap = (GAP_FLOOR_MS * BACKLOG_FLOOD) / waiting;
      else if (waiting > BACKLOG_HANDFUL) gap = Math.max(GAP_FLOOR_MS, (GAP_MS * BACKLOG_HANDFUL) / waiting);
      const start = Math.max(now, lastStart + gap);
      lastStart = start;
      items.set(w.key, { ...w, start, land: start + FLIGHT_MS, instant: false });
    }
    return added;
  }

  /** The job is over: whatever has not landed does so within DRAIN_MS. */
  function drain(now) {
    const deadline = now + DRAIN_MS;
    const queued = [];
    for (const it of items.values()) {
      if (it.land <= now) continue;
      if (it.start <= now) it.land = Math.min(it.land, deadline);
      else queued.push(it);
    }
    queued.sort((a, b) => a.start - b.start);
    const gap = queued.length ? Math.min(GAP_FLOOR_MS, (DRAIN_MS - DRAIN_FLIGHT_MS) / queued.length) : 0;
    queued.forEach((it, i) => {
      it.start = now + i * gap;
      it.land = it.start + DRAIN_FLIGHT_MS;
    });
    if (queued.length) lastStart = queued[queued.length - 1].start;
  }

  function stageSummary(s) {
    const n = rec.threats.length;
    if (s.id === "stride") return plural(n, "threat", "threats");
    if (s.id === "mitre_map") return rec.techniques.size + " of " + plural(n, "threat", "threats") + " mapped";
    if (s.id === "attack_tree") return plural(rec.links, "link", "links");
    if (s.id === "mitigations") return plural(rec.fixes.size, "fix", "fixes") + " drafted";
    if (s.id === "dread") return plural(rec.scores.size, "threat", "threats") + " scored";
    if (s.id === "test_cases") return plural(rec.tests.size, "test scenario", "test scenarios");
    const lk = rec.lookups;
    if (s.id === "nvd" && lk && lk.total.checked) return nvdSummary(lk, false);
    if (s.id === "otx" && lk && lk.otx) {
      const o = lk.otx;
      if (o.state !== "found" || !o.returned || !o.used) return o.state === "none" || o.state === "found" ? "no public reports matched" : "";
      return fmtN(o.used) + " of " + atLeast(o) + pluralN(o.returned, "public report", "public reports") + " passed on";
    }
    return "";
  }

  function itemLine(it) {
    const th = rec.byId.get(it.id);
    const s = stage(KIND_STAGE[it.kind]);
    const who = s ? s.name : "Agent";
    if (it.kind === "w") return who + ": " + it.id + " written (" + (th.type || COLUMN_NAME.get(th.col)) + ")";
    if (it.kind === "m") return who + ": " + it.id + " → " + techLabel(rec.techniques.get(it.id));
    if (it.kind === "p") return who + ": " + it.id + " linked, " + plural(rec.steps.get(it.id), "attack step", "attack steps");
    if (it.kind === "f") return who + ": fix drafted for " + it.id;
    if (it.kind === "s") return who + ": " + it.id + " scored " + scoreText(rec.scores.get(it.id));
    return who + ": test written for " + it.id;
  }

  /** The whole log, in order, from the record alone. */
  function buildEvents() {
    const ev = [];
    let seq = 0;
    const add = (t, si, rank, kind, text, key) => ev.push({ t, si, rank, seq: seq++, kind, text, key: key || kind + ":" + si });
    for (const s of rec.stages) {
      const at = s.started !== null ? s.started : s.finished !== null ? s.finished : 0;
      const end = s.finished !== null ? s.finished : at;
      if (s.status === "fallback") {
        add(end, s.index, 2, "skip", s.name + " skipped" + (s.reason ? ": " + s.reason : ""));
        continue;
      }
      if (s.status === "queued") continue;
      add(at, s.index, 0, "start", s.name + " started");
      if (s.status === "done") {
        const sum = stageSummary(s);
        add(end, s.index, 2, "finish", s.name + " finished" + (sum ? ": " + sum : ""));
      } else if (s.status === "error") {
        add(Math.max(end, at), s.index, 2, "fail", s.name + " failed" + (s.reason ? ": " + s.reason : ""));
      }
    }
    const lk = rec.lookups;
    if (lk) {
      // what each lookup gave, when it answered: shown at once, never paced
      const within = (s, t) => {
        let at = t;
        if (s.started !== null) at = Math.max(at, s.started);
        if (s.finished !== null) at = Math.min(at, s.finished);
        return at;
      };
      const nvd = stage("nvd");
      if (nvd) {
        lk.nvd.forEach((e, i) => add(within(nvd, e.t), nvd.index, 1, "find", nvd.name + ": " + productName(e) + ", " + nvdLine(e), "lk:nvd:" + i));
        if (lk.more) {
          const at = nvd.finished !== null ? nvd.finished : lk.nvd.length ? lk.nvd[lk.nvd.length - 1].t : 0;
          add(within(nvd, at), nvd.index, 1, "find", nvd.name + ": " + pluralN(lk.more, "more product was", "more products were") + " checked and " + (lk.more === 1 ? "is" : "are") + " not listed", "lk:nvd:more");
        }
      }
      const otx = stage("otx");
      // switched off: the step's own "skipped" line says so
      if (otx && lk.otx && lk.otx.state !== "off") add(within(otx, lk.otx.t), otx.index, 1, "find", otx.name + ": " + otxLine(lk.otx), "lk:otx");
    }
    for (const it of items.values()) {
      const s = stage(KIND_STAGE[it.kind]);
      let t = it.t;
      if (s) {
        if (s.started !== null) t = Math.max(t, s.started);
        if (s.finished !== null) t = Math.min(t, s.finished);
      }
      add(t, s ? s.index : rec.stages.length, 1, "item", itemLine(it), it.key);
    }
    ev.sort((a, b) => a.t - b.t || a.si - b.si || a.rank - b.rank || a.seq - b.seq);
    const sig = ev.map((e) => e.key + "\u0001" + e.t + "\u0001" + e.kind + "\u0001" + e.text).join("\u0002");
    if (sig === eventsSig) return;
    eventsSig = sig;
    events = ev;
    version += 1;
  }

  // Counted the way the rail shows them: when the job has ended, a stage
  // still marked working counts as the rail reads it (done, failed, or
  // stopped), and one still waiting counts as not run.
  function counts() {
    let ran = 0;
    let skipped = 0;
    let failed = 0;
    let notRun = 0;
    const ended = TERMINAL.has(status);
    let rerun = 0;
    for (const s of rec.stages) {
      if (s.status === "done") ran += 1;
      else if (s.status === "fallback") skipped += 1;
      else if (s.status === "error" && reruns.has(s.id)) {
        ran += 1;
        rerun += 1;
      } else if (s.status === "error") failed += 1;
      else if (s.status === "working" && ended) {
        if (status === "complete") ran += 1;
        else if (status === "failed") failed += 1;
        else skipped += 1;
      } else if (s.status === "queued" && ended) notRun += 1;
    }
    return { ran, skipped, failed, notRun, rerun };
  }
  function countsText() {
    const c = counts();
    return (
      plural(c.ran, "stage ran", "stages ran") +
      (c.rerun ? " (" + c.rerun + " run again)" : "") +
      ", " + c.skipped + " skipped" +
      (c.failed ? ", " + c.failed + " failed" : "") +
      (c.notRun ? ", " + c.notRun + " not run" : "")
    );
  }

  function finalClock() {
    let t = rec.t;
    for (const s of rec.stages) if (s.finished !== null && s.finished > t) t = s.finished;
    return t;
  }

  /** Take one polled record. ``now`` is when it arrived, in milliseconds. */
  function push(progress, jobStatus, jobError, now) {
    const deck = isDeckProgress(progress);
    if (!deck && !rec) return false;
    if (deck) rec = normalize(progress, titles);
    if (JOB_STATUS.has(jobStatus)) status = jobStatus;
    error = TERMINAL.has(status) && status !== "complete" ? str(jobError, 600) : "";
    if (lastPush !== null) pushGap = clamp(now - lastPush, 400, 4000);
    lastPush = now;
    if (first || rec.t > anchorT) {
      anchorT = rec.t;
      anchorAt = now;
    }
    const added = deck ? syncItems(now) : false;
    if (TERMINAL.has(status)) {
      if (terminalAt === null) {
        terminalAt = now;
        drain(now);
      } else if (added) drain(now);
    } else terminalAt = null;

    // What the working agent is writing: keep the place when it continues.
    const live = TERMINAL.has(status) ? null : rec.live;
    const text = readableLive(live);
    const liveStage = live ? live.stage : "";
    typing.pos = liveStage === typing.stage ? retarget(typing.text, text, typing.pos) : 0;
    typing.stage = liveStage;
    typing.text = text;
    typing.rate = Math.max(40, (text.length - typing.pos) / (pushGap / 1000) / 0.9);

    buildEvents();
    if (deck) first = false;
    return true;
  }

  function lastLanded(kind, landed) {
    let best = null;
    for (const it of items.values()) {
      if (it.kind === kind && landed.has(it.key) && (!best || it.land > best.land || (it.land === best.land && it.t >= best.t))) best = it;
    }
    return best ? best.id : null;
  }

  function buildWork(s, landed, nLanded, body, cursor) {
    const live = rec.live && rec.live.stage === s.id ? rec.live : null;
    const item = live ? live.item : null;
    const th = item ? rec.byId.get(item) : null;
    const n = rec.threats.length;
    const w = { stage: s.id, head: "", sub: "", body: "", cursor: false, rows: [], target: null };
    const typed = () => {
      w.body = body;
      w.cursor = cursor;
    };
    const subject = () => (item ? item + (th && th.title ? " · " + th.title : "") : "");
    if (s.id === "stride") {
      const field = live && live.field ? own(FIELD_LABEL, live.field) || "" : "";
      if (live && live.field === "Recommendations" && !item) w.head = "Writing recommendations";
      else w.head = "Writing threat " + (th ? th.index + 1 : n + 1) + (field ? " · " + field : "");
      if (item) w.sub = item + " · " + (th ? th.type || COLUMN_NAME.get(th.col) : COLUMN_NAME.get(columnForId(item)));
      typed();
      if (!w.body) w.cursor = true;
      const sent = lastLanded("w", landed);
      if (sent) w.rows.push({ k: "Sent to the board:", v: sent });
      if (item && !landed.has("w" + item)) w.target = { card: item, writing: true };
    } else if (s.id === "mitre_map") {
      w.head = "Mapping threat " + (th ? th.index + 1 : Math.min(n, nLanded.m + 1)) + " of " + n;
      w.sub = subject();
      const done = [...items.values()].filter((it) => it.kind === "m" && landed.has(it.key)).sort((a, b) => a.land - b.land || a.t - b.t);
      for (const it of done.slice(-2)) w.rows.push({ k: it.id + " →", v: techLabel(rec.techniques.get(it.id)) });
      if (item && landed.has("w" + item)) w.target = { card: item };
    } else if (s.id === "attack_tree") {
      w.head = "Linking attack paths · " + plural(rec.links, "link", "links");
      w.sub = item ? subject() : rec.root ? "Root: " + rec.root : "";
      typed();
      if (live) for (const label of treeLive(live.text).done.slice(-2)) w.rows.push({ k: "└", v: label });
      if (item && landed.has("w" + item)) w.target = { card: item };
      else if (rec.root) w.target = { root: true };
    } else if (s.id === "mitigations") {
      w.head = "Drafting fix " + Math.min(Math.max(n, 1), nLanded.f + 1) + " of " + n;
      w.sub = subject();
      typed();
      const last = lastLanded("f", landed);
      if (last) w.rows.push({ k: "Fix drafted:", v: last });
      if (item && landed.has("w" + item)) w.target = { card: item };
    } else if (s.id === "dread") {
      w.head = "Scoring threat " + Math.min(Math.max(n, 1), nLanded.s + 1) + " of " + n;
      w.sub = item ? "Now scoring " + item : "";
      const last = lastLanded("s", landed);
      const sc = last ? rec.scores.get(last) : null;
      if (sc) {
        w.rows.push({ k: "Just scored", v: last + ": risk " + scoreText(sc) });
        const cell = (j) => AXES[j][1] + " " + (sc.axes[j] === null ? "?" : sc.axes[j]);
        w.rows.push({ k: "", v: [0, 1, 2].map(cell).join(" · "), dim: true });
        w.rows.push({ k: "", v: [3, 4].map(cell).join(" · "), dim: true });
      }
      if (item && landed.has("w" + item)) w.target = { card: item };
    } else if (s.id === "test_cases") {
      w.head = "Writing test " + Math.min(Math.max(n, 1), nLanded.t + 1) + " of " + n;
      w.sub = subject();
      typed();
      const last = lastLanded("t", landed);
      if (last) w.rows.push({ k: "Test written:", v: last });
      if (item && landed.has("w" + item)) w.target = { card: item };
    } else if (s.id === "serialize") {
      w.head = "Reading the system description";
      w.body = s.detail || "Profile and technology list.";
    } else if (s.id === "nvd") {
      w.head = "Looking up known vulnerabilities";
      const lk = rec.lookups;
      // with lookups, only the current check is shown: a one-number summary
      // line ("X: found 10 CVEs") gives way to the two numbers below
      const summaryLine = lk && !s.detail.startsWith("Checking ");
      w.body = (summaryLine ? "" : s.detail) || "Checking the selected technologies.";
      // the current check holds to one line, so the result below keeps its room
      if (lk) w.oneLine = true;
      const last = lk && lk.nvd.length ? lk.nvd[lk.nvd.length - 1] : null;
      if (last) {
        // keep: the two numbers are never dropped to make room
        w.rows.push({ k: productName(last) + ":", v: nvdLine(last), keep: true });
        if ((last.state === "found" || last.state === "none") && last.top.length) {
          const shown = last.top.slice(0, 3).map((i) => i.id);
          const rest = last.used - shown.length;
          // spare: the first row to go when the panel is short (the two numbers stay)
          w.rows.push({ k: "", v: shown.join(", ") + (rest > 0 ? " and " + rest + " more" : ""), dim: true, spare: true });
        }
      }
    } else if (s.id === "otx") {
      w.head = "Checking threat intelligence";
      w.body = s.detail || "Reading sector threat reports.";
    } else if (s.id === "mitre_load") {
      w.head = "Loading the technique catalog";
      w.body = "MITRE ATT&CK catalog, used by the mapper next.";
    } else if (s.id === "markdown") {
      w.head = "Assembling the report tables";
      w.body = "Formatting tables for " + plural(n, "threat", "threats") + ".";
    } else {
      w.head = s.name;
      w.body = s.detail;
    }
    return w;
  }

  /** The view model at ``now``. ``opts.motion`` false: no packets, no typing. */
  /** Say how polling is going: "ok", "retrying", or "lost", with the one
      sentence to show. Once lost, the feed stays lost. */
  /** Everything the record holds about one threat, as label and text rows,
      for the reader who opens a card. Rows the record does not
      have are left out. Null for an id the record does not hold. */
  function detail(id) {
    if (!rec || typeof id !== "string" || !rec.byId.has(id)) return null;
    const th = rec.byId.get(id);
    const rows = [];
    if (th.scenario) rows.push({ k: "Scenario", v: th.scenario });
    const tech = rec.techniques.get(id);
    if (tech && (tech.id || tech.name)) rows.push({ k: "Technique", v: techLabel(tech) });
    const fix = rec.fixes.get(id);
    if (fix && fix.text) rows.push({ k: "Fix", v: fix.text });
    const test = rec.tests.get(id);
    if (test && test.title) rows.push({ k: "Test", v: test.title });
    const sc = rec.scores.get(id);
    if (sc && sc.risk !== null) {
      const axes = AXES.map(([, name], j) => (sc.axes[j] === null ? "" : name + " " + sc.axes[j])).filter(Boolean);
      rows.push({ k: "Risk score", v: scoreText(sc) + (axes.length ? " (" + axes.join(", ") + ")" : "") });
    }
    return { id, title: id + " · " + (th.type || COLUMN_NAME.get(th.col)), rows };
  }

  /** What a lookup agent found, for its detail list: a title, the fixed
      note, and label and text rows. NVD rows carry each kept id (with its
      link); OTX rows carry each report. Null when nothing has answered. */
  function lookupDetail(stageId) {
    if (!rec || !rec.lookups || typeof stageId !== "string") return null;
    const lk = rec.lookups;
    const s = stage(stageId);
    const name = (s && s.name) || "";
    const term = (s && s.term) || "";
    const title = name && term ? name + " · " + term : name || term;
    if (stageId === "nvd") {
      if (!lk.nvd.length && !lk.more) return null;
      const rows = lk.nvd.map((e) => {
        const links = e.state === "found" ? e.top.map((i) => ({ id: i.id, score: i.score, href: nvdLink(i.id), text: i.id + (i.score === null ? "" : " (" + i.score.toFixed(1) + ")") })) : [];
        // "and N more" only follows ids it can count on from (the line above already gives the number)
        const more = links.length && e.used > links.length ? "and " + fmtN(e.used - links.length) + " more passed on" : "";
        return { kind: "tech", k: productName(e), v: nvdLine(e, TO_WRITER) + ".", links, more };
      });
      if (lk.more) {
        // what the products past the list came to, from the totals
        let failed = lk.total.failed;
        let unknown = lk.total.unknown;
        for (const e of lk.nvd) {
          if (e.state === "failed") failed -= 1;
          else if (e.state === "unknown") unknown -= 1;
        }
        const of = [];
        if (failed > 0) of.push(fmtN(failed) + " did not finish");
        if (unknown > 0) of.push(fmtN(unknown) + " had no entry in NVD");
        const v = pluralN(lk.more, "more product was", "more products were") + " checked" + (of.length ? "; of " + (lk.more === 1 ? "it" : "those") + ", " + of.join(" and ") : "") + ".";
        rows.push({ kind: "more", k: "Not listed", v });
      }
      return { id: "lk:nvd", stage: "nvd", title: title || "NVD", note: NVD_NOTE, rows };
    }
    if (stageId === "otx") {
      const o = lk.otx;
      if (!o) return null;
      const rows = [];
      if (o.sector) rows.push({ kind: "info", k: "Sector", v: o.sector });
      let sum;
      if (o.state === "failed" || o.state === "off") sum = otxLine(o) + ".";
      else if (o.state === "none" || !o.returned) sum = "No public reports matched.";
      else sum = otxLine({ ...o, sector: "" }, TO_WRITER) + ".";
      sum = sum.charAt(0).toUpperCase() + sum.slice(1);
      rows.push({ kind: "info", k: "Reports", v: sum });
      for (const r of o.reports) rows.push({ kind: "report", k: r.date || "No date", v: r.title });
      return { id: "lk:otx", stage: "otx", title: title || "OTX", note: OTX_NOTE, rows };
    }
    return null;
  }

  /** An add-on stage that failed in the job was run again from the results
      and succeeded. Only a failed add-on stage of a finished job counts. */
  function markRerun(stageId) {
    if (!rec || !TERMINAL.has(status) || !Object.hasOwn(STAGE_KIND, stageId) || stageId === "mitre_map") return false;
    const s = rec.stageById.get(stageId);
    if (!s || s.status !== "error") return false;
    reruns.add(stageId);
    return true;
  }

  function setLink(mode, message, now) {
    if (link === "lost" || !LINK_MODES.has(mode)) return false;
    link = mode;
    linkMessage = mode === "ok" ? "" : str(message, 300);
    if (mode === "lost" && typeof now === "number") {
      // what the last record held is shown at once: nothing is left in flight
      for (const it of items.values()) {
        if (it.land > now) {
          it.start = now;
          it.land = now;
          it.instant = true;
        }
      }
    }
    return true;
  }

  function view(now, opts) {
    if (!rec) return null;
    const terminal = TERMINAL.has(status);
    const lost = link === "lost" && !terminal;
    const retrying = link === "retrying" && !terminal;
    const motion = (!opts || opts.motion !== false) && !lost;
    // No tick for a while (hidden tab, another step): show the true state now.
    if (lastView === null || now - lastView > REATTACH_GAP_MS) {
      for (const it of items.values()) {
        if (it.land > now) {
          it.start = now;
          it.land = now;
          it.instant = true;
        }
      }
      lastStart = Math.min(lastStart, now);
    }
    const dt = lastView === null ? 0 : Math.max(0, now - lastView) / 1000;

    const landed = new Set();
    const nLanded = { w: 0, m: 0, p: 0, f: 0, s: 0, t: 0 };
    const flights = [];
    const justLanded = [];
    let pending = 0;
    for (const it of items.values()) {
      if (it.land <= now) {
        landed.add(it.key);
        nLanded[it.kind] += 1;
        if (!it.instant && (lastView === null || it.land > lastView)) justLanded.push({ key: it.key, kind: it.kind, id: it.id, stage: KIND_STAGE[it.kind] });
      } else {
        pending += 1;
        if (motion && it.start <= now) {
          flights.push({ key: it.key, kind: it.kind, id: it.id, stage: KIND_STAGE[it.kind], u: clamp((now - it.start) / (it.land - it.start), 0, 1) });
        }
      }
    }

    // clock
    let clock;
    if (terminal) clock = finalClock();
    else if ((status === "queued" || status === "idle") && rec.t === 0) clock = 0;
    else if (lost) clock = shownClock;
    else {
      // between polls the clock runs on from the last record, but never more
      // than CLOCK_LEAD_S past the last poll that answered
      const run = anchorT + Math.max(0, now - anchorAt) / 1000;
      const cap = lastPush === null ? run : anchorT + Math.max(0, lastPush - anchorAt) / 1000 + CLOCK_LEAD_S;
      clock = Math.max(shownClock, Math.min(run, cap));
    }
    shownClock = clock;

    // typing
    if (!motion) typing.pos = typing.text.length;
    else typing.pos = Math.min(typing.text.length, typing.pos + typing.rate * Math.min(dt, 0.25));
    const typedText = typing.text.slice(0, Math.floor(typing.pos));
    const typingLive = motion && typing.pos < typing.text.length;

    // stages
    let cur = -1;
    let lastTouched = -1;
    const stageFrac = (s) => {
      const n = rec.threats.length;
      const kind = own(STAGE_KIND, s.id);
      return kind && n ? clamp(nLanded[kind] / n, 0, 1) : null;
    };
    const stages = rec.stages.map((s) => {
      let state = { queued: "waiting", working: "working", done: "done", fallback: "skipped", error: "failed" }[s.status];
      let label = { waiting: "Waiting", working: "Working", done: "Done", skipped: "Skipped", failed: "Failed" }[state];
      let reason = state === "skipped" || state === "failed" ? s.reason : "";
      let dur = "";
      let frac = state === "done" || state === "failed" ? 1 : 0;
      if (s.status !== "queued") lastTouched = s.index;
      if (s.status === "error" && reruns.has(s.id)) {
        state = "done";
        label = "Done";
        reason = RERUN_REASON;
        frac = 1;
      }
      if (state === "working" && terminal) {
        // The job ended with this stage still marked working.
        if (status === "failed") {
          state = "failed";
          label = "Failed";
          reason = "The run stopped here";
        } else if (status === "cancelled") {
          state = "skipped";
          label = "Stopped";
          reason = "The run was cancelled";
        } else {
          state = "done";
          label = "Done";
        }
        frac = status === "complete" ? 1 : 0;
      } else if (state === "working") {
        if (cur < 0) cur = s.index;
        if (s.started !== null) dur = fmtDur(clock - s.started);
        frac = stageFrac(s);
      } else if (state === "done" && s.started !== null && s.finished !== null) {
        dur = fmtDur(s.finished - s.started);
      } else if (state === "waiting" && terminal) {
        label = "Not run";
      }
      const out = { id: s.id, name: s.name, term: s.term, phase: s.phase, state, label, dur, reason, frac };
      if (rec.lookups && LOOKUP_STAGES.includes(s.id)) {
        out.note = state === "done" ? lookupNote(s.id, rec.lookups) : "";
        // the short source name goes before a result, so the line fits
        if (out.note) out.noteTerm = s.id === "otx" ? "OTX" : s.term;
      }
      return out;
    });
    if (lost) {
      // no contact: nothing is shown as working any more
      for (const st of stages) {
        if (st.state !== "working") continue;
        st.state = "skipped";
        st.label = "Stopped";
        st.dur = "";
        st.frac = 0;
      }
      cur = -1;
    }
    const total = stages.length;
    const shownStep = cur >= 0 ? cur : lastTouched;

    // work panel
    const work = !terminal && cur >= 0 ? buildWork(rec.stages[cur], landed, nLanded, windowed(typedText, 150), typingLive) : null;

    // board
    const n = rec.threats.length;
    const stride = stageStatus("stride");
    const mapper = stageStatus("mitre_map");
    const treeSt = stageStatus("attack_tree");
    const addon = { f: stageStatus("mitigations"), s: stageStatus("dread"), t: stageStatus("test_cases") };
    const gone = (st) => st === "fallback" || st === "error";
    const mark = (kind, id, onText, idleText, noneText) => {
      const st = kind === "p" ? treeSt : addon[kind];
      if (landed.has(kind + id)) return { on: true, text: onText };
      if (gone(st)) return null;
      const settled = st === "done" && !items.has(kind + id);
      return { on: false, text: settled ? noneText : idleText };
    };
    const cols = new Map(COLUMNS.map((c) => [c.key, { key: c.key, name: c.name, cards: [] }]));
    const colOf = (key) => {
      if (!cols.has(key)) cols.set(key, { key: OTHER.key, name: OTHER.name, cards: [] });
      return cols.get(key);
    };
    const target = work ? work.target : null;
    for (const th of rec.threats) {
      const on = landed.has("w" + th.id);
      const tech = rec.techniques.get(th.id);
      const sc = rec.scores.get(th.id);
      const steps = rec.steps.get(th.id) || 0;
      let chip;
      if (tech && landed.has("m" + th.id)) chip = { on: true, id: tech.id, name: tech.name, text: techLabel(tech) };
      else if (!tech && RESOLVED.has(mapper)) chip = { on: false, id: "", name: "", text: "no technique matched" };
      else chip = { on: false, id: "", name: "", text: "technique" };
      colOf(th.col).cards.push({
        id: th.id,
        landed: on,
        incoming: !on,
        ghost: "",
        title: th.title,
        scenario: th.scenario,
        chip,
        score: mark("s", th.id, sc ? scoreText(sc) : "", "score", "no score"),
        path: mark("p", th.id, plural(steps, "step", "steps"), "path", "no path"),
        fix: mark("f", th.id, "✓ fix", "fix", "no fix"),
        test: mark("t", th.id, "✓ test", "test", "no test"),
        focus: !!(target && !target.writing && target.card === th.id && on),
        linked: landed.has("p" + th.id),
      });
    }
    if (target && target.writing && !rec.byId.has(target.card)) {
      colOf(columnForId(target.card)).cards.push({
        id: target.card, landed: false, incoming: true, ghost: "Writing threat " + (n + 1) + "…", title: "", scenario: "",
        chip: { on: false, id: "", name: "", text: "technique" }, score: null, path: null, fix: null, test: null, focus: false, linked: false,
      });
    }
    const columns = [...cols.values()];
    const rows = Math.max(3, ...columns.map((c) => c.cards.length));
    const used = columns.filter((c) => c.cards.some((card) => card.landed)).length;
    let countText;
    if (status === "idle") countText = "";
    else if (stride === "done" || terminal) countText = plural(nLanded.w, "threat", "threats") + " in " + plural(used, "category", "categories");
    else countText = plural(nLanded.w, "threat", "threats") + " so far";
    const treeStarted = treeSt !== "queued" && treeSt !== "fallback" && (rec.links > 0 || !!rec.root);
    const board = {
      columns,
      rows,
      compact: rows > 3,
      countText,
      rootText: treeStarted && rec.root ? "Attack tree root: " + rec.root : "",
      tree: { started: treeStarted, active: treeSt === "working" && !terminal },
    };

    // tally
    const known = RESOLVED.has(stride) || terminal;
    const tallyRow = (key, label, stageId, kind) => {
      const st = stageStatus(stageId);
      const s = stage(stageId);
      const row = { key, label, phase: s ? s.phase : "model", n: nLanded[kind], total: known ? n : null, text: "", off: false };
      const addOn = kind === "f" || kind === "s" || kind === "t";
      if (addOn && st === "error" && reruns.has(stageId)) {
        // run again from the results: the deck has no count for that run
        row.text = "run again";
        row.plain = true;
      } else if (addOn && st === "fallback") {
        row.text = "skipped";
        row.off = true;
      } else if (addOn && st === "error") {
        row.text = "failed";
        row.off = true;
      } else row.text = known ? row.n + " of " + n : String(row.n);
      return row;
    };
    const linkRow = { key: "link", label: "Attack tree links", phase: "model", n: treeSt === "queued" ? 0 : rec.links, total: null, text: "", off: false, plain: true };
    linkRow.text = String(linkRow.n);
    const tallyRows = [
      tallyRow("w", "Threats written", "stride", "w"),
      tallyRow("m", "Techniques mapped", "mitre_map", "m"),
      linkRow,
      tallyRow("f", "Fixes drafted", "mitigations", "f"),
      tallyRow("s", "Risk scores", "dread", "s"),
      tallyRow("t", "Tests written", "test_cases", "t"),
    ];
    const notes = [];
    const um = rec.unmatched;
    const loose = [];
    if (um.fixes) loose.push(plural(um.fixes, "fix", "fixes"));
    if (um.scores) loose.push(plural(um.scores, "score", "scores"));
    if (um.tests) loose.push(plural(um.tests, "test", "tests"));
    if (um.tree) loose.push(plural(um.tree, "attack path", "attack paths"));
    if (loose.length) {
      const list = loose.length > 2 ? loose.slice(0, -1).join(", ") + ", and " + loose[loose.length - 1] : loose.join(" and ");
      notes.push(list + " did not match a threat");
    }
    if (rec.truncated) notes.push("More than 200 threats were written; the first 200 are shown");

    // log: everything up to the first item that has not landed yet
    let shown = 0;
    while (shown < events.length && (events[shown].kind !== "item" || landed.has(events[shown].key))) shown += 1;
    const drained = pending === 0;
    let endEvent = null;
    if (terminal && drained) {
      if (status === "complete") endEvent = { t: clock, kind: "end", text: "Run finished: " + countsText(), key: "end" };
      else if (status === "failed") endEvent = { t: clock, kind: "fail", text: "Run failed" + (error ? ": " + error : ""), key: "end" };
      else endEvent = { t: clock, kind: "skip", text: "Run cancelled", key: "end" };
    }

    // summary
    let summary = null;
    const c = counts();
    if (lost) summary = { tone: "fail", title: "Stopped", text: "", top: null, error: linkMessage };
    else if (terminal && drained) {
      if (status === "complete") {
        let top = null;
        for (const [id, sc] of rec.scores) if (sc.risk !== null && (!top || sc.risk > top.risk)) top = { id, risk: sc.risk, text: scoreText(sc) };
        let text = countsText() + ".";
        for (const id of LOOKUP_STAGES) {
          const s = stage(id);
          if (rec.lookups && s && s.status === "error") text += " " + s.name + " failed" + (s.reason ? ": " + s.reason : ".");
        }
        summary = { tone: c.failed ? "warn" : "ok", title: "Run finished in " + fmtClock(clock), text, top, error: "" };
      } else if (status === "failed") {
        summary = { tone: "fail", title: "Run failed at " + fmtClock(clock), text: "", top: null, error: error || "The run did not finish." };
      } else {
        summary = { tone: "warn", title: "Run cancelled at " + fmtClock(clock), text: "This run was stopped before it finished.", top: null, error: "" };
      }
    }

    // step, progress, status line
    let stepText;
    let stepName;
    if (status === "complete") {
      stepText = "Finished";
      stepName = countsText();
    } else if (status === "failed") {
      stepText = "Failed";
      // the stage that stopped the run is the last one that failed (an
      // earlier lookup may have failed without stopping it)
      // a lookup step that failed by itself (with its own reason) did not
      // stop the run, so it is never the one named
      const bad = [...stages].reverse().find((s) => s.state === "failed" && !(LOOKUP_STAGES.includes(s.id) && LOOKUP_OWN_FAILURE.has(s.reason)));
      stepName = bad ? bad.name : "The run did not finish";
    } else if (status === "cancelled") {
      stepText = "Cancelled";
      stepName = shownStep >= 0 ? "stopped at " + stages[shownStep].name : "before it started";
    } else if (lost) {
      stepText = "Stopped";
      stepName = "this page stopped following the run";
    } else if (status === "idle") {
      stepText = "Ready";
      stepName = plural(total, "agent", "agents") + " waiting";
    } else if (shownStep < 0) {
      stepText = "Starting";
      stepName = plural(total, "step", "steps");
    } else {
      stepText = "Step " + (shownStep + 1) + " of " + total;
      stepName = stages[shownStep].name + (stages[shownStep].state === "skipped" ? " (skipped)" : "");
    }
    let resolved = 0;
    for (const s of stages) {
      if (s.state === "done" || s.state === "skipped" || s.state === "failed") resolved += 1;
      else if (s.state === "working" && s.frac !== null) resolved += s.frac * 0.999;
    }
    const progress = status === "complete" ? 1 : total ? clamp(resolved / total, 0, 1) : 0;
    const threatsText = known ? plural(nLanded.w, "threat", "threats") : plural(nLanded.w, "threat", "threats") + " so far";
    let statusLine;
    if (status === "complete") statusLine = "Finished. " + countsText() + ". " + threatsText + ".";
    else if (status === "failed") statusLine = "The run failed" + (error ? ": " + error : ".");
    else if (status === "cancelled") statusLine = "The run was cancelled.";
    else if (status === "idle") statusLine = "";
    else if (lost) statusLine = linkMessage;
    else if (retrying) statusLine = linkMessage;
    else statusLine = stepText + ", " + stepName + ", " + threatsText;

    // each lookup step's result, said once by the status line (the view
    // keeps the keys it has said); both can resolve in one poll
    const announce = [];
    const lookupStages = [];
    if (rec.lookups) {
      for (const id of LOOKUP_STAGES) {
        const s = stage(id);
        if (!s) continue;
        if ((id === "nvd" && (rec.lookups.nvd.length || rec.lookups.more)) || (id === "otx" && rec.lookups.otx)) lookupStages.push(id);
        if (s.status === "error") announce.push({ key: id, text: s.name + " failed" + (s.reason ? ": " + s.reason : ".") });
        else if (s.status === "done" && id === "nvd" && rec.lookups.total.checked) {
          announce.push({ key: id, text: s.name + " finished: " + nvdSummary(rec.lookups, true) + "." });
        } else if (s.status === "done" && id === "otx" && rec.lookups.otx) {
          announce.push({ key: id, text: s.name + " finished: " + otxLine(rec.lookups.otx) + "." });
        }
      }
    }

    lastView = now;
    return {
      status,
      terminal,
      failed: status === "failed",
      cancelled: status === "cancelled",
      error,
      clock,
      clockText: fmtClock(clock),
      stepText,
      stepName,
      statusLine,
      // a finished run whose queue has drained gets a new key, so its final
      // line (with every threat counted) is written once more
      statusKey: lost ? "lost" : status + ":" + shownStep + (terminal && drained ? ":end" : "") + (retrying ? ":retrying" : "") + (c.rerun ? ":rerun" + c.rerun : ""),
      link: terminal ? "ok" : link,
      linkText: retrying || lost ? linkMessage : "",
      progress,
      stages,
      cur,
      work,
      board,
      flights,
      justLanded,
      tally: { rows: tallyRows, notes },
      log: { events, shown, version, end: endEvent },
      summary,
      announce,
      lookupStages,
      failedStages: c.failed,
      rerunStages: c.rerun,
      pending,
      drained,
      typing: typingLive,
      // nothing left to animate: the run is over, or it has not started
      idle: lost || (drained && !typingLive && (terminal || ((status === "idle" || status === "queued") && cur < 0))),
    };
  }

  /** When each item starts its flight and lands (for tests and the harness). */
  function schedule() {
    return [...items.values()].map((it) => ({ key: it.key, kind: it.kind, id: it.id, t: it.t, start: it.start, land: it.land, instant: it.instant }));
  }

  return { push, view, schedule, setLink, markRerun, detail, lookupDetail };
}
