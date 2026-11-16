"""Headless browser checks of the running app in mock mode.

    python tools/browser_check.py [--out DIR] [--only pages,wizard,...] [--sizes 1440x900]

It starts the app with ``AEGIS_MOCK_LLM=1`` on a free local port through
``tools/mock_entry.py`` (the real app with every outside source stubbed, so
nothing leaves the machine), drives Chromium through Playwright, and writes
screenshots and ``readings.json`` to ``--out`` (default
``build/browser_check`` in the repo). Install the browser once with
``python -m playwright install chromium``.

Checks (``--only`` picks some; each runs at every size in ``--sizes``):

- ``pages``: every page in the navigation loads with no console errors.
- ``deck``: a linear run first in a fresh session: one deck mount from the
  idle preview to the results, full width with the sidebar collapsed, one
  scroll, nothing under the sidebar control, and the page bottom in reach.
- ``wizard``: an agentic run in the office, then a linear run in the deck in
  the same session: mounts, animation loops, the longest frame gap, moves of
  the main scroller, where the live view sits, the deck's styling after the
  swap, and that the results appear; then every threat-model export
  downloads (at the first size).
- ``reload``: a linear run reloaded while it runs (a new session): the
  page picks the job up from ``?run=`` and shows its results, the parameter
  is gone once the run settles, and the old link then opens no run.
- ``lookup``, ``policy``, ``pcap``: one job of each kind runs to a saved
  result and its downloads work. The capture check uses the real ``tshark``
  when it is on PATH, otherwise the test suite's fake one (readings say which).
- ``scan``: an AI workflow scan of a typed system prompt runs to a saved record with the simulated
  stand-in, through the test suite's fake garak unless ``AEGIS_GARAK_PYTHON``
  names a real one (readings say which); its progress, results, an attempt,
  and the record download are checked.
- ``layout``: the dashboard columns, the detail page heading, and the fixed
  sidebar control over scrolled content.
- ``atlas``: a linear run for an AI system (application type "AI/ML
  Systems"): the results name the tab "MITRE ATT&CK and ATLAS", the MITRE
  ATLAS block has one row per threat, and every technique, mitigation, and
  case study link in it has the atlas.mitre.org form.
- ``brand``: in a light and a dark browser color scheme, the sidebar shield
  matches the page's theme (white artwork on a dark page, navy on a light
  one), and the tab icon is the brand favicon.
- ``settings``: in mock mode, the Settings page says mock mode is on and its
  provider and model controls are disabled.
- ``providers``: a second server outside mock mode through
  ``tools/provider_entry.py``, where every provider's model list is faked.
  For each of Claude, Amazon Bedrock, OpenAI, and Gemini it fills the
  credential fields, waits for the model select box to fill, picks a model,
  and checks the page names the provider and model in use and never shows a
  credential; then one policy runs (answered by the canned mock) and its
  result names the provider and model, and one workflow scan with the real
  model runs through the same choice (fake garak unless
  ``AEGIS_GARAK_PYTHON`` is set) and its record names them.

Exit status is 1 when any reading breaks its rule.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, Locator, Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "build" / "browser_check"
SIZES = {"1440x900": (1440, 900), "1024x700": (1024, 700)}
LOOKUP_PASTE = "nginx 1.25.3\nOpenSSL/3.0.13\nPostgreSQL 16.4.0\nAcme widget 1.0.0\nRedis"
CAPTURE = ROOT / "tests" / "aegisshield" / "services" / "fixtures" / "minimal.pcap"

# Installed before any page script runs: listeners added to and removed from
# document and window, live ResizeObservers, and a frame loop of its own for
# the longest page frame gap and every move of the main scroller.
PAGE_PROBE = """
(() => {
  const L = { doc: 0, win: 0, roLive: 0 };
  window.__listeners = L;
  const add = EventTarget.prototype.addEventListener;
  const rem = EventTarget.prototype.removeEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    if (this === document) L.doc += 1; else if (this === window) L.win += 1;
    return add.call(this, type, fn, opts);
  };
  EventTarget.prototype.removeEventListener = function (type, fn, opts) {
    if (this === document) L.doc -= 1; else if (this === window) L.win -= 1;
    return rem.call(this, type, fn, opts);
  };
  const RO = window.ResizeObserver;
  if (RO) {
    window.ResizeObserver = class extends RO {
      constructor(cb) { super(cb); L.roLive += 1; this.__live = true; }
      disconnect() { if (this.__live) { L.roLive -= 1; this.__live = false; } return super.disconnect(); }
    };
  }
  const p = { sampling: false, frames: 0, maxGapMs: 0, scrollMoves: [], lastScroll: null };
  window.__pageProbe = p;
  let last = 0;
  function tick(ts) {
    if (p.sampling) {
      if (last) p.maxGapMs = Math.max(p.maxGapMs, ts - last);
      last = ts;
      p.frames += 1;
      const main = document.querySelector('[data-testid="stMain"]');
      const y = main ? main.scrollTop : window.scrollY;
      if (p.lastScroll !== null && Math.abs(y - p.lastScroll) >= 1) {
        p.scrollMoves.push({ from: Math.round(p.lastScroll), to: Math.round(y), at: Math.round(ts) });
      }
      p.lastScroll = y;
    } else last = 0;
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
"""

COUNTERS = """() => {
  const pick = (o, keys) => Object.fromEntries(keys.map((k) => [k, (o || {})[k] ?? 0]));
  return {
    deck: pick(window.__aegisDeck, ["calls", "mounts", "frames", "maxGapMs"]),
    office: pick(window.__aegisOffice, ["calls", "mounts", "chainStarts", "cancels", "ends", "frames", "maxGapMs"]),
    listeners: { ...(window.__listeners || {}) },
    page: { frames: window.__pageProbe.frames, maxGapMs: Math.round(window.__pageProbe.maxGapMs),
            scrollMoves: window.__pageProbe.scrollMoves.slice() },
    roots: { deck: document.querySelectorAll('.aegis-deck-root').length,
             office: document.querySelectorAll('.aegis-office-root').length },
  };
}"""

# Where the live view sits in the viewport, and the main scroller's offset.
LIVE_VIEW = """() => {
  const el = document.querySelector('.aegis-deck-root, .aegis-office-root');
  const main = document.querySelector('[data-testid="stMain"]');
  if (!el) return null;
  const r = el.getBoundingClientRect();
  return { top: Math.round(r.top), bottom: Math.round(r.bottom), height: Math.round(r.height),
           viewport: window.innerHeight, scrollTop: main ? Math.round(main.scrollTop) : null };
}"""

# The deck is styled when its board lays out as the deck's flex row; an
# unstyled deck (the shared-key failure) renders as plain block text.
DECK_STYLE = """() => {
  const board = document.querySelector('.aegis-deck-root .dk-board');
  const root = document.querySelector('.aegis-deck-root');
  return { board: board ? getComputedStyle(board).display : null,
           height: root ? Math.round(root.getBoundingClientRect().height) : null };
}"""

RESULTS_SHOWN = """() => !!Array.from(document.querySelectorAll('[role=tab]'))
  .find((t) => t.textContent.trim() === 'STRIDE findings')"""

# Tiles of a stat row grouped by the row they sit on.
TILE_ROWS = """(selector) => {
  const rows = {};
  for (const t of document.querySelectorAll(selector)) {
    const r = t.getBoundingClientRect();
    if (!r.width) continue;
    const key = Math.round(r.top);
    (rows[key] = rows[key] || []).push(Math.round(r.height));
  }
  return Object.keys(rows).sort((a, b) => a - b).map((k) => rows[k]);
}"""

# Text in the main area drawn under the fixed sidebar control (logo and
# expand button) at the top left, after the page has been scrolled.
UNDER_CONTROL = """() => {
  const parts = ['[data-testid="stSidebarCollapsedControl"]', '[data-testid="stExpandSidebarButton"]',
                 '[data-testid="stHeaderLogo"]', '[data-testid="stLogo"]']
    .flatMap((s) => Array.from(document.querySelectorAll(s)))
    .filter((e) => !e.closest('[data-testid="stSidebar"]'))
    .map((e) => e.getBoundingClientRect()).filter((r) => r.width && r.height);
  if (!parts.length) return { control: null, hits: [] };
  const box = { left: Math.min(...parts.map((r) => r.left)), top: Math.min(...parts.map((r) => r.top)),
                right: Math.max(...parts.map((r) => r.right)), bottom: Math.max(...parts.map((r) => r.bottom)) };
  const main = document.querySelector('[data-testid="stMain"]');
  // Only what is visible counts: text clipped by the main scroller is not drawn.
  const m = main.getBoundingClientRect();
  const hits = [];
  const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent.trim()) continue;
    const range = document.createRange();
    range.selectNodeContents(n);
    for (const raw of range.getClientRects()) {
      const r = { left: Math.max(raw.left, m.left), right: Math.min(raw.right, m.right),
                  top: Math.max(raw.top, m.top), bottom: Math.min(raw.bottom, m.bottom) };
      if (r.right <= r.left || r.bottom <= r.top) continue;
      if (r.right > box.left && r.left < box.right && r.bottom > box.top && r.top < box.bottom) {
        hits.push(n.textContent.trim().slice(0, 40));
        break;
      }
    }
  }
  return { control: Object.fromEntries(Object.entries(box).map(([k, v]) => [k, Math.round(v)])), hits };
}"""

DASHBOARD = """() => {
  const actions = document.querySelector('.st-key-ax_card_quick_actions');
  if (!actions) return null;
  const sideCol = actions.closest('[data-testid="stColumn"]');
  const cols = Array.from(sideCol.parentElement.children).filter((c) => c.matches('[data-testid="stColumn"]'));
  const top = (el) => (el ? Math.round(el.getBoundingClientRect().top) : null);
  const heading = (col, text) => Array.from(col.querySelectorAll('h2'))
    .find((h) => h.textContent.includes(text));
  return { columns: cols.map((c) => Math.round(c.getBoundingClientRect().width)),
           recentHeadingTop: top(heading(cols[0], 'Recent threat models')),
           actionsHeadingTop: top(heading(sideCol, 'Quick actions')),
           recentCardTop: top(cols[0].querySelector('[class*="st-key-dash_row_"]')),
           actionsCardTop: top(actions) };
}"""

HEADING = """() => {
  const h = document.querySelector('.ax-header .ax-title');
  if (!h) return null;
  const lh = parseFloat(getComputedStyle(h).lineHeight) || 1;
  return { text: h.textContent, height: Math.round(h.getBoundingClientRect().height),
           lines: Math.round(h.getBoundingClientRect().height / lh),
           full: h.getAttribute('title') || null };
}"""

# The empty progress track's color, blended over the card it sits on, and
# the card's color, to compare (both "r,g,b").
TRACK = """() => {
  const track = document.querySelector('[data-testid="stProgressBarTrack"]');
  if (!track) return null;
  const rgba = (c) => (c.match(/[\\d.]+/g) || []).map(Number);
  let card = track.parentElement;
  while (card && rgba(getComputedStyle(card).backgroundColor)[3] === 0) card = card.parentElement;
  const under = rgba(getComputedStyle(card || document.body).backgroundColor).slice(0, 3);
  const [r, g, b, a = 1] = rgba(getComputedStyle(track).backgroundColor);
  const blend = [r, g, b].map((v, i) => Math.round(v * a + under[i] * (1 - a)));
  return { track: blend, card: under };
}"""


def contrast(first: list[int], second: list[int]) -> float:
    """WCAG contrast ratio of two sRGB colors."""
    def luminance(rgb: list[int]) -> float:
        parts = [c / 255 for c in rgb]
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in parts]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
    hi, lo = sorted((luminance(first), luminance(second)), reverse=True)
    return round((hi + 0.05) / (lo + 0.05), 2)


def check_track(run: Run, name: str, track: dict[str, Any] | None) -> None:
    """The empty track must read as a track against its card."""
    ratio = contrast(track["track"], track["card"]) if track else 0.0
    run.readings[f"{name}_track_contrast"] = ratio
    run.expect(ratio >= 1.4, f"{name}: empty progress track contrast {ratio} against its card")


@dataclass
class Run:
    """Where output goes and what was read, for one invocation."""

    out: Path
    base: str = ""
    readings: dict[str, Any] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)

    def shot(self, page: Page, name: str, *, full: bool = False) -> None:
        page.screenshot(path=str(self.out / f"{name}.png"), full_page=full)

    def expect(self, ok: bool, what: str) -> None:
        if not ok:
            self.failures.append(what)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def server(out: Path, entry: str, *, mock: bool = True, log_name: str = "server.log") -> Iterator[str]:
    """Run the app (in mock mode unless ``mock`` is False) on a free port;
    yield its base URL."""
    port = free_port()
    env = {**os.environ, "AEGIS_MOCK_LLM": "1"} if mock else dict(os.environ)
    if not mock:
        env.pop("AEGIS_MOCK_LLM", None)
    for name in ("AEGIS_DATA_DIR", "AEGIS_PROVIDERS"):
        env.pop(name, None)
    with open(out / log_name, "w") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", entry, "--server.headless", "true",
             "--server.port", str(port), "--server.address", "127.0.0.1",
             "--browser.gatherUsageStats", "false"],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.3)
            yield f"http://127.0.0.1:{port}"
        finally:
            proc.terminate()
            proc.wait(timeout=20)


def settle(page: Page, ms: int = 600) -> None:
    """Wait for Streamlit's running indicator to go, then a little more."""
    page.wait_for_timeout(200)
    page.wait_for_function("() => !document.querySelector('[data-testid=\"stStatusWidget\"]')",
                           timeout=30000)
    page.wait_for_timeout(ms)


def new_page(browser: Browser, size: str, console: list[str]) -> Page:
    width, height = SIZES[size]
    ctx = browser.new_context(viewport={"width": width, "height": height}, accept_downloads=True)
    ctx.add_init_script(PAGE_PROBE)
    page = ctx.new_page()
    page.on("console", lambda m: console.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console.append(str(e)))
    return page


def open_app(browser: Browser, run: Run, size: str, console: list[str]) -> Page:
    page = new_page(browser, size, console)
    page.goto(run.base)
    settle(page, 1500)
    return page


def nav(page: Page, label: str) -> None:
    """Open a page from the navigation, expanding the sidebar if needed."""
    link = page.locator('[data-testid="stSidebarNavLink"]').filter(has_text=label).first
    box = link.bounding_box() if link.count() else None
    if not box or box["x"] < 0:
        # Streamlit shows the control on hover; force the click.
        page.locator('[data-testid="stExpandSidebarButton"]').first.click(force=True)
        page.wait_for_timeout(500)
    link.click()
    settle(page, 1200)


def key(page: Page, widget_key: str) -> Locator:
    return page.locator(f".st-key-{widget_key}")


def wait_text(page: Page, text: str, timeout: float = 30000) -> None:
    page.get_by_text(text, exact=False).first.wait_for(timeout=timeout)


def pick(page: Page, label: str, value: str) -> None:
    box = page.locator('[data-testid="stSelectbox"]').filter(has_text=label).first
    box.locator("input").click()
    page.keyboard.type(value)
    page.wait_for_timeout(150)
    page.locator('[role="option"]').filter(has_text=value).first.click()
    settle(page, 250)


def download(page: Page, run: Run, button: Locator, name: str) -> int:
    """Click a download button; return the saved file's size in bytes."""
    with page.expect_download(timeout=30000) as info:
        button.click()
    target = run.out / "downloads" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    info.value.save_as(target)
    return target.stat().st_size


def counters(page: Page) -> dict[str, Any]:
    return page.evaluate(COUNTERS)


def start_sampling(page: Page) -> None:
    page.evaluate("() => { const p = window.__pageProbe; p.sampling = true; p.frames = 0;"
                  " p.maxGapMs = 0; p.scrollMoves = []; p.lastScroll = null; }")


def stop_sampling(page: Page) -> None:
    page.evaluate("() => { window.__pageProbe.sampling = false; }")


def check_console(run: Run, name: str, console: list[str]) -> None:
    run.readings[f"{name}_console"] = console
    run.expect(not console, f"{name}: console errors {console}")


# ------------------------------------------------------------- pages


def check_pages(browser: Browser, run: Run, size: str) -> None:
    console: list[str] = []
    page = open_app(browser, run, size, console)
    seen = {}
    # Each link's text is its icon's name, then its label.
    labels = page.locator('[data-testid="stSidebarNavLink"]').all_inner_texts()
    for label in labels:
        name = label.strip().splitlines()[-1].strip()
        nav(page, name)
        run.shot(page, f"page_{name.lower().replace(' ', '_')}_{size}")
        seen[name] = page.url.rsplit("/", 1)[-1]
    run.readings[f"pages_{size}"] = seen
    run.expect(len(seen) >= 6, f"pages {size}: only {len(seen)} pages in the navigation")
    check_console(run, f"pages_{size}", console)
    page.context.close()


# ------------------------------------------------------------- wizard


def set_agentic(page: Page, on: bool) -> None:
    nav(page, "Settings")
    toggle = page.locator(".st-key-aegis_agentic_widget input[type=checkbox]")
    if toggle.is_checked() != on:
        page.locator(".st-key-aegis_agentic_widget label").first.click()
        settle(page)


def fill_wizard(page: Page, app_type: str = "Web application") -> None:
    """Steps 1 and 2 with the example description and a retail profile."""
    nav(page, "New threat model")
    insert = page.get_by_role("button", name="Insert the example description")
    if insert.count():
        insert.click()
        settle(page)
    page.get_by_role("button", name="Next").click()
    settle(page)
    for label, value in (("Application type", app_type), ("Industry sector", "Retail"),
                         ("Data sensitivity", "High"), ("Internet-facing", "Yes"),
                         ("Number of employees", "101-1000")):
        pick(page, label, value)
    page.get_by_role("button", name="Next").click()
    settle(page, 1200)


def watch_run(page: Page, run: Run, prefix: str, limit: float = 90) -> dict[str, Any]:
    """Press Generate and sample until the results appear."""
    before = counters(page)
    start_sampling(page)
    page.get_by_role("button", name="Generate").click()
    t0, mid, roots, positions = time.time(), None, set(), []
    while time.time() - t0 < limit:
        page.wait_for_timeout(400)
        c = counters(page)
        roots.add((c["roots"]["deck"], c["roots"]["office"]))
        position = page.evaluate(LIVE_VIEW)
        if position:
            positions.append(position)
        if mid is None and time.time() - t0 > 4:
            run.shot(page, f"{prefix}_midrun")
            mid = position
        if page.evaluate(RESULTS_SHOWN):
            break
    seconds = round(time.time() - t0, 1)
    settle(page, 2500)
    stop_sampling(page)
    after = counters(page)
    settled = page.evaluate(LIVE_VIEW)
    run.shot(page, f"{prefix}_settled")
    return {"before": before, "after": after, "seconds_to_results": seconds,
            "results_shown": page.evaluate(RESULTS_SHOWN), "roots_seen": sorted(roots),
            "live_view_midrun": mid, "live_view_settled": settled,
            "live_view_tops": sorted({p["top"] for p in positions}),
            "scroll_moves": after["page"]["scrollMoves"],
            "longest_page_frame_gap_ms": after["page"]["maxGapMs"]}


def check_live_view_position(run: Run, name: str, reading: dict[str, Any]) -> None:
    """The live view starts on screen during the run and after it settles,
    and the main area moved at most once (the one deliberate scroll)."""
    for when in ("live_view_midrun", "live_view_settled"):
        pos = reading.get(when)
        run.expect(bool(pos) and 0 <= pos["top"] < pos["viewport"] * 0.35,
                   f"{name}: {when} starts at {pos and pos['top']} px of {pos and pos['viewport']}")
    run.expect(len(reading["scroll_moves"]) <= 1,
               f"{name}: main area moved {len(reading['scroll_moves'])} times")


def check_wizard(browser: Browser, run: Run, size: str) -> None:
    """Agentic run in the office, then a linear run in the deck, one session."""
    console: list[str] = []
    page = open_app(browser, run, size, console)
    set_agentic(page, True)
    fill_wizard(page)
    run.shot(page, f"wizard_office_idle_{size}")
    office = watch_run(page, run, f"wizard_office_{size}")
    # The room settles (its loop ends) once every desk is final and the
    # tweens are done, a few seconds after the results appear.
    page.wait_for_function("() => (window.__aegisOffice || {}).ends >= 1", timeout=20000)
    office["after"] = counters(page)
    o_before, o_after = office["before"]["office"], office["after"]["office"]
    office["office_mounts"] = o_after["mounts"]
    office["office_loops_started_during_run"] = o_after["chainStarts"] - o_before["chainStarts"]
    office["office_loops_ended"] = o_after["ends"]
    office["deck_mounts"] = office["after"]["deck"]["mounts"]
    run.expect(office["results_shown"], f"wizard {size}: agentic results did not appear")
    run.expect(o_after["mounts"] == 1, f"wizard {size}: office mounted {o_after['mounts']} times")
    run.expect(office["office_loops_started_during_run"] == 1,
               f"wizard {size}: office loop started {office['office_loops_started_during_run']} times")
    run.expect(o_after["ends"] >= 1 and o_after["frames"] > 0,
               f"wizard {size}: office did not play and settle")
    run.expect(office["deck_mounts"] == 0, f"wizard {size}: deck mounted in an agentic run")
    check_live_view_position(run, f"wizard office {size}", office)
    run.readings[f"wizard_office_{size}"] = office

    set_agentic(page, False)
    nav(page, "New threat model")
    run.shot(page, f"wizard_deck_idle_{size}")
    deck = watch_run(page, run, f"wizard_deck_{size}")
    d_after = deck["after"]["deck"]
    deck["deck_mounts"] = d_after["mounts"]
    deck["style"] = page.evaluate(DECK_STYLE)
    run.expect(deck["results_shown"], f"wizard {size}: linear results did not appear")
    # The page shows the finished agentic run in the office until Generate,
    # so the deck's one mount is the swap at the start of this run.
    run.expect(d_after["mounts"] == 1, f"wizard {size}: deck mounted {d_after['mounts']} times")
    run.expect(deck["style"]["board"] not in (None, "block", "inline"),
               f"wizard {size}: deck unstyled after the swap ({deck['style']})")
    run.expect(all(r[0] + r[1] <= 1 for r in deck["roots_seen"] + office["roots_seen"]),
               f"wizard {size}: two live roots at once")
    check_live_view_position(run, f"wizard deck {size}", deck)
    run.readings[f"wizard_deck_{size}"] = deck
    if size == next(iter(SIZES)):
        check_tm_exports(page, run)
    check_console(run, f"wizard_{size}", console)
    page.context.close()


# The page's last element against the bottom of the main scroller, with
# the scroller at its end: the bottom of the page must be reachable.
PAGE_BOTTOM = """() => {
  const main = document.querySelector('[data-testid="stMain"]');
  main.scrollTo(0, main.scrollHeight);
  const blocks = main.querySelectorAll('[data-testid="stElementContainer"]');
  const last = blocks[blocks.length - 1];
  return { lastBottom: Math.round(last.getBoundingClientRect().bottom),
           mainBottom: Math.round(main.getBoundingClientRect().bottom),
           viewport: window.innerHeight };
}"""


def check_deck(browser: Browser, run: Run, size: str) -> None:
    """A linear run first, in a fresh session: the deck's own path."""
    console: list[str] = []
    page = open_app(browser, run, size, console)
    fill_wizard(page)
    collapsed = page.locator('[data-testid="stExpandSidebarButton"]').count() > 0
    idle_mounts = counters(page)["deck"]["mounts"]
    deck = watch_run(page, run, f"deck_first_{size}")
    deck["sidebar_collapsed"] = collapsed
    deck["idle_mounts"] = idle_mounts
    deck["width"] = page.evaluate(
        "() => Math.round(document.querySelector('.aegis-deck-root').getBoundingClientRect().width)")
    deck["under_sidebar_control"] = page.evaluate(UNDER_CONTROL)
    deck["page_bottom"] = page.evaluate(PAGE_BOTTOM)
    width = SIZES[size][0]
    run.expect(deck["results_shown"], f"deck first {size}: results did not appear")
    run.expect(idle_mounts == 1 and deck["after"]["deck"]["mounts"] == 1,
               f"deck first {size}: mounts idle {idle_mounts}, after {deck['after']['deck']['mounts']}")
    run.expect(collapsed, f"deck first {size}: the wizard did not collapse the sidebar")
    run.expect(deck["width"] >= width - 16, f"deck first {size}: deck {deck['width']} px wide")
    run.expect(len(deck["scroll_moves"]) == 1, f"deck first {size}: {len(deck['scroll_moves'])} scroll moves")
    run.expect(not deck["under_sidebar_control"]["hits"],
               f"deck first {size}: text under the control {deck['under_sidebar_control']['hits']}")
    bottom = deck["page_bottom"]
    run.expect(bottom["lastBottom"] <= bottom["mainBottom"],
               f"deck first {size}: the page bottom is out of reach {bottom}")
    check_live_view_position(run, f"deck first {size}", deck)
    run.readings[f"deck_first_{size}"] = deck
    check_console(run, f"deck_first_{size}", console)
    page.context.close()


def _run_param(page: Page) -> str | None:
    found = re.search(r"[?&]run=([A-Za-z0-9_-]+)", page.url)
    return found.group(1) if found else None


def check_reload(browser: Browser, run: Run, size: str) -> None:
    """Reload during a linear run: the new session adopts the job from the URL."""
    console: list[str] = []
    page = open_app(browser, run, size, console)
    missing: list[str] = []
    page.on("response", lambda r: missing.append(r.url) if r.status == 404 else None)
    fill_wizard(page)
    page.get_by_role("button", name="Generate").click()
    t0 = time.time()
    while _run_param(page) is None and time.time() - t0 < 20:
        page.wait_for_timeout(250)
    link = page.url
    job = _run_param(page)
    page.wait_for_timeout(1500)
    shown_before = page.evaluate(RESULTS_SHOWN)
    page.reload()
    t1 = time.time()
    while not page.evaluate(RESULTS_SHOWN) and time.time() - t1 < 90:
        page.wait_for_timeout(400)
    settle(page, 2500)
    run.shot(page, f"reload_{size}")
    reading = {"job_in_url": bool(job), "results_before_reload": shown_before,
               "results_after_reload": page.evaluate(RESULTS_SHOWN),
               "seconds_to_results": round(time.time() - t1, 1),
               "run_param_after_settle": _run_param(page), "not_found": missing}
    later = new_page(browser, size, console)
    later.on("response", lambda r: missing.append(r.url) if r.status == 404 else None)
    later.goto(link)
    settle(later, 3000)
    reading["old_link_shows_results"] = later.evaluate(RESULTS_SHOWN)
    reading["old_link_run_param"] = _run_param(later)
    later.context.close()
    run.expect(reading["job_in_url"], f"reload {size}: the run id never reached the URL")
    run.expect(not shown_before, f"reload {size}: the run ended before the reload")
    run.expect(reading["results_after_reload"], f"reload {size}: the reloaded page showed no results")
    run.expect(reading["run_param_after_settle"] is None, f"reload {size}: ?run= left after the run settled")
    run.expect(not reading["old_link_shows_results"] and reading["old_link_run_param"] is None,
               f"reload {size}: the old link still opened the run")
    # Opening a page's own path (/new-threat-model?run=...) makes Streamlit's
    # frontend probe for its server under that path first; those two 404s are
    # its own and expected. Any other 404 still counts.
    probes = [u for u in missing if re.search(r"/_stcore/(health|host-config)$", u)]
    run.expect(len(probes) == len(missing), f"reload {size}: missing resources {missing}")
    not_found = "Failed to load resource: the server responded with a status of 404 (Not Found)"
    for _ in probes:
        if not_found in console:
            console.remove(not_found)
    run.readings[f"reload_{size}"] = reading
    check_console(run, f"reload_{size}", console)
    page.context.close()


def check_tm_exports(page: Page, run: Run) -> None:
    page.get_by_role("button", name="4  Export").click()
    settle(page, 1200)
    run.shot(page, "wizard_export")
    sizes = {}
    for button in page.locator('[data-testid="stDownloadButton"] button').all():
        label = button.inner_text().strip().splitlines()[-1].strip()
        sizes[label] = download(page, run, button, "tm_" + label.lower().replace(" ", "_"))
    run.readings["tm_exports"] = sizes
    run.expect(len(sizes) >= 4 and all(v > 0 for v in sizes.values()),
               f"threat model exports: {sizes}")


# The ATLAS block's rows and every link in it, with its href.
ATLAS_BLOCK = """() => {
  const block = document.querySelector('.tm-atlas');
  if (!block) return null;
  return { rows: block.querySelectorAll('.tm-atlas-row').length,
           links: Array.from(block.querySelectorAll('a')).map((a) => a.getAttribute('href')) };
}"""
ATLAS_LINK = re.compile(r"https://atlas\.mitre\.org/(?:techniques/AML\.T\d{4}(?:\.\d{3})?"
                        r"|mitigations/AML\.M\d{4}|studies/AML\.CS\d{4})")


def check_atlas(browser: Browser, run: Run, size: str) -> None:
    """An AI system's linear run: the ATLAS tab, block, and link forms."""
    console: list[str] = []
    page = open_app(browser, run, size, console)
    fill_wizard(page, app_type="AI/ML Systems")
    reading = watch_run(page, run, f"atlas_{size}")
    run.expect(reading["results_shown"], f"atlas {size}: results did not appear")
    tab = page.get_by_role("tab", name="MITRE ATT&CK and ATLAS")
    run.expect(tab.count() == 1, f"atlas {size}: no 'MITRE ATT&CK and ATLAS' tab")
    if tab.count():
        tab.first.click()
        settle(page, 800)
    block = page.evaluate(ATLAS_BLOCK)
    if block:
        page.locator(".tm-atlas").first.scroll_into_view_if_needed()
        settle(page, 300)
    run.shot(page, f"atlas_block_{size}")
    reading["atlas_block"] = block
    links = (block or {}).get("links") or []
    run.expect(bool(block) and block["rows"] >= 1, f"atlas {size}: no ATLAS block rows ({block})")
    run.expect(any("/techniques/AML.T" in h for h in links), f"atlas {size}: no ATLAS technique link")
    bad = [h for h in links if not ATLAS_LINK.fullmatch(h or "")]
    run.expect(not bad, f"atlas {size}: links not in an ATLAS page form: {bad[:3]}")
    run.readings[f"atlas_{size}"] = reading
    check_console(run, f"atlas_{size}", console)
    page.context.close()


# ------------------------------------------------------------- tools


def check_lookup(browser: Browser, run: Run, size: str) -> None:
    console: list[str] = []
    page = open_app(browser, run, size, console)
    nav(page, "Vulnerability lookup")
    page.get_by_role("textbox", name="Or paste a list").fill(LOOKUP_PASTE)
    page.keyboard.press("Tab")
    settle(page, 500)
    key(page, "vl_run").locator("button").click()
    wait_text(page, "Lookup running")
    page.wait_for_timeout(1500)
    run.shot(page, f"lookup_running_{size}")
    track = page.evaluate(TRACK)
    wait_text(page, "What was not checked", 60000)
    settle(page, 1200)
    run.shot(page, f"lookup_results_{size}")
    rows = page.evaluate(TILE_ROWS, ".ax-tile")
    reading: dict[str, Any] = {"progress_track": track, "tile_rows": [len(r) for r in rows]}
    check_track(run, f"lookup_{size}", track)
    if size == next(iter(SIZES)):
        reading["downloads"] = {
            "json": download(page, run, key(page, "vl_dl_json").locator("button"), "lookup.json"),
            "csv": download(page, run, key(page, "vl_dl_csv").locator("button"), "lookup.csv")}
        run.expect(all(v > 0 for v in reading["downloads"].values()), "lookup downloads empty")
    run.readings[f"lookup_{size}"] = reading
    counts = reading["tile_rows"]
    run.expect(bool(counts) and max(counts) - min(counts) <= 1,
               f"lookup {size}: summary tiles wrap unevenly {counts}")
    check_console(run, f"lookup_{size}", console)
    page.context.close()


def save_profile(page: Page) -> None:
    page.get_by_role("tab", name="Organization profile").click()
    settle(page)
    page.get_by_role("textbox", name="Legal name *").fill("Example Retail Inc.")
    industry = page.locator('[data-testid="stSelectbox"]').filter(has_text="Industry").first
    industry.click()
    page.get_by_role("option", name="Retail and e-commerce").click()
    page.get_by_role("button", name="Save profile").click()
    settle(page, 1500)
    wait_text(page, "Profile saved.")
    page.get_by_role("tab", name="Policy catalog").click()
    settle(page)


def check_policy(browser: Browser, run: Run, size: str) -> None:
    console: list[str] = []
    page = open_app(browser, run, size, console)
    nav(page, "Policies")
    save_profile(page)
    run.shot(page, f"policies_catalog_{size}")
    run.shot(page, f"policies_catalog_full_{size}", full=True)
    rows = page.evaluate(TILE_ROWS, '.st-key-pol_catalog [class*="st-key-ax_card_pol_"]')
    uneven = [r for r in rows if max(r) - min(r) > 2]
    key(page, "pol_gen_information_security_policy").locator("button").click()
    wait_text(page, "is ready. Review it", 90000)
    settle(page, 1200)
    run.shot(page, f"policy_reader_{size}")
    reading: dict[str, Any] = {"card_rows": rows}
    if size == next(iter(SIZES)):
        reading["downloads"] = {
            "pdf": download(page, run, key(page, "pol_dl_pdf").locator("button"), "policy.pdf"),
            "md": download(page, run, key(page, "pol_dl_md").locator("button"), "policy.md")}
        run.expect(all(v > 0 for v in reading["downloads"].values()), "policy downloads empty")
    run.readings[f"policy_{size}"] = reading
    run.expect(not uneven, f"policies {size}: card rows of uneven height {uneven}")
    check_console(run, f"policy_{size}", console)
    page.context.close()


def check_pcap(browser: Browser, run: Run, size: str) -> None:
    console: list[str] = []
    page = open_app(browser, run, size, console)
    if not page.locator('[data-testid="stSidebarNavLink"]').filter(has_text="PCAP analysis").count():
        run.readings[f"pcap_{size}"] = "skipped: no tshark on PATH"
        page.context.close()
        return
    nav(page, "PCAP analysis")
    page.locator('input[type="file"]').set_input_files(str(CAPTURE))
    settle(page, 1200)
    key(page, "pcap_run").locator("button").click()
    wait_text(page, "Analyzing minimal.pcap")
    page.wait_for_timeout(800)
    run.shot(page, f"pcap_running_{size}")
    track = page.evaluate(TRACK)
    wait_text(page, "Analysis finished and saved", 90000)
    settle(page, 1500)
    run.shot(page, f"pcap_results_{size}")
    reading: dict[str, Any] = {"progress_track": track}
    check_track(run, f"pcap_{size}", track)
    if size == next(iter(SIZES)):
        reading["downloads"] = {"md": download(page, run, key(page, "pcap_dl_md").locator("button"),
                                               "capture.md")}
        run.expect(reading["downloads"]["md"] > 0, "capture report download empty")
    run.readings[f"pcap_{size}"] = reading
    check_console(run, f"pcap_{size}", console)
    page.context.close()


# ------------------------------------------------------------- scan


def check_scan(browser: Browser, run: Run, size: str) -> None:
    console: list[str] = []
    page = open_app(browser, run, size, console)
    if not page.locator('[data-testid="stSidebarNavLink"]').filter(has_text="AI workflow scan").count():
        run.failures.append(f"scan {size}: the AI workflow scan page is not in the navigation")
        page.context.close()
        return
    nav(page, "AI workflow scan")
    run.shot(page, f"scan_form_{size}")
    run.shot(page, f"scan_form_full_{size}", full=True)
    body = page.inner_text("body")
    run.expect("Workflow step to scan" not in body, f"scan {size}: the page still offers the app's own steps")
    system = key(page, "scan_system_prompt").locator("textarea")
    system.fill("You answer billing questions for Example Retail in two sentences or fewer.")
    system.press("Tab")
    settle(page)
    prompts = key(page, "scan_limit_prompts").locator("input")
    prompts.fill("2")
    prompts.press("Enter")
    settle(page)
    key(page, "scan_run").locator("button").click()
    wait_text(page, "Scan running")
    page.wait_for_timeout(1500)
    run.shot(page, f"scan_running_{size}")
    track = page.evaluate(TRACK)
    wait_text(page, "Scan saved to this session", 120000)
    settle(page, 1500)
    run.shot(page, f"scan_results_{size}")
    run.shot(page, f"scan_results_full_{size}", full=True)
    body = page.inner_text("body")
    reading: dict[str, Any] = {"progress_track": track, "fake_garak": os.environ.get("AEGIS_GARAK_PYTHON") is None}
    reading["complete"] = "garak finished every probe" in body
    reading["simulated_label"] = "simulated model, not a real model run" in body
    reading["atlas_reference"] = "ATLAS AML.T0051.000" in body
    reading["workflow_stored"] = "Your workflow as stored" in body
    run.expect(reading["atlas_reference"], f"scan {size}: no ATLAS reference in the results")
    run.expect(reading["workflow_stored"], f"scan {size}: the stored workflow is not shown")
    run.expect(reading["complete"], f"scan {size}: the scan did not finish as complete")
    run.expect(reading["simulated_label"], f"scan {size}: results are not labeled simulated")
    check_track(run, f"scan_{size}", track)
    page.locator('[data-testid="stExpander"] summary').first.click()
    settle(page, 600)
    run.shot(page, f"scan_attempt_{size}")
    if size == next(iter(SIZES)):
        reading["downloads"] = {
            "json": download(page, run, key(page, "scan_dl_json").locator("button"), "scan.json"),
            "report": download(page, run, key(page, "scan_dl_garak_report_jsonl").locator("button"),
                               "garak.report.jsonl")}
        run.expect(all(v > 0 for v in reading["downloads"].values()), "scan downloads empty")
    run.readings[f"scan_{size}"] = reading
    check_console(run, f"scan_{size}", console)
    page.context.close()


# ------------------------------------------------------------- layout


# The first recent threat model's title on the dashboard: how it overflows.
RECENT_TITLE = """() => {
  const p = document.querySelector('[class*="st-key-dash_row_"] [data-testid="stPageLink"] a p');
  if (!p) return null;
  const s = getComputedStyle(p);
  return {overflow: s.textOverflow, wrap: s.whiteSpace, cut: p.scrollWidth > p.clientWidth};
}"""


def check_layout(browser: Browser, run: Run, size: str) -> None:
    """Dashboard columns, the detail heading, and the fixed sidebar control."""
    console: list[str] = []
    page = open_app(browser, run, size, console)
    sample = page.get_by_role("button", name="Try with sample data")
    if sample.count():
        sample.click()
        settle(page, 1500)
    run.shot(page, f"dashboard_populated_{size}")
    dash = page.evaluate(DASHBOARD)
    title = page.evaluate(RECENT_TITLE)
    page.locator('[class*="st-key-dash_row_"] a').first.click()
    settle(page, 1500)
    run.shot(page, f"detail_{size}")
    heading = page.evaluate(HEADING)
    collapse = page.locator('[data-testid="stSidebarCollapseButton"] button').first
    if collapse.count() and not page.locator('[data-testid="stExpandSidebarButton"]').count():
        # Streamlit shows the control while the sidebar is hovered.
        page.locator('[data-testid="stSidebar"]').hover()
        page.wait_for_timeout(300)
        collapse.click()
        page.wait_for_timeout(800)
    collapsed = page.locator('[data-testid="stExpandSidebarButton"]').count() > 0
    tab = page.locator("[role=tab]").first
    under = []
    if tab.count():
        tab.evaluate("t => t.scrollIntoView({block: 'start'})")
        page.wait_for_timeout(500)
        run.shot(page, f"detail_scrolled_collapsed_{size}")
        under.append(page.evaluate(UNDER_CONTROL))
    for offset in (120, 400, 800):
        page.locator('[data-testid="stMain"]').evaluate(f"m => m.scrollTo(0, {offset})")
        page.wait_for_timeout(300)
        under.append(page.evaluate(UNDER_CONTROL))
    run.expect(bool(title) and title["overflow"] == "ellipsis" and title["wrap"] == "nowrap",
               f"dashboard {size}: a long recent title does not end in an ellipsis {title}")
    run.readings[f"layout_{size}"] = {"dashboard": dash, "recent_title": title, "detail_heading": heading,
                                      "sidebar_collapsed": collapsed,
                                      "under_sidebar_control": under}
    run.expect(collapsed and all(u["control"] for u in under),
               f"layout {size}: could not collapse the sidebar to measure its control")
    run.expect(bool(dash) and None not in dash.values()
               and abs(dash["actionsHeadingTop"] - dash["recentHeadingTop"]) <= 2
               and abs(dash["actionsCardTop"] - dash["recentCardTop"]) <= 2,
               f"dashboard {size}: columns start at different heights {dash}")
    run.expect(bool(heading) and heading["lines"] <= 1,
               f"detail {size}: heading runs to {heading and heading['lines']} lines")
    hits = sorted({h for u in under for h in u["hits"]})
    run.expect(not hits, f"layout {size}: text under the sidebar control {hits[:5]}")
    check_console(run, f"layout_{size}", console)
    page.context.close()


# ---------------------------------------------------------------- brand

# The page background's luminance and the sidebar logo's average color over
# its opaque pixels, read by drawing the served image on a canvas.
BRAND = """async () => {
  const lum = (c) => { const [r, g, b] = c.match(/\\d+/g).map(Number);
                       return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255; };
  const app = document.querySelector('[data-testid="stApp"]');
  const img = document.querySelector('[data-testid="stSidebarLogo"], [data-testid="stHeaderLogo"]');
  const icon = document.querySelector('link[rel~="icon"]');
  if (!app || !img) return null;
  const pic = new Image();
  pic.src = img.currentSrc || img.src;
  await pic.decode();
  const canvas = document.createElement('canvas');
  canvas.width = pic.naturalWidth; canvas.height = pic.naturalHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(pic, 0, 0);
  const px = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  let sum = 0, n = 0;
  for (let i = 0; i < px.length; i += 4) {
    if (px[i + 3] > 200) { sum += 0.2126 * px[i] + 0.7152 * px[i + 1] + 0.0722 * px[i + 2]; n += 1; }
  }
  return { page: lum(getComputedStyle(app).backgroundColor), logo: n ? sum / n / 255 : null,
           icon: icon ? icon.getAttribute('href') : null };
}"""


def check_brand(browser: Browser, run: Run, size: str) -> None:
    """The sidebar shield's artwork matches the page's theme."""
    readings: dict[str, Any] = {}
    for scheme in ("light", "dark"):
        console: list[str] = []
        width, height = SIZES[size]
        ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme)
        page = ctx.new_page()
        page.on("console", lambda m, c=console: c.append(m.text) if m.type == "error" else None)
        page.goto(run.base)
        settle(page, 1500)
        reading = page.evaluate(BRAND)
        run.shot(page, f"brand_{scheme}_{size}")
        readings[scheme] = reading
        ok = bool(reading) and reading["logo"] is not None
        # White artwork on a dark page, navy artwork on a light one.
        run.expect(ok and (reading["page"] < 0.5) == (reading["logo"] > 0.5),
                   f"brand {scheme} {size}: logo artwork does not match the page theme {reading}")
        run.expect(ok and bool(reading["icon"]), f"brand {scheme} {size}: no tab icon {reading}")
        check_console(run, f"brand_{scheme}_{size}", console)
        ctx.close()
    run.readings[f"brand_{size}"] = readings


# ----------------------------------------------------------- providers

# Credentials typed into the provider check. They are made up, never sent
# anywhere (the provider entry fakes every listing), and must never appear
# in the page.
_FAKE_CREDS = {
    "claude": {"api_key": "check-claude-key-0001"},
    "openai": {"api_key": "check-openai-key-0001"},
    "gemini": {"api_key": "check-gemini-key-0001"},
    "bedrock": {"access_key_id": "CHECKACCESSID0001", "secret_access_key": "check-secret-0001",
                "session_token": "check-session-0001"},
}
_PROVIDER_LABELS = {"claude": "Claude (Anthropic)", "bedrock": "Amazon Bedrock",
                    "openai": "OpenAI", "gemini": "Gemini (Google)"}
_PICKS = {"claude": "claude-opus-5-5", "openai": "test-chat-b", "gemini": "test-gemini-b",
          "bedrock": "us.test.vision-model-v1:0"}


def _type_secret(page: Page, widget_key: str, value: str) -> None:
    field = key(page, widget_key).locator("input")
    field.fill(value)
    field.press("Enter")
    settle(page, 400)


def _page_text(page: Page) -> str:
    return page.evaluate("() => document.body.innerText + document.body.innerHTML")


def check_settings(browser: Browser, run: Run, size: str) -> None:
    """Mock mode: the provider controls say mock mode is on."""
    console: list[str] = []
    page = open_app(browser, run, size, console)
    nav(page, "Settings")
    run.shot(page, f"settings_mock_{size}")
    text = _page_text(page)
    disabled = key(page, "aegis_provider_widget").locator("input").is_disabled()
    run.readings[f"settings_mock_{size}"] = {"says_mock": "Mock mode is on" in text,
                                             "provider_disabled": disabled}
    run.expect("Mock mode is on" in text and disabled,
               f"settings {size}: mock mode is not stated or the provider control is enabled")
    check_console(run, f"settings_mock_{size}", console)
    page.context.close()


def _provider_scan(page: Page, run: Run, size: str, readings: dict[str, Any]) -> None:
    """The last choice (Gemini) also answers a workflow scan with the real
    model: the page names it, and the saved scan records it."""
    in_use = "Gemini (Google), test-gemini-b"
    nav(page, "AI workflow scan")
    wait_text(page, f"Model your workflow uses: {in_use}")
    system = key(page, "scan_system_prompt").locator("textarea")
    system.fill("You answer billing questions for Example Retail in two sentences or fewer.")
    system.press("Tab")
    settle(page)
    prompts = key(page, "scan_limit_prompts").locator("input")
    prompts.fill("1")
    prompts.press("Enter")
    settle(page)
    text = _page_text(page)
    readings["scan_names_model"] = f"Model your workflow uses: {in_use}" in text
    readings["scan_key_sentence"] = "your Gemini (Google) credential" in text
    key(page, "scan_run").locator("button").click()
    wait_text(page, "Scan saved to this session", 120000)
    settle(page, 1200)
    run.shot(page, f"providers_scan_result_{size}", full=True)
    text = _page_text(page)
    leaked = [v for creds in _FAKE_CREDS.values() for v in creds.values() if v in text]
    readings["scan_record_model"] = f"Real model (your provider credential): {in_use}" in text
    readings["scan_credential_shown"] = leaked
    run.expect(readings["scan_names_model"] and readings["scan_key_sentence"],
               f"providers {size}: the scan page does not name the chosen provider and model")
    run.expect(readings["scan_record_model"], f"providers {size}: the scan record does not name {in_use}")
    run.expect(not leaked, f"providers {size}: a credential is shown after the scan {leaked}")


def check_providers(browser: Browser, run: Run, size: str) -> None:
    """Outside mock mode with faked providers: every provider's form fills."""
    console: list[str] = []
    readings: dict[str, Any] = {}
    with server(run.out, "tools/provider_entry.py", mock=False,
                log_name=f"provider_server_{size}.log") as base:
        page = new_page(browser, size, console)
        page.goto(base)
        settle(page, 1500)
        nav(page, "Settings")
        run.shot(page, f"providers_start_{size}")
        for provider, label in _PROVIDER_LABELS.items():
            # The provider box sits at the top of the page, above the last form.
            page.locator('[data-testid="stMain"]').evaluate("m => m.scrollTo(0, 0)")
            page.keyboard.press("Escape")
            settle(page, 300)
            pick(page, "Provider", label)
            for field, value in _FAKE_CREDS[provider].items():
                widget = ("aegis_key_input_openai" if provider == "openai"
                          else f"aegis_cred_input_{provider}_{field}")
                _type_secret(page, widget, value)
            if provider == "bedrock":
                pick(page, "AWS region", "us-west-2")
            wait_text(page, "Choose a model" if provider in ("bedrock", "gemini") else "In use")
            options = key(page, "aegis_model_widget").count() > 0
            # The Bedrock form is taller than the others; at some sizes the
            # model box sits at the bottom edge, where its list has no room.
            if options:
                key(page, "aegis_model_widget").evaluate(
                    "e => e.scrollIntoView({block: 'center'})")
                settle(page, 200)
            pick(page, "Model", _PICKS[provider])
            wait_text(page, f"{label}, {_PICKS[provider]}")
            run.shot(page, f"providers_{provider}_{size}", full=True)
            text = _page_text(page)
            leaked = [v for v in _FAKE_CREDS[provider].values() if v in text]
            side = page.locator('[data-testid="stSidebar"] .ax-status').inner_text()
            sidebar_names = label in side
            readings[provider] = {"model_select": options, "in_use": f"{label}, {_PICKS[provider]}" in text,
                                  "sidebar_names_provider": sidebar_names, "credential_shown": leaked}
            run.expect(sidebar_names, f"providers {size}: the sidebar does not name {label}")
            run.expect(options and not leaked,
                       f"providers {size}: {provider} select missing or credential shown {leaked}")
        # The last choice (Gemini) answers a policy; its result names it.
        nav(page, "Policies")
        save_profile(page)
        key(page, "pol_gen_information_security_policy").locator("button").click()
        wait_text(page, "Answered by Gemini (Google), test-gemini-b", timeout=90000)
        settle(page, 800)
        run.shot(page, f"providers_policy_result_{size}", full=True)
        text = _page_text(page)
        leaked = [v for creds in _FAKE_CREDS.values() for v in creds.values() if v in text]
        readings["policy_answered_by"] = "Answered by Gemini (Google), test-gemini-b" in text
        readings["policy_credential_shown"] = leaked
        run.expect(not leaked, f"providers {size}: a credential is shown after the run {leaked}")
        _provider_scan(page, run, size, readings)
        page.context.close()
    run.readings[f"providers_{size}"] = readings
    check_console(run, f"providers_{size}", console)


CHECKS: dict[str, Callable[[Browser, Run, str], None]] = {
    "pages": check_pages, "deck": check_deck, "wizard": check_wizard, "lookup": check_lookup,
    "policy": check_policy, "pcap": check_pcap, "scan": check_scan, "layout": check_layout,
    "atlas": check_atlas, "reload": check_reload, "brand": check_brand,
    "settings": check_settings, "providers": check_providers,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--entry", default="tools/mock_entry.py")
    ap.add_argument("--only", default=",".join(CHECKS))
    ap.add_argument("--sizes", default=",".join(SIZES))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    run = Run(out=args.out)
    run.readings["real_tshark"] = bool(shutil.which("tshark"))
    with server(args.out, args.entry) as base, sync_playwright() as pw:
        run.base = base
        browser = pw.chromium.launch()
        for name in args.only.split(","):
            for size in args.sizes.split(","):
                try:
                    CHECKS[name](browser, run, size)
                except Exception as exc:  # noqa: BLE001 - one broken check must not hide the rest
                    run.failures.append(f"{name} {size}: {type(exc).__name__}: {exc}")
        browser.close()
    run.readings["failures"] = run.failures
    (args.out / "readings.json").write_text(json.dumps(run.readings, indent=1, default=str))
    sys.stdout.write(json.dumps({"failures": run.failures}, indent=1) + "\n")
    return 1 if run.failures else 0


if __name__ == "__main__":
    sys.exit(main())
