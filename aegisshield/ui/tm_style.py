"""Styles used only by the threat-model pages (wizard, results, list, detail,
dashboard). They build on the theme's tokens and use only ``tm-`` classes
this package writes and ``st-key-tm*`` classes from widget keys.
"""

from __future__ import annotations

import streamlit as st

__all__ = ["CSS", "apply"]

CSS = """
/* Stepper: four buttons in a row; the current step is the primary one. */
[class*="st-key-tm_stepper"] [data-testid="stHorizontalBlock"] { gap: var(--space-2); }
[class*="st-key-tm_stepper"] button { width: 100%; justify-content: flex-start; min-height: 44px; }
[class*="st-key-tm_stepper"] button p { font-weight: 600; }
.tm-step-hint { color: var(--text-muted); font-size: var(--type-sm); margin: 2px 0 0; }

/* Character counter and small captions. */
.tm-counter { color: var(--text-muted); font-size: var(--type-sm); margin-top: -6px; }
.tm-counter.tm-short { color: var(--warn-text); }

/* Chips: STRIDE breakdown, patterns, threat ids. */
.tm-chips { display: flex; flex-wrap: wrap; gap: var(--space-2); margin: var(--space-2) 0 var(--space-3); }
.tm-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px;
  background: var(--bg-raised); border: 1px solid var(--border-strong); color: var(--text-soft);
  font-size: var(--type-sm); }
.tm-chip strong { color: var(--text-primary); font-weight: 600; }
.tm-chip .tm-letter { font-family: var(--mono); color: var(--accent-text); font-weight: 700; }
.tm-label { color: var(--text-muted); font-size: var(--type-xs); text-transform: uppercase;
  letter-spacing: 0.08em; margin: var(--space-3) 0 var(--space-1); }
.tm-id { font-family: var(--mono); font-size: var(--type-sm); color: var(--accent-text);
  background: var(--accent-glow); padding: 1px 6px; border-radius: 4px; white-space: nowrap; }

/* Findings list (STRIDE). */
.tm-findings { display: flex; flex-direction: column; gap: var(--space-2); }
.tm-finding { display: grid; grid-template-columns: 56px 1fr; gap: var(--space-3); padding: var(--space-3);
  border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-raised); }
.tm-sev { display: flex; flex-direction: column; align-items: center; justify-content: center;
  border-radius: var(--radius-sm); background: var(--tone-bg); color: var(--tone-text);
  border: 1px solid var(--tone); font-family: var(--mono); font-weight: 700; min-height: 48px; }
.tm-sev small { font-family: inherit; font-weight: 500; font-size: 0.62rem; text-transform: uppercase;
  letter-spacing: 0.06em; }
.tm-finding-head { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); }

/* MITRE ATLAS block: one row per threat. */
.tm-atlas { display: flex; flex-direction: column; gap: var(--space-2); margin-top: var(--space-2); }
.tm-atlas-row { padding: var(--space-3); border: 1px solid var(--border); border-radius: var(--radius-md);
  background: var(--bg-raised); }
.tm-atlas-row p { margin: var(--space-1) 0 0; }
.tm-muted { color: var(--text-muted); }
.tm-finding-title { color: var(--text-primary); font-weight: 600; }
.tm-finding p { margin: 6px 0 0; color: var(--text-soft); font-size: var(--type-base); line-height: 1.5; }
.tm-finding a { color: var(--accent-text); }

/* DREAD bars. */
.tm-dread-top { display: flex; align-items: baseline; gap: var(--space-3); }
.tm-dread-score { font-size: 2.2rem; font-weight: 700; color: var(--tone-text); font-family: var(--mono); }
.tm-bars { display: flex; flex-direction: column; gap: 8px; margin-top: var(--space-3); }
.tm-bar { display: grid; grid-template-columns: 110px 1fr 32px; align-items: center; gap: var(--space-2);
  font-size: var(--type-sm); color: var(--text-soft); }
.tm-bar-track { height: 8px; border-radius: 999px; background: var(--bg-terminal); overflow: hidden; }
.tm-bar-fill { height: 100%; border-radius: 999px; background: var(--tone); }
.tm-bar-value { font-family: var(--mono); color: var(--text-primary); text-align: right; }

/* Diagrams (SVG images that carry their own colors). */
.tm-diagram { width: 100%; overflow-x: auto; padding: var(--space-2) 0; }
.tm-diagram img.tm-svg { display: block; max-width: 100%; height: auto; }
.tm-legend { display: flex; flex-wrap: wrap; gap: var(--space-4); color: var(--text-muted);
  font-size: var(--type-sm); margin-top: var(--space-2); }
.tm-legend span::before { content: ""; display: inline-block; width: 10px; height: 10px;
  border-radius: 50%; margin-right: 6px; vertical-align: -1px; background: var(--dot); }

/* The wizard's run bar once a run has started: one compact line. */
.st-key-tm_runline { gap: var(--space-3); padding: 6px var(--space-3); border: 1px solid var(--border);
  border-radius: var(--radius-md); background: var(--bg-raised); }
.st-key-tm_runline [data-testid="stElementContainer"]:first-child { flex: 1 1 auto; min-width: 0; }
.tm-runline { margin: 0; color: var(--text-soft); font-size: var(--type-sm); white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; }
.tm-runline strong { color: var(--text-primary); font-weight: 600; }

/* List rows. */
.tm-row-meta { color: var(--text-muted); font-size: var(--type-sm); }
.tm-row-title { color: var(--text-primary); font-weight: 600; font-size: var(--type-md); }
/* A dashboard row's title link stays on one line and ends in an ellipsis
   when it does not fit, instead of being cut mid-letter. */
[class*="st-key-dash_row_"] [data-testid="stPageLink"] a { max-width: 100%; min-width: 0; }
[class*="st-key-dash_row_"] [data-testid="stPageLink"] a > span:last-child { min-width: 0; overflow: hidden; }
[class*="st-key-dash_row_"] [data-testid="stPageLink"] a p { overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; }

/* Dashboard banner. */
.tm-urgent { display: flex; align-items: center; gap: var(--space-4); padding: var(--space-4) var(--space-5);
  border-radius: var(--radius-md); border: 1px solid var(--crit); background: rgba(239, 68, 68, 0.1);
  margin-bottom: var(--space-3); }
.tm-urgent-lead { color: var(--crit-text); font-weight: 700; text-transform: uppercase;
  font-size: var(--type-xs); letter-spacing: 0.08em; }
.tm-urgent-title { color: var(--text-primary); font-weight: 600; font-size: var(--type-md); }
.tm-urgent-meta { color: var(--text-soft); font-size: var(--type-sm); }
.tm-intro { color: var(--text-soft); max-width: 70ch; line-height: 1.6; }
"""


def apply() -> None:
    """Add the threat-model page styles (one ``<style>`` block, no layout gap)."""
    st.html(f"<style>{CSS}</style>")
