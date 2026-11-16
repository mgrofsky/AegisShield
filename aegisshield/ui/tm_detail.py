"""Pure helpers for showing a threat model, plus the two diagrams drawn as SVG.

- The attack chain's last node does not depend on a sector pattern: it is
  "Sensitive data" whenever the profile names a sensitivity level other than
  "None", for every sector, rather than guessing a regulated data class from
  a loose word list.
- ``first_mitigation_text`` also reads the mitigations table the pipeline
  writes; skipping table lines would leave the card empty.
- The attack tree from ``attack_tree_code`` is drawn, not just counted; the
  Mermaid text is parsed by ``report_service``'s parser, the same one the
  PDF uses.

Every label placed in SVG is escaped here.
"""

from __future__ import annotations

import base64
import html
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from aegisshield.pipeline.mitre_links import technique_url
from aegisshield.services.report_service import MAX_TREE_DEPTH, _parse_mermaid_graph

__all__ = [
    "DREAD_AXES",
    "DreadRow",
    "Edge",
    "Node",
    "attack_tree_svg",
    "chain_svg",
    "derive_attack_chain",
    "dread_composite",
    "first_mitigation_text",
    "mitre_url",
    "parse_dread_table",
    "short_label",
    "svg_image",
    "stride_letter",
    "top_threat_axes",
    "top_threat_row",
]

_STRIDE = (
    ("spoofing", "S"),
    ("tampering", "T"),
    ("repudiation", "R"),
    ("information disclosure", "I"),
    ("denial of service", "D"),
    ("elevation of privilege", "E"),
)

DREAD_AXES = ("damage", "reproducibility", "exploitability", "affected", "discoverability")
_AXIS_LABELS = {
    "damage": "Damage",
    "reproducibility": "Reproducible",
    "exploitability": "Exploitable",
    "affected": "Affected",
    "discoverability": "Discoverable",
}
_SEPARATOR = re.compile(r"^:?-{2,}:?$")


def stride_letter(threat_type: object) -> str:
    """S, T, R, I, D, or E for a STRIDE category name; "" when unknown."""
    text = str(threat_type or "").lower()
    for needle, letter in _STRIDE:
        if needle in text:
            return letter
    return ""


@dataclass(frozen=True)
class DreadRow:
    """One scored threat from the DREAD table."""

    id: str
    damage: float | None
    reproducibility: float | None
    exploitability: float | None
    affected: float | None
    discoverability: float | None
    risk: float


def _number(value: object) -> float | None:
    try:
        number = float(str("" if value is None else value).strip())
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def parse_dread_table(markdown: object) -> tuple[list[DreadRow], dict[str, DreadRow]]:
    """``(rows, by_id)`` from the DREAD markdown table; rows without a numeric
    risk score, the header, and the separator are skipped."""
    rows: list[DreadRow] = []
    by_id: dict[str, DreadRow] = {}
    if not isinstance(markdown, str) or not markdown:
        return rows, by_id
    for raw in markdown.split("\n"):
        line = raw.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) < 7:
            continue
        row_id = cells[0]
        if row_id.lower() == "id" or _SEPARATOR.match(re.sub(r"\s", "", row_id)):
            continue
        risk = _number(cells[6])
        if not row_id or risk is None:
            continue
        row = DreadRow(row_id, *(_number(c) for c in cells[1:6]), risk=risk)
        rows.append(row)
        by_id[row_id] = row
    return rows, by_id


def dread_composite(rows: Sequence[DreadRow] | None) -> float | None:
    """The mean risk, rounded to one decimal; None when there is none."""
    scores = [r.risk for r in rows or [] if math.isfinite(r.risk)]
    if not scores:
        return None
    return round(sum(scores) / len(scores) + 1e-9, 1)


def top_threat_row(rows: Sequence[DreadRow] | None) -> DreadRow | None:
    """The highest-risk row (the first one on a tie)."""
    best: DreadRow | None = None
    for row in rows or []:
        if best is None or row.risk > best.risk:
            best = row
    return best


def top_threat_axes(row: DreadRow | None) -> list[tuple[str, str, float]]:
    """``(key, label, value)`` for each of the row's five axes that has a value."""
    if row is None:
        return []
    out = []
    for key in DREAD_AXES:
        value = getattr(row, key)
        if value is not None:
            out.append((key, _AXIS_LABELS[key], value))
    return out


@dataclass(frozen=True)
class Node:
    """A node in a diagram. ``kind`` picks its style (entry, asset, crit, goal, step, leaf)."""

    id: str
    label: str
    kind: str
    tag: str = ""


@dataclass(frozen=True)
class Edge:
    """A link from one node to the next; ``attack`` marks the attacker's path."""

    source: str
    target: str
    attack: bool = False


def short_label(text: object, limit: int = 28) -> str:
    """The first clause of ``text``, cut to ``limit`` characters."""
    value = str(text or "").strip()
    first = re.split(r"[.,;:]", value)[0].strip() or value
    return f"{first[: limit - 1]}..." if len(first) > limit else first


def derive_attack_chain(profile: Mapping[str, Any] | None, threats: Sequence[Any] | None,
                        dread_by_id: Mapping[str, DreadRow] | None) -> tuple[list[Node], list[Edge]]:
    """Internet, the application, the two highest-risk threats, then the data
    at stake: the attack path, built only from real data."""
    profile = profile or {}
    nodes = [Node("entry", "Internet", "entry")]
    surface = profile.get("app_type") or profile.get("surface")
    if surface:
        nodes.append(Node("surface", str(surface), "asset"))
    by_id = dread_by_id or {}
    ranked = []
    for threat in threats or []:
        if not isinstance(threat, Mapping):
            continue
        threat_id = threat.get("ID") or threat.get("id")
        label = threat.get("Scenario") or threat.get("Threat Type") or threat_id
        if threat_id and label:
            risk = by_id[threat_id].risk if threat_id in by_id else None
            ranked.append((str(threat_id), str(label), risk))
    ranked.sort(key=lambda t: -1 if t[2] is None else t[2], reverse=True)
    crit_ids = []
    for threat_id, label, _risk in ranked[:2]:
        node_id = f"crit-{threat_id}"
        crit_ids.append(node_id)
        nodes.append(Node(node_id, short_label(label, 44), "crit", tag=threat_id))
    sink = None
    sensitive = str(profile.get("sensitive_data") or "").strip()
    if sensitive and sensitive.lower() != "none":
        sink = "sink"
        nodes.append(Node(sink, "Sensitive data", "crit", tag=f"{sensitive} sensitivity"))
    edges = [
        Edge(a.id, b.id, attack=b.id in crit_ids or b.id == sink)
        for a, b in zip(nodes, nodes[1:], strict=False)
    ]
    return nodes, edges


def mitre_url(technique_id: object) -> str | None:
    """The attack.mitre.org page for an ATT&CK id, the atlas.mitre.org page for
    an ATLAS id, or None when the id has neither shape."""
    return technique_url(technique_id)


def _strip_inline(line: str) -> str:
    line = re.sub(r"^[-*+]\s+", "", line)
    line = re.sub(r"^\d+\.\s+", "", line)
    line = re.sub(r"[*_`]+", "", line)
    line = re.sub(r"^\s*>\s?", "", line)
    return line.strip()


def first_mitigation_text(markdown: object) -> str:
    """The first mitigation as plain text: the first paragraph that is not a
    heading, or the Mitigation cell of the table's first row."""
    if not isinstance(markdown, str) or not markdown:
        return ""
    buf: list[str] = []
    header: list[str] | None = None
    for raw in markdown.split("\n"):
        line = raw.strip()
        if not line:
            if buf:
                break
            continue
        if re.match(r"^#{1,6}\s", line):
            if buf:
                break
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if header is None:
                header = [c.lower() for c in cells]
            elif not all(_SEPARATOR.match(c.replace(" ", "")) for c in cells if c) and not buf:
                column = next((i for i, h in enumerate(header) if "mitigation" in h), len(cells) - 1)
                if column < len(cells) and cells[column]:
                    return _strip_inline(cells[column])
            continue
        if re.match(r"^[-=]{3,}$", line):
            continue
        buf.append(_strip_inline(line))
    return " ".join(buf).strip()


# ------------------------------------------------------------------- SVG

# The diagrams are shown as images (``st.html`` sanitizes inline SVG away),
# so each SVG carries its own styles, in the theme's colors.
_SVG_STYLE = (
    "<style>"
    ".edge{fill:none;stroke:#3a4a68;stroke-width:2}"
    ".edge.attack{stroke:#ef4444;stroke-dasharray:6 5}"
    ".node circle,.node rect{stroke-width:2}"
    ".entry circle{fill:#0f2a3a;stroke:#38bdf8}"
    ".asset circle{fill:#33260e;stroke:#f59e0b}"
    ".crit circle{fill:#3a1418;stroke:#ef4444}"
    ".goal rect{fill:#13254a;stroke:#3b82f6}"
    ".step rect{fill:#10162a;stroke:#3a4a68}"
    ".leaf rect{fill:#0b111c;stroke:#2c3a55}"
    "text{fill:#e2e8f0;font:12px Inter,'Segoe UI',system-ui,-apple-system,sans-serif}"
    ".letter{font:700 13px 'JetBrains Mono',ui-monospace,Menlo,monospace}"
    ".tid{fill:#60a5fa;font:600 11px 'JetBrains Mono',ui-monospace,Menlo,monospace}"
    "</style>"
)


def svg_image(svg: str, alt: str) -> str:
    """An ``<img>`` tag that shows ``svg`` (a data URI, so nothing is fetched)."""
    data = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f'<img class="tm-svg" alt="{_esc(alt)}" src="data:image/svg+xml;base64,{data}"/>'


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _wrap(text: str, width: int, lines: int) -> list[str]:
    words, out, line = text.split(), [], ""
    for word in words:
        if len(line) + len(word) + (1 if line else 0) <= width:
            line = f"{line} {word}".strip()
        else:
            if line:
                out.append(line)
            line = word[:width]
        if len(out) == lines:
            break
    if line and len(out) < lines:
        out.append(line)
    if len(out) == lines and len(" ".join(out)) < len(text):
        out[-1] = out[-1][: max(0, width - 3)].rstrip() + "..."
    return out


def chain_svg(nodes: Sequence[Node], edges: Sequence[Edge]) -> str:
    """The attack path: nodes left to right, alternating height, curved links."""
    width, height, margin = 760, 250, 76
    count = len(nodes)
    span = (width - 2 * margin) / (count - 1) if count > 1 else 0
    pos = {}
    for index, node in enumerate(nodes):
        x = margin + span * index if count > 1 else width / 2
        y = height * (0.56 if index % 2 == 0 else 0.34)
        pos[node.id] = (x, y)
    parts = [f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
             'role="img" aria-label="Attack path graph" '
             f'xmlns="http://www.w3.org/2000/svg">{_SVG_STYLE}']
    for edge in edges:
        if edge.source not in pos or edge.target not in pos:
            continue
        (ax, ay), (bx, by) = pos[edge.source], pos[edge.target]
        mid = (ax + bx) / 2
        cls = "edge attack" if edge.attack else "edge"
        parts.append(f'<path class="{cls}" d="M{ax:.1f},{ay:.1f} C{mid:.1f},{ay:.1f} '
                     f'{mid:.1f},{by:.1f} {bx:.1f},{by:.1f}"/>')
    for node in nodes:
        x, y = pos[node.id]
        radius = 28 if node.kind == "crit" else 26
        below = y > height / 2
        parts.append(f'<g class="node {_esc(node.kind)}"><circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}"/>')
        letter = {"entry": "IN", "asset": "APP"}.get(node.kind, "!")
        if node.tag and node.id.startswith("crit-"):
            letter = node.tag.split("-")[-1][:3]
        parts.append(f'<text class="letter" x="{x:.1f}" y="{y + 4:.1f}" '
                     f'text-anchor="middle">{_esc(letter)}</text>')
        first = y + 46 if below else y - 52
        for offset, line in enumerate(_wrap(node.label, 24, 2)):
            parts.append(f'<text x="{x:.1f}" y="{first + offset * 15:.1f}" '
                         f'text-anchor="middle">{_esc(line)}</text>')
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


_TREE_ID = re.compile(r"\b([A-Z]{2}-[A-Z]\d{2})\b")


def attack_tree_svg(code: object) -> str | None:
    """The Mermaid attack tree drawn as a left-to-right tree, or None when
    the code has no edges to draw. Levels past ``MAX_TREE_DEPTH`` are not
    drawn (the page also shows the Mermaid source)."""
    if not isinstance(code, str) or not code.strip():
        return None
    labels, children, roots = _parse_mermaid_graph(code)
    if not children:
        return None
    col_w, box_w, box_h, row_h, pad = 250, 214, 46, 58, 16
    placed: dict[str, tuple[int, int]] = {}
    order: list[str] = []
    depth_max = 0
    next_row = 0

    def place(node_id: str, depth: int, trail: frozenset[str]) -> float:
        nonlocal next_row, depth_max
        depth_max = max(depth_max, depth)
        kids = [k for k in children.get(node_id, []) if k not in trail and k not in placed]
        if depth + 1 >= MAX_TREE_DEPTH:
            kids = []
        if node_id in placed:
            return placed[node_id][1]
        if not kids:
            row = next_row
            next_row += 1
        else:
            rows = [place(k, depth + 1, trail | {node_id}) for k in kids]
            row = (min(rows) + max(rows)) / 2
        placed[node_id] = (depth, row)
        order.append(node_id)
        return row

    for root in roots:
        place(root, 0, frozenset())
    width = pad * 2 + depth_max * col_w + box_w
    height = int(pad * 2 + max(1, next_row) * row_h)
    parts = [f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
             'role="img" aria-label="Attack tree" '
             f'xmlns="http://www.w3.org/2000/svg">{_SVG_STYLE}']

    def anchor(node_id: str) -> tuple[float, float]:
        depth, row = placed[node_id]
        return pad + depth * col_w, pad + row * row_h

    for source, kids in children.items():
        if source not in placed:
            continue
        sx, sy = anchor(source)
        for kid in kids:
            if kid not in placed:
                continue
            kx, ky = anchor(kid)
            x1, y1, x2, y2 = sx + box_w, sy + box_h / 2, kx, ky + box_h / 2
            mid = (x1 + x2) / 2
            parts.append(f'<path class="edge" d="M{x1:.1f},{y1:.1f} C{mid:.1f},{y1:.1f} '
                         f'{mid:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"/>')
    for node_id in order:
        x, y = anchor(node_id)
        depth, _row = placed[node_id]
        kind = "goal" if depth == 0 else ("leaf" if not children.get(node_id) else "step")
        label = labels.get(node_id, node_id)
        match = _TREE_ID.search(label)
        tag = match.group(1) if match else ""
        text = label.replace(tag, "").strip() if tag else label
        parts.append(f'<g class="node {kind}"><rect x="{x:.1f}" y="{y:.1f}" width="{box_w}" '
                     f'height="{box_h}" rx="8"/>')
        lines = _wrap(text, 30 if not tag else 24, 2)
        top = y + box_h / 2 - (len(lines) - 1) * 7 + 4
        text_x = x + 10
        if tag:
            parts.append(f'<text class="tid" x="{text_x:.1f}" y="{y + 15:.1f}">{_esc(tag)}</text>')
            top = y + 31 - (len(lines) - 1) * 6
        for offset, line in enumerate(lines):
            parts.append(f'<text x="{text_x:.1f}" y="{top + offset * 14:.1f}">{_esc(line)}</text>')
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)
