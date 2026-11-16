"""Data helpers for the vulnerability lookup page (no Streamlit here).

Turns what the visitor picked or pasted into lookup input, and a finished
lookup result into the rows, filters, and files the page shows. The result
may come from an imported workspace, so every helper reads it defensively:
a missing or wrongly typed field is treated as absent, never trusted.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from aegisshield.data import data_path
from aegisshield.services import vuln_lookup
from aegisshield.services.vuln_lookup import DetectedTech

__all__ = [
    "FILTER_SEVERITIES",
    "SORT_CHOICES",
    "CveRow",
    "catalog_names",
    "eol_value",
    "cve_rows",
    "filter_rows",
    "lookup_title",
    "not_checked",
    "MAX_PASTE_CHARS",
    "MAX_PASTE_LINE_CHARS",
    "parse_pasted",
    "picked_technologies",
    "safe_url",
    "source_gaps",
    "state_label",
    "summary_value",
    "tech_label",
    "to_csv",
    "to_json",
]

# The state names as the lookup results word them.
_STATE_LABELS = {
    vuln_lookup.STATE_VULNERABILITIES_FOUND: "Vulnerabilities found",
    vuln_lookup.STATE_CHECKED_NONE_FOUND: "Checked, none found",
    vuln_lookup.STATE_NOT_CHECKED: "Not checked",
}

# What each source failure means for the visitor, keyed by the ``errors`` key
# the lookup service records.
_SOURCE_GAPS = {
    "kev": "CISA KEV catalog unavailable, so known-exploited status is unknown.",
    "epss": "EPSS scores unavailable, so exploit probability is not shown.",
    "exploitdb": "ExploitDB unavailable, so public exploits may be missing.",
    "eol": "endoflife.date did not answer, so end-of-life status is unknown.",
    "otx": "AlienVault OTX did not answer, so no OTX reports are shown.",
}

_ANSWERED = (vuln_lookup.STATE_VULNERABILITIES_FOUND, vuln_lookup.STATE_CHECKED_NONE_FOUND)

FILTER_SEVERITIES = ("Critical", "High", "Medium", "Low", "None")
SORT_CHOICES = ("Priority", "CVSS score", "EPSS probability", "Published")

# The paste box: a lookup takes at most 30 technologies, so 20,000
# characters is far more than any real list. A line is clipped before the
# banner patterns run, since they cost up to the square of a line's length;
# a real banner line is under 200 characters.
MAX_PASTE_CHARS = 20_000
MAX_PASTE_LINE_CHARS = 500
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_SAFE_URL_PREFIXES = (
    "https://nvd.nist.gov/vuln/detail/",
    "https://www.exploit-db.com/",
    "https://otx.alienvault.com/pulse/",
    "https://endoflife.date/",
)
_URL_TAIL_RE = re.compile(r"[A-Za-z0-9._~/%#=?&+-]{0,300}")
# Bounded like ``vuln_lookup._BANNER_RE``'s name, so it is linear in the line.
_BANNER_LINE_RE = re.compile(r"[A-Za-z][A-Za-z0-9._\-]{0,63}/\d")
# A cell a spreadsheet would run as a formula starts with one of these.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


# ------------------------------------------------------------------ input


@lru_cache(maxsize=1)
def catalog_names() -> tuple[str, ...]:
    """The products the lookup recognizes, by display name, sorted."""
    doc = json.loads(data_path("tech_cpe_map.json").read_text(encoding="utf-8"))
    return tuple(sorted({p["product_name"] for p in doc["products"]}, key=str.lower))


def picked_technologies(picked: Iterable[tuple[str, str]]) -> list[DetectedTech]:
    """Catalog picks (name, version as typed) as lookup input."""
    out: list[DetectedTech] = []
    for name, version in picked:
        text = " ".join((version or "").split()).removeprefix("v").removeprefix("V")
        out.append(DetectedTech(name=name, version=text or None, source="selected", raw=name))
    return out


def parse_pasted(raw: str) -> list[DetectedTech]:
    """A pasted list in any format the lookup's parsers accept.

    JSON (a list of ``{name, version}``, ``{"technologies": [...]}``, or a
    ``{name: version}`` mapping) when the text parses as JSON; otherwise one
    technology per line, where a line holding ``Name/1.2.3`` banners is read
    for those banners and any other line as ``name version``.
    The text is read up to ``MAX_PASTE_CHARS`` and each line up to
    ``MAX_PASTE_LINE_CHARS`` (the page refuses a longer paste first).
    """
    text = (raw or "")[:MAX_PASTE_CHARS].strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            return vuln_lookup.parse_json_input(json.loads(text))
        except (json.JSONDecodeError, RecursionError):
            pass
    found: list[DetectedTech] = []
    for line in text.splitlines():
        line = line[:MAX_PASTE_LINE_CHARS]
        if _BANNER_LINE_RE.search(line):
            found.extend(vuln_lookup.parse_text(line))
        else:
            found.extend(vuln_lookup.parse_tech_list(line))
    seen: dict[str, DetectedTech] = {}
    for tech in found:
        seen.setdefault(tech.key(), tech)
    return list(seen.values())


def lookup_title(technologies: Sequence[DetectedTech]) -> str:
    """A short title for a saved lookup: the first few names."""
    names = [t.name for t in technologies]
    head = ", ".join(names[:3])
    rest = len(names) - 3
    return f"{head} and {rest} more" if rest > 0 else head or "Lookup"


# ----------------------------------------------------------------- result


def _technologies(result: object) -> list[Mapping[str, Any]]:
    items = result.get("technologies") if isinstance(result, Mapping) else None
    return [t for t in items if isinstance(t, Mapping)] if isinstance(items, list) else []


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def safe_url(value: object) -> str | None:
    """``value`` when it is an https link to one of the lookup's sources, else None."""
    url = _text(value)
    for prefix in _SAFE_URL_PREFIXES:
        if url.startswith(prefix) and _URL_TAIL_RE.fullmatch(url[len(prefix):]):
            return url
    return None


def state_label(entry: Mapping[str, Any]) -> str:
    """The technology's state in the lookup results' words."""
    return _STATE_LABELS.get(_text(entry.get("state")), "Not checked")


def summary_value(summary: object, key: str) -> str:
    """One summary count as text; an unknown count reads "Not checked", never 0."""
    value = _count(summary.get(key)) if isinstance(summary, Mapping) else None
    return "Not checked" if value is None else str(value)


def tech_label(entry: Mapping[str, Any]) -> str:
    """``name version`` for a technology entry."""
    name, version = _text(entry.get("name")), _text(entry.get("version"))
    return f"{name} {version}" if version else name


def not_checked(result: object) -> list[str]:
    """The service's sentence for every technology that was not checked."""
    out: list[str] = []
    for entry in _technologies(result):
        if entry.get("state") not in _ANSWERED:
            out.append(_text(entry.get("description")) or f"{tech_label(entry)}: not checked.")
    return out


_NO_EPSS = "EPSS returned no scores for this lookup, so exploit probability is not shown."
_NO_OTX = "AlienVault OTX was not asked, because no OTX key was set."


def source_gaps(result: object, request: object = None) -> list[str]:
    """One sentence per source that failed or was not asked.

    EPSS failures are silent in the service (every row is simply left
    unscored), so a lookup with CVE rows and not one EPSS score says so.
    OTX is named when the request shows it was not asked.
    """
    seen: list[str] = []
    for entry in _technologies(result):
        errors = entry.get("errors")
        for key in errors if isinstance(errors, Mapping) else ():
            sentence = _SOURCE_GAPS.get(key)
            if sentence and sentence not in seen:
                seen.append(sentence)
    rows = cve_rows(result)
    if rows and all(r.epss is None for r in rows) and _SOURCE_GAPS["epss"] not in seen:
        seen.append(_NO_EPSS)
    if isinstance(request, Mapping) and request.get("otx_requested") is False:
        seen.append(_NO_OTX)
    return seen


def eol_value(result: object) -> str:
    """The end-of-life count as text: "Not checked" when no technology was
    looked up or endoflife.date failed for one, since the count would then
    read lower than it is."""
    entries = _technologies(result)
    looked_up = [e for e in entries if e.get("state") in _ANSWERED]
    if not looked_up or any(isinstance(e.get("errors"), Mapping) and "eol" in e["errors"] for e in entries):
        return "Not checked"
    return str(sum(1 for e in entries if isinstance(e.get("eol"), Mapping) and e["eol"].get("is_eol")))


@dataclass(frozen=True)
class CveRow:
    """One CVE row as the page shows it, already checked for type."""

    tech_index: int
    technology: str
    cve_id: str
    url: str | None
    score: float | None
    cvss_version: str
    severity: str
    known_exploited: bool | None
    kev_due: str
    epss: float | None
    epss_percentile: float | None
    exploits: tuple[tuple[str, str | None], ...]
    # False when ExploitDB failed for this technology: no exploits listed
    # then means "unknown", not "none".
    exploits_known: bool
    published: str
    description: str

    @property
    def has_exploit(self) -> bool:
        """True when ExploitDB lists a public exploit for this CVE."""
        return bool(self.exploits)


def _severity(value: object) -> str:
    word = _text(value).strip().capitalize()
    return word if word in {"Critical", "High", "Medium", "Low"} else "None"


def cve_rows(result: object) -> list[CveRow]:
    """Every CVE row in the result, with its exploits attached, in result order."""
    rows: list[CveRow] = []
    for index, entry in enumerate(_technologies(result)):
        exploits: dict[str, list[tuple[str, str | None]]] = {}
        for ref in entry.get("exploits") if isinstance(entry.get("exploits"), list) else []:
            if isinstance(ref, Mapping):
                label = f"EDB-{_text(ref.get('edb_id'))}" if _text(ref.get("edb_id")) else "ExploitDB"
                exploits.setdefault(_text(ref.get("cve_id")), []).append((label, safe_url(ref.get("url"))))
        for cve in entry.get("cves") if isinstance(entry.get("cves"), list) else []:
            if not isinstance(cve, Mapping):
                continue
            cve_id = _text(cve.get("cve_id"))
            kev = cve.get("kev") if isinstance(cve.get("kev"), Mapping) else {}
            known = cve.get("known_exploited")
            valid_id = bool(_CVE_ID_RE.fullmatch(cve_id))
            rows.append(
                CveRow(
                    tech_index=index,
                    technology=tech_label(entry),
                    cve_id=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if valid_id else None,
                    score=_number(cve.get("cvss_score")),
                    cvss_version=_text(cve.get("cvss_version")),
                    severity=_severity(cve.get("severity")),
                    known_exploited=known if isinstance(known, bool) else None,
                    kev_due=_text(kev.get("due_date")),
                    epss=_number(cve.get("epss")),
                    epss_percentile=_number(cve.get("epss_percentile")),
                    exploits=tuple(exploits.get(cve_id, ())),
                    exploits_known=not (isinstance(entry.get("errors"), Mapping)
                                        and "exploitdb" in entry["errors"]),
                    published=_text(cve.get("published")),
                    description=_text(cve.get("description")),
                )
            )
    return rows


_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}


def filter_rows(
    rows: Sequence[CveRow],
    *,
    kev_only: bool = False,
    exploit_only: bool = False,
    severities: Iterable[str] | None = None,
    sort: str = SORT_CHOICES[0],
) -> list[CveRow]:
    """The rows that pass the filters, in the chosen order.

    "Priority" keeps known exploited first, then the highest score (the
    service's order); the others sort by one field, missing values last.
    """
    allowed = set(severities) if severities is not None else set(FILTER_SEVERITIES)
    kept = [
        r for r in rows
        if (not kev_only or r.known_exploited is True)
        and (not exploit_only or r.has_exploit)
        and r.severity in allowed
    ]
    if sort == "CVSS score":
        return sorted(kept, key=lambda r: (r.score is None, -(r.score or 0.0)))
    if sort == "EPSS probability":
        return sorted(kept, key=lambda r: (r.epss is None, -(r.epss or 0.0)))
    if sort == "Published":
        return sorted(kept, key=lambda r: r.published, reverse=True)
    return sorted(
        kept,
        key=lambda r: (r.known_exploited is not True, -_SEVERITY_RANK[r.severity], -(r.score or 0.0)),
    )


# ---------------------------------------------------------------- export


def to_json(record_payload: Mapping[str, Any]) -> bytes:
    """The saved lookup (request and result) as pretty UTF-8 JSON."""
    return json.dumps(record_payload, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8")


def _cell(value: object) -> str:
    """A CSV cell that a spreadsheet will show as text, never run as a formula."""
    text = "" if value is None else str(value)
    return f"'{text}" if text.startswith(_FORMULA_START) else text


_CSV_HEADER = (
    "technology", "state", "detail", "cve_id", "cvss_score", "cvss_version", "severity",
    "known_exploited", "kev_due_date", "epss", "epss_percentile", "public_exploits",
    "published", "nvd_url",
)


def _yes_no(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def to_csv(result: object) -> bytes:
    """One row per CVE, and one row for each technology without CVE rows."""
    rows = cve_rows(result)
    by_tech: dict[int, list[CveRow]] = {}
    for row in rows:
        by_tech.setdefault(row.tech_index, []).append(row)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(_CSV_HEADER)
    for index, entry in enumerate(_technologies(result)):
        base = [tech_label(entry), state_label(entry), _text(entry.get("description"))]
        for row in by_tech.get(index, []):
            writer.writerow([_cell(v) for v in (
                *base, row.cve_id, row.score, row.cvss_version, row.severity,
                _yes_no(row.known_exploited), row.kev_due, row.epss, row.epss_percentile,
                " ".join(label for label, _ in row.exploits) or ("" if row.exploits_known else "unknown"),
                row.published, row.url,
            )])
        if index not in by_tech:
            writer.writerow([_cell(v) for v in (*base, *[""] * (len(_CSV_HEADER) - 3))])
    return out.getvalue().encode("utf-8")
