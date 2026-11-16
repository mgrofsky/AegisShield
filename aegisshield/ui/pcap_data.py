"""Data helpers for the PCAP analysis page (no Streamlit here).

``trim_for_storage`` decides what a saved analysis keeps, and the
``*_rows`` helpers turn tshark's text reports and field tables into rows for
tables. A stored result may come from an imported workspace, so every helper
reads it defensively.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from typing import Any

__all__ = [
    "STORED_ROWS",
    "conversation_rows",
    "field_rows",
    "pair_rows",
    "phs_rows",
    "size_words",
    "trim_for_storage",
]

# Rows a saved analysis keeps per table. The service keeps up to 2,000 SIP
# messages and 500 rows per other table; the aggregations (computed over
# every row) and the statistics reports are kept up to 220 lines. Measured
# with every table full (2,000 SIP rows, 500 per other table, full reports):
# about 1.1 MB untrimmed, about 290 KB saved, so a 10 MB workspace holds
# about thirty analyses even in the worst case.
STORED_ROWS = 200
_TABLES = ("dns_queries", "tls_sni", "http_requests")
_MAX_STAT_LINES = 220

_PHS_RE = re.compile(r"^(?P<indent>\s*)(?P<proto>\S+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)\s*$")
# Matched against a right-stripped line, so the rest needs no lazy group
# before trailing space (that form cost the square of a run of spaces).
_CONV_RE = re.compile(r"^\s*(?P<a>\S+)\s+<->\s+(?P<b>\S+)\s+(?P<rest>.+)$")
_NUMBER_RE = re.compile(r"^\d+(?:\.\d+)?$")

# Friendly column names for tshark's field names.
_COLUMNS = {
    "frame.number": "Frame",
    "frame.time_relative": "Time (s)",
    "ip.src": "Source",
    "ip.dst": "Destination",
    "dns.qry.name": "Query",
    "dns.qry.type": "Type",
    "tls.handshake.extensions_server_name": "Server name",
    "http.request.method": "Method",
    "http.host": "Host",
    "http.request.uri": "Path",
    "http.user_agent": "User agent",
    "sip.Method": "Method",
    "sip.Status-Code": "Status",
    "sip.Status-Line": "Status line",
    "sip.from.user": "From",
    "sip.to.user": "To",
    "sip.Call-ID": "Call ID",
    "sip.User-Agent": "User agent",
    "sip.Server": "Server",
    "src_ip": "Source",
    "user_agent": "User agent",
    "frame": "Frame",
}


def _lines(value: object) -> list[str]:
    return [line for line in value if isinstance(line, str)] if isinstance(value, list) else []


def trim_for_storage(result: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of an ``analyze_pcap`` result small enough to keep.

    Keeps the first ``STORED_ROWS`` SIP messages and DNS, TLS, and HTTP rows,
    every aggregation, the model's analysis, and the statistics reports (at
    most 220 lines each). ``stored_rows`` records each trimmed table's
    original row count, so the page can say what was left out.
    """
    out = copy.deepcopy(dict(result))
    trimmed: dict[str, int] = {}
    for name in _TABLES:
        rows = out.get(name)
        if isinstance(rows, list) and len(rows) > STORED_ROWS:
            trimmed[name] = len(rows)
            out[name] = rows[:STORED_ROWS]
    sip = out.get("sip")
    if isinstance(sip, dict) and isinstance(sip.get("messages"), list) and len(sip["messages"]) > STORED_ROWS:
        trimmed["sip_messages"] = len(sip["messages"])
        sip["messages"] = sip["messages"][:STORED_ROWS]
    for name in ("protocol_hierarchy", "conversations", "rtp_streams_raw"):
        lines = out.get(name)
        if isinstance(lines, list) and len(lines) > _MAX_STAT_LINES:
            trimmed[name] = len(lines)
            out[name] = lines[:_MAX_STAT_LINES]
    out["stored_rows"] = trimmed
    return out


def size_words(count: object) -> str:
    """A byte count as "812 B", "4.2 KB", or "3.1 MB"."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return "unknown size"
    if count < 1024:
        return f"{count} B"
    if count < 1024 * 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count / (1024 * 1024):.1f} MB"


def phs_rows(lines: object) -> list[dict[str, Any]]:
    """Protocol hierarchy lines as ``{Level, Protocol, Frames, Bytes}`` rows."""
    rows: list[dict[str, Any]] = []
    for line in _lines(lines):
        match = _PHS_RE.match(line)
        if match:
            rows.append({
                "Level": len(match["indent"]) // 2 + 1,
                "Protocol": match["proto"],
                "Frames": int(match["frames"]),
                "Bytes": int(match["bytes"]),
            })
    return rows


def conversation_rows(lines: object) -> list[dict[str, Any]]:
    """IP conversation lines as rows. A line whose numbers do not have the
    expected eight columns keeps them as one "Details" cell."""
    rows: list[dict[str, Any]] = []
    for line in _lines(lines):
        match = _CONV_RE.match(line.rstrip())
        if not match:
            continue
        parts = match["rest"].split()
        if len(parts) == 8 and all(_NUMBER_RE.match(p) for p in parts):
            rows.append({
                "Address A": match["a"], "Address B": match["b"],
                "Frames": int(float(parts[4])), "Bytes": int(float(parts[5])),
                "Start (s)": float(parts[6]), "Duration (s)": float(parts[7]),
                "Details": "",
            })
        else:
            rows.append({"Address A": match["a"], "Address B": match["b"], "Frames": None,
                         "Bytes": None, "Start (s)": None, "Duration (s)": None, "Details": match["rest"]})
    return rows


def field_rows(rows: object) -> list[dict[str, str]]:
    """A tshark field table with friendly column names; values as text."""
    out: list[dict[str, str]] = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, Mapping):
            out.append({_COLUMNS.get(str(k), str(k)): "" if v is None else str(v) for k, v in row.items()})
    return out


def pair_rows(pairs: object, label: str) -> list[dict[str, Any]]:
    """``[[value, count], ...]`` as ``{label, Count}`` rows."""
    out: list[dict[str, Any]] = []
    for pair in pairs if isinstance(pairs, list) else []:
        if isinstance(pair, list | tuple) and len(pair) == 2 and isinstance(pair[1], int):
            out.append({label: str(pair[0]), "Count": pair[1]})
    return out
