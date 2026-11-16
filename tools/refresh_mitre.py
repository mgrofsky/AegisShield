"""Refresh or check the bundled MITRE ATT&CK and MITRE ATLAS data.

The app reads four files: the three ATT&CK STIX bundles in
``MITRE_ATTACK_DATA/`` and one ATLAS file in ``aegisshield/data/atlas/``.
This tool is the only thing that writes them. It downloads the pinned
release files over HTTPS from one fixed host, refuses redirects, caps each
download's size, and checks each file's SHA-256 against the pin before it
parses anything. It then checks that each file parses and holds the pinned
release version, converts the ATLAS YAML to the JSON shape the app reads
(``yaml.safe_load`` only), and checks the converted bytes against their own
pin. Only after every file has passed does it write them: each to a temporary
file next to its target, then, once all are ready, renamed into place (a
failure while writing removes the temporary files and leaves the old files).
Each download has an overall deadline as well as a per-read timeout. The
app itself reads JSON only and never imports yaml.

``--check`` needs no network: it compares the files on disk with the pins.

To move to a new release, change the versions, URLs, and pins below, run
the tool (a download whose hash does not match the pin is refused, and the
message shows the hash it saw so the operator can check it against the
release page), run it again and, when it refuses the converted ATLAS file
because its hash does not match ``ATLAS_JSON_SHA256``, check the conversion
and set that pin to the hash it prints, then run it once more, update
``ATLAS_FILE`` in ``aegisshield/pipeline/catalog_service.py`` if the ATLAS
file name changed, remove the old ATLAS file, and update both SOURCE.md
files and the pins in ``tests/aegisshield/data/test_data.py``.

Run from the repository root:
    python tools/refresh_mitre.py            # download, check, and write
    python tools/refresh_mitre.py --check    # verify the files on disk only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegisshield.pipeline.catalog_service import (  # noqa: E402
    ATLAS_FILE,
    ATTACK_DOMAIN_FILES,
    _attack_pattern_to_entry,
)

ATTACK_VERSION = "20.1"
ATLAS_VERSION = "2026.10"
ATLAS_FORMAT_MAJOR = "6"

ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com"})
TIMEOUT_SECONDS = 120
# The longest one download may take in all. The check runs between reads,
# so a stalled read can add up to ``TIMEOUT_SECONDS`` past it.
DOWNLOAD_DEADLINE_SECONDS = 600
CHUNK_BYTES = 1 << 20

ATLAS_LICENSE = (
    "Apache License, Version 2.0. Copyright 2021-2026 MITRE. As stated in the LICENSE file of "
    "github.com/mitre-atlas/atlas-data at tag v2026.10 and on https://atlas.mitre.org/terms, "
    "which also points to the ATT&CK Terms of Use for the ATT&CK content ATLAS uses. "
    "Converted by tools/refresh_mitre.py: ids, names, and descriptions are copied unchanged; "
    "fields the app does not use are left out (see aegisshield/data/atlas/SOURCE.md)."
)


@dataclass(frozen=True)
class Pinned:
    """One release file: where it comes from, its SHA-256, and its size cap."""

    name: str
    url: str
    sha256: str
    max_bytes: int


_ATTACK_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1"

ATTACK_SOURCES: dict[str, Pinned] = {
    "enterprise": Pinned(
        ATTACK_DOMAIN_FILES["enterprise"],
        f"{_ATTACK_BASE}/enterprise-attack/enterprise-attack-20.1.json",
        "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5",
        150_000_000,
    ),
    "ics": Pinned(
        ATTACK_DOMAIN_FILES["ics"],
        f"{_ATTACK_BASE}/ics-attack/ics-attack-20.1.json",
        "3f6448369f9135ade84ff6437479441530d0b262f910dca991879a7146b524ff",
        50_000_000,
    ),
    "mobile": Pinned(
        ATTACK_DOMAIN_FILES["mobile"],
        f"{_ATTACK_BASE}/mobile-attack/mobile-attack-20.1.json",
        "632e2ec40848394f9873a7a3485fc32f92b861a4e7271f7e88e0cb02f11bb6af",
        50_000_000,
    ),
}

ATLAS_SOURCE = Pinned(
    "ATLAS-2026.10.yaml",
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/v2026.10/dist/v6/ATLAS-2026.10.yaml",
    "ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d",
    20_000_000,
)

ATLAS_JSON_NAME = ATLAS_FILE
ATLAS_JSON_SHA256 = "46e9f17cbeffbce48f770cb4d9ac18b35531cc08eaf0ab72bc74f9b7fc7946f1"

Fetcher = Callable[[Pinned, Path], str]


class RefreshError(Exception):
    """A download, check, or conversion failed; nothing was written."""


def attack_dir(root: Path) -> Path:
    """Where the ATT&CK bundles live under a repository root."""
    return root / "MITRE_ATTACK_DATA"


def atlas_dir(root: Path) -> Path:
    """Where the ATLAS file lives under a repository root."""
    return root / "aegisshield" / "data" / "atlas"


def sha256_file(path: Path) -> str:
    """The SHA-256 of a file, read in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect, so a download cannot leave the fixed host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise RefreshError(f"refused a redirect ({code}) from {req.full_url}")


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise RefreshError(f"refusing to download from {url}: only https on {sorted(ALLOWED_HOSTS)}")


def _clock() -> float:
    """Seconds on a clock that only moves forward (a function so tests can set it)."""
    return time.monotonic()


def fetch(pinned: Pinned, dest: Path) -> str:
    """Download ``pinned`` to ``dest`` within its size cap and
    ``DOWNLOAD_DEADLINE_SECONDS``; returns the SHA-256."""
    _check_url(pinned.url)
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(pinned.url, headers={"User-Agent": "refresh-mitre"})
    digest = hashlib.sha256()
    size = 0
    deadline = _clock() + DOWNLOAD_DEADLINE_SECONDS
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response, dest.open("wb") as out:
        for chunk in iter(lambda: response.read(CHUNK_BYTES), b""):
            size += len(chunk)
            if size > pinned.max_bytes:
                raise RefreshError(f"{pinned.url} is larger than the {pinned.max_bytes} byte cap")
            if _clock() > deadline:
                raise RefreshError(f"{pinned.url} did not finish within {DOWNLOAD_DEADLINE_SECONDS} seconds")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def attack_collection_version(bundle: Mapping[str, Any]) -> str | None:
    """The ``x_mitre_version`` of the bundle's collection object, if any."""
    for obj in bundle.get("objects", []) or []:
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return None


def attack_counts(bundle: Mapping[str, Any], domain: str) -> dict[str, int]:
    """Live techniques and sub-techniques, filtered as the app's catalog filters them."""
    entries = [e for e in (_attack_pattern_to_entry(o, domain) for o in bundle.get("objects", []) or [])
               if e is not None]
    subs = sum(1 for e in entries if "." in e.technique_id)
    return {"techniques": len(entries) - subs, "sub_techniques": subs}


def check_attack_bundle(path: Path, domain: str, version: str) -> dict[str, int]:
    """Parse one ATT&CK bundle and check its collection version; returns its counts."""
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RefreshError(f"{domain} bundle does not parse: {exc}") from exc
    found = attack_collection_version(bundle)
    if found != version:
        raise RefreshError(f"{domain} bundle is version {found!r}, expected {version!r}")
    counts = attack_counts(bundle, domain)
    if not counts["techniques"]:
        raise RefreshError(f"{domain} bundle holds no live techniques")
    return counts


def read_atlas_yaml(path: Path) -> dict[str, Any]:
    """Parse the ATLAS release YAML with ``yaml.safe_load`` (no tags, no code)."""
    import yaml  # Only this tool reads YAML; the app reads the converted JSON.

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RefreshError(f"ATLAS YAML does not parse: {exc}") from exc
    if not isinstance(doc, dict):
        raise RefreshError("ATLAS YAML is not a mapping")
    return doc


def _targets(relationships: Mapping[str, Any], source: str, kind: str) -> list[str]:
    """Target ids of ``source``'s relationships of ``kind``, in order, without repeats."""
    seen: list[str] = []
    for rel in (relationships.get(source) or {}).get(kind, []) or []:
        target = str(rel["target"])
        if target not in seen:
            seen.append(target)
    return seen


def _require(ids: Sequence[str], known: Mapping[str, Any], what: str) -> None:
    missing = [i for i in ids if i not in known]
    if missing:
        raise RefreshError(f"{what} refers to ids not in the release: {missing}")


def convert_atlas(doc: Mapping[str, Any], *, version: str, source: Pinned) -> dict[str, Any]:
    """The ATLAS release (format 6) as the JSON the app reads.

    Keeps ids exactly as published and copies names and descriptions
    unchanged. Each technique carries its parent id (None for a top-level
    technique) and its tactics; each mitigation the technique ids it
    addresses; each case study its summary and the technique ids it uses.
    """
    fmt = str(doc.get("format-version", ""))
    if fmt.split(".")[0] != ATLAS_FORMAT_MAJOR:
        raise RefreshError(f"ATLAS format {fmt!r} is not format {ATLAS_FORMAT_MAJOR}")
    collection = doc.get("collection") or {}
    if str(collection.get("version")) != version:
        raise RefreshError(f"ATLAS release is version {collection.get('version')!r}, expected {version!r}")
    tactics = doc.get("tactics") or {}
    techniques = doc.get("techniques") or {}
    mitigations = doc.get("mitigations") or {}
    cases = doc.get("case-studies") or {}
    rels = doc.get("relationships") or {}
    for section, items in (("tactics", tactics), ("techniques", techniques),
                           ("mitigations", mitigations), ("case-studies", cases)):
        if not items:
            raise RefreshError(f"ATLAS release has no {section}")
        bad = [key for key, obj in items.items() if obj.get("id") != key]
        if bad:
            raise RefreshError(f"ATLAS {section} keys do not match their ids: {bad}")

    order = _targets(rels, "ATLAS-matrix", "sequences")
    _require(order, tactics, "the matrix")
    tactic_ids = order + [t for t in tactics if t not in order]

    out_techniques = []
    for tid, obj in techniques.items():
        tactic_refs = _targets(rels, tid, "achieves")
        parents = _targets(rels, tid, "specializes")
        _require(tactic_refs, tactics, tid)
        _require(parents, techniques, tid)
        if not tactic_refs:
            raise RefreshError(f"{tid} has no tactic")
        if len(parents) > 1:
            raise RefreshError(f"{tid} has more than one parent: {parents}")
        out_techniques.append({
            "id": tid,
            "name": obj["name"],
            "parent": parents[0] if parents else None,
            "tactics": [{"id": t, "name": tactics[t]["name"]} for t in tactic_refs],
            "description": obj.get("description", "") or "",
        })

    out_mitigations = []
    for mid, obj in mitigations.items():
        targets = _targets(rels, mid, "mitigates")
        _require(targets, techniques, mid)
        out_mitigations.append({"id": mid, "name": obj["name"],
                                "description": obj.get("description", "") or "", "techniques": targets})

    out_cases = []
    for cid, obj in cases.items():
        targets = _targets(rels, cid, "employs")
        _require(targets, techniques, cid)
        out_cases.append({"id": cid, "name": obj["name"],
                          "summary": obj.get("description", "") or "", "techniques": targets})

    return {
        "version": version,
        "release_date": str(collection.get("modified-date", "")),
        "format_version": fmt,
        "source": source.url,
        "source_sha256": source.sha256,
        "license": ATLAS_LICENSE,
        "tactics": [{"id": t, "name": tactics[t]["name"], "description": tactics[t].get("description", "") or ""}
                    for t in tactic_ids],
        "techniques": out_techniques,
        "mitigations": out_mitigations,
        "case_studies": out_cases,
    }


def atlas_json_bytes(data: Mapping[str, Any]) -> bytes:
    """The converted ATLAS data as the exact bytes written to disk."""
    return (json.dumps(data, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def atlas_counts(data: Mapping[str, Any]) -> dict[str, int]:
    """Counts of each section of the converted ATLAS data."""
    subs = sum(1 for t in data["techniques"] if t["parent"])
    return {"tactics": len(data["tactics"]), "techniques": len(data["techniques"]) - subs,
            "sub_techniques": subs, "mitigations": len(data["mitigations"]),
            "case_studies": len(data["case_studies"])}


def _download(pinned: Pinned, dest: Path, fetcher: Fetcher) -> None:
    digest = fetcher(pinned, dest)
    if digest != pinned.sha256:
        raise RefreshError(f"{pinned.url} has SHA-256 {digest}, but the pin is {pinned.sha256}. "
                           "Check it against the release page before changing the pin.")


def _replace_all(pairs: Sequence[tuple[Path, Path]]) -> None:
    """Copy each ``(src, dest)`` to a temporary file next to ``dest``, then,
    only when every copy is complete, rename each into place. A failed copy
    removes the temporary files made so far and leaves every ``dest`` as it was."""
    staged: list[tuple[Path, Path]] = []
    try:
        for src, dest in pairs:
            tmp = dest.with_name(dest.name + ".tmp")
            staged.append((tmp, dest))
            with src.open("rb") as fin, tmp.open("wb") as fout:
                for chunk in iter(lambda fin=fin: fin.read(CHUNK_BYTES), b""):
                    fout.write(chunk)
    # Any failure, even an interrupt, must not leave a half-written temporary
    # file behind; the exception is raised again unchanged.
    except BaseException:
        for tmp, _dest in staged:
            if tmp.is_file():
                tmp.unlink()
        raise
    for tmp, dest in staged:
        os.replace(tmp, dest)


def refresh(root: Path, out: TextIO, *, fetcher: Fetcher = fetch,
            attack: Mapping[str, Pinned] = ATTACK_SOURCES, atlas: Pinned = ATLAS_SOURCE,
            attack_version: str = ATTACK_VERSION, atlas_version: str = ATLAS_VERSION,
            atlas_json_name: str = ATLAS_JSON_NAME, atlas_json_sha256: str = ATLAS_JSON_SHA256) -> None:
    """Download, check, convert, and then write all four files under ``root``.

    Nothing is written unless every download matches its pin, every file
    passes its checks, and the converted ATLAS bytes match
    ``atlas_json_sha256``. Prints the versions, counts, and SHA-256 written.
    """
    with tempfile.TemporaryDirectory(prefix="refresh-mitre-") as tmp_name:
        tmp = Path(tmp_name)
        counts: dict[str, dict[str, int]] = {}
        for domain, pinned in attack.items():
            dest = tmp / pinned.name
            _download(pinned, dest, fetcher)
            counts[domain] = check_attack_bundle(dest, domain, attack_version)
        yaml_path = tmp / atlas.name
        _download(atlas, yaml_path, fetcher)
        data = convert_atlas(read_atlas_yaml(yaml_path), version=atlas_version, source=atlas)
        converted = atlas_json_bytes(data)
        converted_sha = hashlib.sha256(converted).hexdigest()
        if converted_sha != atlas_json_sha256:
            raise RefreshError(f"the converted {atlas_json_name} has SHA-256 {converted_sha}, but the pin is "
                               f"{atlas_json_sha256}. Check the conversion before changing ATLAS_JSON_SHA256.")
        atlas_out = tmp / atlas_json_name
        atlas_out.write_bytes(converted)

        attack_dir(root).mkdir(parents=True, exist_ok=True)
        atlas_dir(root).mkdir(parents=True, exist_ok=True)
        _replace_all([*((tmp / p.name, attack_dir(root) / p.name) for p in attack.values()),
                      (atlas_out, atlas_dir(root) / atlas_json_name)])
        for domain, pinned in attack.items():
            out.write(f"ATT&CK {attack_version} {domain}: {counts[domain]['techniques']} techniques, "
                      f"{counts[domain]['sub_techniques']} sub-techniques, "
                      f"{pinned.name} sha256 {pinned.sha256}\n")
        written = sha256_file(atlas_dir(root) / atlas_json_name)
        c = atlas_counts(data)
        out.write(f"ATLAS {atlas_version} ({data['release_date']}): {c['tactics']} tactics, "
                  f"{c['techniques']} techniques, {c['sub_techniques']} sub-techniques, "
                  f"{c['mitigations']} mitigations, {c['case_studies']} case studies; "
                  f"source {atlas.name} sha256 {atlas.sha256}; wrote {atlas_json_name} sha256 {written}\n")


def check(root: Path, *, attack: Mapping[str, Pinned] = ATTACK_SOURCES,
          atlas_json_name: str = ATLAS_JSON_NAME, atlas_json_sha256: str = ATLAS_JSON_SHA256,
          atlas_version: str = ATLAS_VERSION) -> list[str]:
    """Problems with the files on disk against the pins; an empty list means they match."""
    problems: list[str] = []
    for pinned in attack.values():
        path = attack_dir(root) / pinned.name
        if not path.is_file():
            problems.append(f"missing {path}")
        elif sha256_file(path) != pinned.sha256:
            problems.append(f"{path} does not match its pin")
    path = atlas_dir(root) / atlas_json_name
    if not path.is_file():
        problems.append(f"missing {path}")
        return problems
    if sha256_file(path) != atlas_json_sha256:
        problems.append(f"{path} does not match its pin")
    try:
        found = json.loads(path.read_text(encoding="utf-8")).get("version")
    except ValueError:
        found = None
    if found != atlas_version:
        problems.append(f"{path} is version {found!r}, expected {atlas_version!r}")
    strays = sorted(p.name for p in atlas_dir(root).glob("atlas-*.json") if p.name != atlas_json_name)
    if strays:
        problems.append(f"old ATLAS files still present: {strays}")
    return problems


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None, root: Path = ROOT) -> int:
    """Refresh the data, or with ``--check`` verify it; returns the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the files on disk; no network")
    args = parser.parse_args(argv)
    out = stdout or sys.stdout
    if args.check:
        problems = check(root)
        for problem in problems:
            out.write(f"FAIL {problem}\n")
        if not problems:
            out.write(f"OK ATT&CK {ATTACK_VERSION} and ATLAS {ATLAS_VERSION} match their pins\n")
        return 1 if problems else 0
    try:
        refresh(root, out)
    except (RefreshError, OSError) as exc:
        out.write(f"FAIL {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
