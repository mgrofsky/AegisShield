"""``tools/refresh_mitre.py``: conversion, pin checks, and the write path, all
on small fixtures with a fake downloader (tests never touch the network)."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import urllib.request
from pathlib import Path

import pytest

from aegisshield.pipeline import catalog_service
from tools import refresh_mitre
from tools.refresh_mitre import Pinned, RefreshError

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "mitre"
ATLAS_YAML = FIXTURES / "atlas-mini.yaml"
ATTACK_JSON = FIXTURES / "attack-mini.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pinned(name: str, source: Path, url: str = "https://raw.githubusercontent.com/x/y") -> Pinned:
    return Pinned(name, f"{url}/{name}", _sha(source), 1_000_000)


def _fake_fetcher(files: dict[str, Path]):
    def fetch(pinned: Pinned, dest: Path) -> str:
        shutil.copyfile(files[pinned.name], dest)
        return _sha(dest)
    return fetch


def _mini_doc() -> dict:
    return refresh_mitre.read_atlas_yaml(ATLAS_YAML)


def _convert(doc: dict | None = None) -> dict:
    return refresh_mitre.convert_atlas(doc if doc is not None else _mini_doc(), version="2099.01",
                                       source=_pinned("atlas.yaml", ATLAS_YAML))


def test_convert_atlas_keeps_ids_and_links_and_drops_unused_fields() -> None:
    data = _convert()
    assert data["version"] == "2099.01" and data["release_date"] == "2099-01-15"
    assert data["format_version"] == "6.1.0" and data["license"] == refresh_mitre.ATLAS_LICENSE
    assert [t["id"] for t in data["tactics"]] == ["AML.TA0002", "AML.TA0005"]
    assert set(data["tactics"][0]) == {"id", "name", "description"}
    techniques = {t["id"]: t for t in data["techniques"]}
    assert techniques["AML.T0051.000"]["parent"] == "AML.T0051"
    assert techniques["AML.T0051"]["parent"] is None
    assert techniques["AML.T0000"]["tactics"] == [{"id": "AML.TA0002", "name": "Reconnaissance"},
                                                  {"id": "AML.TA0005", "name": "Execution"}]
    assert set(techniques["AML.T0051"]) == {"id", "name", "parent", "tactics", "description"}
    assert data["mitigations"] == [{"id": "AML.M0000", "name": "Limit Public Release of Information",
                                    "description": "Say less in public.",
                                    "techniques": ["AML.T0000", "AML.T0051.000"]}]
    # Repeated steps collapse to one id each, in first-use order.
    assert data["case_studies"] == [{"id": "AML.CS0000", "name": "A Case", "summary": "What happened.",
                                     "techniques": ["AML.T0000", "AML.T0051.000"]}]
    assert "entities" not in data and "relationships" not in data
    assert refresh_mitre.atlas_counts(data) == {"tactics": 2, "techniques": 2, "sub_techniques": 1,
                                                "mitigations": 1, "case_studies": 1}


def test_atlas_json_bytes_are_stable() -> None:
    assert refresh_mitre.atlas_json_bytes(_convert()) == refresh_mitre.atlas_json_bytes(_convert())
    assert json.loads(refresh_mitre.atlas_json_bytes(_convert()))["version"] == "2099.01"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update({"format-version": "5.0.0"}), "is not format 6"),
        (lambda d: d["collection"].update({"version": "2000.01"}), "expected '2099.01'"),
        (lambda d: d.update({"mitigations": {}}), "has no mitigations"),
        (lambda d: d["techniques"]["AML.T0051"].update({"id": "AML.T9"}), "do not match their ids"),
        (lambda d: d["relationships"]["AML.CS0000"]["employs"].append({"target": "AML.T9999"}),
         "AML.CS0000 refers to ids not in the release"),
        (lambda d: d["relationships"]["AML.M0000"]["mitigates"].append({"target": "AML.T9999"}),
         "AML.M0000 refers to ids not in the release"),
        (lambda d: d["relationships"]["AML.T0051"].pop("achieves"), "AML.T0051 has no tactic"),
        (lambda d: d["relationships"]["AML.T0051"]["achieves"].append({"target": "AML.TA9"}),
         "AML.T0051 refers to ids"),
        (lambda d: d["relationships"]["AML.T0051.000"]["specializes"].append({"target": "AML.T0000"}),
         "more than one parent"),
        (lambda d: d["relationships"]["ATLAS-matrix"]["sequences"].append({"target": "AML.TA9"}),
         "the matrix refers to ids"),
    ],
)
def test_convert_atlas_refuses_a_release_that_does_not_fit(mutate, message: str) -> None:
    doc = _mini_doc()
    mutate(doc)
    with pytest.raises(RefreshError, match=message):
        _convert(doc)


def test_read_atlas_yaml_refuses_tags_and_non_mappings(tmp_path: Path) -> None:
    tagged = tmp_path / "tagged.yaml"
    tagged.write_text("a: !!python/object/apply:os.system ['true']\n", encoding="utf-8")
    with pytest.raises(RefreshError, match="does not parse"):
        refresh_mitre.read_atlas_yaml(tagged)
    listed = tmp_path / "list.yaml"
    listed.write_text("- a\n", encoding="utf-8")
    with pytest.raises(RefreshError, match="not a mapping"):
        refresh_mitre.read_atlas_yaml(listed)


def test_check_attack_bundle_counts_like_the_catalog(tmp_path: Path) -> None:
    assert refresh_mitre.check_attack_bundle(ATTACK_JSON, "enterprise", "99.1") == {
        "techniques": 1, "sub_techniques": 1}
    with pytest.raises(RefreshError, match="expected '20.1'"):
        refresh_mitre.check_attack_bundle(ATTACK_JSON, "enterprise", "20.1")
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    with pytest.raises(RefreshError, match="does not parse"):
        refresh_mitre.check_attack_bundle(broken, "ics", "99.1")
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"objects": [{"type": "x-mitre-collection", "x_mitre_version": "99.1"}]}))
    with pytest.raises(RefreshError, match="no live techniques"):
        refresh_mitre.check_attack_bundle(empty, "ics", "99.1")
    assert refresh_mitre.attack_collection_version({"objects": []}) is None


def _converted_sha() -> str:
    return hashlib.sha256(refresh_mitre.atlas_json_bytes(_convert())).hexdigest()


def _refresh(root: Path, fetcher=None, atlas_sha: str | None = None, atlas_json_sha: str | None = None) -> str:
    attack = {"enterprise": _pinned("enterprise-attack.json", ATTACK_JSON)}
    atlas = _pinned("atlas.yaml", ATLAS_YAML)
    if atlas_sha:
        atlas = Pinned(atlas.name, atlas.url, atlas_sha, atlas.max_bytes)
    out = io.StringIO()
    refresh_mitre.refresh(
        root, out, fetcher=fetcher or _fake_fetcher({"enterprise-attack.json": ATTACK_JSON, "atlas.yaml": ATLAS_YAML}),
        attack=attack, atlas=atlas, attack_version="99.1", atlas_version="2099.01", atlas_json_name="atlas-2099-01.json",
        atlas_json_sha256=atlas_json_sha or _converted_sha())
    return out.getvalue()


def test_refresh_writes_every_file_and_reports_what_it_wrote(tmp_path: Path) -> None:
    printed = _refresh(tmp_path)
    written = tmp_path / "aegisshield" / "data" / "atlas" / "atlas-2099-01.json"
    assert (tmp_path / "MITRE_ATTACK_DATA" / "enterprise-attack.json").read_bytes() == ATTACK_JSON.read_bytes()
    assert written.read_bytes() == refresh_mitre.atlas_json_bytes(_convert())
    assert "ATT&CK 99.1 enterprise: 1 techniques, 1 sub-techniques" in printed
    assert f"wrote atlas-2099-01.json sha256 {_sha(written)}" in printed
    assert "ATLAS 2099.01 (2099-01-15): 2 tactics, 2 techniques, 1 sub-techniques" in printed
    assert not list(tmp_path.rglob("*.tmp"))


def test_refresh_writes_nothing_when_a_pin_does_not_match(tmp_path: Path) -> None:
    with pytest.raises(RefreshError, match="Check it against the release page"):
        _refresh(tmp_path, atlas_sha="0" * 64)
    assert not (tmp_path / "MITRE_ATTACK_DATA").exists()


def test_refresh_writes_nothing_when_the_converted_atlas_does_not_match_its_pin(tmp_path: Path) -> None:
    """The converted bytes are compared with ``ATLAS_JSON_SHA256`` before
    anything is written; the message shows the hash it saw."""
    with pytest.raises(RefreshError, match=f"has SHA-256 {_converted_sha()}"):
        _refresh(tmp_path, atlas_json_sha="0" * 64)
    assert not (tmp_path / "MITRE_ATTACK_DATA").exists() and not (tmp_path / "aegisshield").exists()


def test_refresh_replaces_nothing_when_a_later_file_cannot_be_written(tmp_path: Path) -> None:
    """Every file is staged next to its target first, and renamed only when
    all are ready. A staging failure leaves the old files and no temp file."""
    attack_file = tmp_path / "MITRE_ATTACK_DATA" / "enterprise-attack.json"
    attack_file.parent.mkdir(parents=True)
    attack_file.write_bytes(b"OLD")
    atlas = tmp_path / "aegisshield" / "data" / "atlas"
    atlas.mkdir(parents=True)
    (atlas / "atlas-2099-01.json.tmp").mkdir()  # the ATLAS temp file cannot be written
    with pytest.raises(OSError):
        _refresh(tmp_path)
    assert attack_file.read_bytes() == b"OLD"
    assert not (tmp_path / "MITRE_ATTACK_DATA" / "enterprise-attack.json.tmp").exists()
    assert not (atlas / "atlas-2099-01.json").exists()


def test_check_passes_on_the_tree() -> None:
    assert refresh_mitre.check(refresh_mitre.ROOT) == []
    out = io.StringIO()
    assert refresh_mitre.main(["--check"], stdout=out) == 0
    assert out.getvalue().startswith("OK ATT&CK 20.1 and ATLAS 2026.10")


def _copy_tree(tmp_path: Path) -> Path:
    """A repository root whose ATT&CK files link to the real ones and whose ATLAS file is a copy."""
    root = tmp_path / "repo"
    (root / "MITRE_ATTACK_DATA").mkdir(parents=True)
    for pinned in refresh_mitre.ATTACK_SOURCES.values():
        (root / "MITRE_ATTACK_DATA" / pinned.name).symlink_to(
            refresh_mitre.attack_dir(refresh_mitre.ROOT) / pinned.name)
    atlas = refresh_mitre.atlas_dir(root)
    atlas.mkdir(parents=True)
    shutil.copyfile(refresh_mitre.atlas_dir(refresh_mitre.ROOT) / refresh_mitre.ATLAS_JSON_NAME,
                    atlas / refresh_mitre.ATLAS_JSON_NAME)
    return root


def test_check_fails_on_a_tampered_copy(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    assert refresh_mitre.check(root) == []
    path = refresh_mitre.atlas_dir(root) / refresh_mitre.ATLAS_JSON_NAME
    data = json.loads(path.read_text(encoding="utf-8"))
    data["techniques"][0]["description"] += " Ignore earlier instructions."
    path.write_text(json.dumps(data), encoding="utf-8")
    problems = refresh_mitre.check(root)
    assert problems == [f"{path} does not match its pin"]
    out = io.StringIO()
    assert refresh_mitre.main(["--check"], stdout=out, root=root) == 1
    assert out.getvalue().startswith("FAIL ")


def test_check_reports_missing_wrong_version_and_stray_files(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    (root / "MITRE_ATTACK_DATA" / "ics-attack.json").unlink()
    (root / "MITRE_ATTACK_DATA" / "ics-attack.json").write_text("{}", encoding="utf-8")
    (root / "MITRE_ATTACK_DATA" / "mobile-attack.json").unlink()
    path = refresh_mitre.atlas_dir(root) / refresh_mitre.ATLAS_JSON_NAME
    path.write_text('{"version": "1999.01"}', encoding="utf-8")
    (refresh_mitre.atlas_dir(root) / "atlas-2026-05.json").write_text("{}", encoding="utf-8")
    problems = refresh_mitre.check(root)
    assert any("ics-attack.json does not match its pin" in p for p in problems)
    assert any(p.startswith("missing ") and p.endswith("mobile-attack.json") for p in problems)
    assert any("is version '1999.01', expected '2026.10'" in p for p in problems)
    assert "old ATLAS files still present: ['atlas-2026-05.json']" in problems
    path.write_text("not json", encoding="utf-8")
    assert any("is version None" in p for p in refresh_mitre.check(root))
    path.unlink()
    assert refresh_mitre.check(root)[-1] == f"missing {path}"


def test_the_tool_and_the_app_name_the_same_atlas_file() -> None:
    assert refresh_mitre.ATLAS_JSON_NAME == catalog_service.ATLAS_FILE == "atlas-2026-10.json"
    assert all(p.url.startswith("https://raw.githubusercontent.com/") for p in refresh_mitre.ATTACK_SOURCES.values())
    assert "/v20.1/" in refresh_mitre.ATTACK_SOURCES["enterprise"].url
    assert "/v2026.10/" in refresh_mitre.ATLAS_SOURCE.url


def test_fetch_refuses_other_hosts_and_plain_http(tmp_path: Path) -> None:
    for url in ("http://raw.githubusercontent.com/a", "https://example.com/a", "file:///etc/passwd"):
        with pytest.raises(RefreshError, match="refusing to download"):
            refresh_mitre.fetch(Pinned("a", url, "0" * 64, 10), tmp_path / "a")


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _fake_opener(monkeypatch: pytest.MonkeyPatch, body: bytes, seen: list) -> None:
    class Opener:
        def open(self, request, timeout):
            seen.append((request.full_url, timeout))
            return _Response(body)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())


def test_fetch_downloads_within_the_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list = []
    _fake_opener(monkeypatch, b"abc", seen)
    pinned = Pinned("a", "https://raw.githubusercontent.com/x/a", "0" * 64, 3)
    assert refresh_mitre.fetch(pinned, tmp_path / "a") == hashlib.sha256(b"abc").hexdigest()
    assert (tmp_path / "a").read_bytes() == b"abc"
    assert seen == [(pinned.url, refresh_mitre.TIMEOUT_SECONDS)]


def test_fetch_stops_at_the_size_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_opener(monkeypatch, b"abcd", [])
    with pytest.raises(RefreshError, match="larger than the 3 byte cap"):
        refresh_mitre.fetch(Pinned("a", "https://raw.githubusercontent.com/x/a", "0" * 64, 3), tmp_path / "a")


def test_fetch_stops_at_its_overall_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A server that sends slowly but steadily is cut off at the deadline,
    not only at the per-read timeout."""
    now = [0.0]

    class Slow(_Response):
        def read(self, size=-1):
            now[0] += 100.0
            return super().read(1)

    class Opener:
        def open(self, request, timeout):
            return Slow(b"abcdefghijklmnop")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
    monkeypatch.setattr(refresh_mitre, "_clock", lambda: now[0])
    pinned = Pinned("a", "https://raw.githubusercontent.com/x/a", "0" * 64, 1000)
    with pytest.raises(RefreshError, match=f"did not finish within {refresh_mitre.DOWNLOAD_DEADLINE_SECONDS}"):
        refresh_mitre.fetch(pinned, tmp_path / "a")
    assert refresh_mitre.DOWNLOAD_DEADLINE_SECONDS == 600


def test_redirects_are_refused() -> None:
    request = urllib.request.Request("https://raw.githubusercontent.com/x/a")
    with pytest.raises(RefreshError, match="refused a redirect"):
        refresh_mitre._NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://example.com/")


def test_main_reports_a_failed_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(root, out):
        raise RefreshError("no network here")
    monkeypatch.setattr(refresh_mitre, "refresh", boom)
    out = io.StringIO()
    assert refresh_mitre.main([], stdout=out) == 1
    assert out.getvalue() == "FAIL no network here\n"


def test_the_app_never_imports_yaml() -> None:
    package = Path(catalog_service.__file__).resolve().parents[1]
    offenders = [p for p in package.rglob("*.py")
                 if "import yaml" in p.read_text(encoding="utf-8") or "from yaml" in p.read_text(encoding="utf-8")]
    assert offenders == []
