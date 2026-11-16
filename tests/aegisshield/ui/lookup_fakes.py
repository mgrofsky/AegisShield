"""Stand-ins for every outside source the vulnerability lookup asks.

Used by the page tests and by the browser evidence run, so neither touches
the network: NVD and OTX are replaced, the CISA KEV, ExploitDB, and
endoflife.date caches are seeded, and EPSS answers from a fixed table.
``install`` returns an ``undo`` callable. Strings are deliberately hostile
where the page renders them.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import requests

from aegisshield.services import (
    eol_service,
    epss_service,
    exploitdb_service,
    kev_service,
    vuln_lookup,
)
from aegisshield.services.exploitdb_service import ExploitRef
from aegisshield.services.kev_service import KevRecord
from aegisshield.services.vuln_lookup import NvdAnswer

HOSTILE = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>[click](javascript:alert(1))'


def _cve(cve_id: str, score: float | None, severity: str | None, published: str, description: str,
         version: str = "3.1") -> dict:
    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "cvss_version": version if score is not None else None,
        "severity": severity,
        "published": published,
        "description": description,
        "references": [],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


NVD = {
    ("nginx", "1.25.3"): NvdAnswer(
        [
            _cve("CVE-2024-7347", 4.7, "MEDIUM", "2024-08-14", "Out-of-bounds read in the mp4 module."),
            _cve("CVE-2023-44487", 7.5, "HIGH", "2023-10-10", "HTTP/2 rapid reset can exhaust server resources."),
            _cve("CVE-2024-24989", 7.5, "HIGH", "2024-02-14", HOSTILE),
        ],
        exact_version=True,
    ),
    ("openssl", "3.0.13"): NvdAnswer(
        [
            _cve("CVE-2024-5535", 9.1, "CRITICAL", "2024-06-27", "SSL_select_next_proto buffer overread."),
            _cve("CVE-2024-4741", None, None, "2024-05-29", "Use after free in SSL_free_buffers."),
        ],
        exact_version=True,
    ),
    ("postgresql", "16.4.0"): NvdAnswer([], exact_version=True),
}

KEV = {
    "CVE-2023-44487": KevRecord(
        cve_id="CVE-2023-44487", vendor_project="IETF", product="HTTP/2",
        vulnerability_name="HTTP/2 Rapid Reset", date_added="2023-10-10",
        short_description="Rapid reset.", required_action="Apply updates.", due_date="2023-10-31",
        known_ransomware_campaign_use="Unknown",
    ),
}

EXPLOITS = {
    "CVE-2023-44487": [ExploitRef("51770", "HTTP/2 Rapid Reset DoS", "dos", "multiple", "2023-10-20",
                                  "https://www.exploit-db.com/exploits/51770")],
}

EOL = {
    "nginx": [{"cycle": "1.25", "eol": "2024-05-29", "latest": "1.25.5"}],
    "openssl": [{"cycle": "3.0", "eol": "2026-09-07", "latest": "3.0.15"}],
    "postgresql": [{"cycle": "16", "eol": "2028-11-09", "latest": "16.6"}],
}

EPSS = {"CVE-2023-44487": ("0.94372", "0.99950"), "CVE-2024-5535": ("0.00210", "0.59500")}

OTX = [{"id": "65a1b2c3d4e5f60718293a4b", "name": "Rapid reset campaigns " + HOSTILE, "TLP": "white",
        "modified": "2024-01-12T10:00:00", "tags": []}]


def _no_network(*_args, **_kwargs):
    raise AssertionError("the lookup tried to reach the network")


def install(*, delay: float = 0.0, otx: bool = True) -> Callable[[], None]:
    """Replace every source; ``delay`` slows each NVD answer (seconds)."""
    saved = {
        "nvd": vuln_lookup.nvd_lookup, "otx": vuln_lookup.otx_lookup, "epss": epss_service._http_get,
        "get": requests.get, "cpe": vuln_lookup._nvd_search_cpe, "cve": vuln_lookup._nvd_search_cve,
    }

    def nvd_lookup(name: str, version: str | None, _key: str) -> NvdAnswer:
        if delay:
            time.sleep(delay)
        ref = vuln_lookup.product_for(name)
        key = ((ref.product if ref else name).lower(), version or "")
        return NvdAnswer([dict(c) for c in NVD.get(key, NvdAnswer([], False)).cves],
                         NVD.get(key, NvdAnswer([], False)).exact_version)

    def otx_lookup(name: str, _key: str) -> list[dict]:
        return [{"id": p["id"], "name": p["name"], "tlp": p["TLP"], "modified": p["modified"],
                 "tags": p["tags"], "url": f"https://otx.alienvault.com/pulse/{p['id']}"} for p in OTX] if otx else []

    def epss_get(params: dict, _timeout: float) -> dict:
        ids = str(params.get("cve", "")).split(",")
        return {"data": [{"cve": i, "epss": EPSS[i][0], "percentile": EPSS[i][1]} for i in ids if i in EPSS]}

    vuln_lookup.nvd_lookup = nvd_lookup
    vuln_lookup.otx_lookup = otx_lookup
    vuln_lookup._nvd_search_cpe = _no_network
    vuln_lookup._nvd_search_cve = _no_network
    epss_service._http_get = epss_get
    requests.get = _no_network
    kev_service.seed_cache_for_tests(KEV)
    exploitdb_service.seed_cache_for_tests(EXPLOITS)
    for product, cycles in EOL.items():
        eol_service.seed_cache_for_tests(product, cycles)

    def undo() -> None:
        vuln_lookup.nvd_lookup = saved["nvd"]
        vuln_lookup.otx_lookup = saved["otx"]
        vuln_lookup._nvd_search_cpe = saved["cpe"]
        vuln_lookup._nvd_search_cve = saved["cve"]
        epss_service._http_get = saved["epss"]
        requests.get = saved["get"]
        kev_service.reset_cache_for_tests()
        exploitdb_service.reset_cache_for_tests()
        eol_service.reset_cache_for_tests()

    return undo
