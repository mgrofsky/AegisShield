"""Technology name to NVD product mapping.

NVD is searched by CPE, and the names people type or tools report are not
CPE names (``Apache HTTP Server`` is ``apache:http_server``). The mapping
lives in ``data/tech_cpe_map.json``; a technology with no entry there is not
looked up, because a guessed product would give answers about the wrong
software.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache

from aegisshield.data import data_path


@dataclass(frozen=True)
class ProductRef:
    """The NVD ``vendor:product`` a technology name means.

    ``accepted`` is every pair NVD files this product under, the main pair
    first (nginx is ``f5:nginx`` now and ``nginx:nginx`` in older entries).
    ``name`` is the mapping file's canonical display name for the product.
    """

    vendor: str
    product: str
    name: str
    eol: str | None = None  # endoflife.date slug, when one exists
    accepted: tuple[tuple[str, str], ...] = ()


@lru_cache(maxsize=1)
def _cpe_map() -> dict[str, ProductRef]:
    doc = json.loads(data_path("tech_cpe_map.json").read_text(encoding="utf-8"))
    index: dict[str, ProductRef] = {}
    for entry in doc["products"]:
        main = (entry["vendor"], entry["product"])
        others = [tuple(pair.split(":", 1)) for pair in entry.get("accepted", [])]
        ref = ProductRef(
            vendor=main[0],
            product=main[1],
            name=entry["product_name"],
            eol=entry.get("eol"),
            accepted=(main, *(pair for pair in others if pair != main)),
        )
        for name in entry["names"]:
            index[name.strip().lower()] = ref
    return index


def product_for(name: str | None) -> ProductRef | None:
    """The mapped product for a technology name (case-insensitive), or None."""
    return _cpe_map().get((name or "").strip().lower())


@lru_cache(maxsize=1)
def _by_pair() -> dict[str, ProductRef]:
    return {f"{ref.vendor}:{ref.product}": ref for ref in _cpe_map().values()}


def product_by_pair(pair: str | None) -> ProductRef | None:
    """The mapped product whose main ``vendor:product`` pair is ``pair``, or None."""
    return _by_pair().get(pair or "")
