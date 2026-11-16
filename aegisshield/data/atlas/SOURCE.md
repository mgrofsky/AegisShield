# MITRE ATLAS data

`atlas-2026-10.json` is MITRE ATLAS release 2026.10 (collection modified 2026-10-28), converted from the official release file by `tools/refresh_mitre.py`. The app reads it through `aegisshield/pipeline/catalog_service.py` and shows the version, read from the file, on the Settings page.

- Source file: `ATLAS-2026.10.yaml`, format 6.1.0, from https://raw.githubusercontent.com/mitre-atlas/atlas-data/v2026.10/dist/v6/ATLAS-2026.10.yaml
- Source SHA-256: `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`. The same file is attached to the GitHub release https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.10 (published 2026-10-28) with the same digest. The repository's `dist/ATLAS.yaml` is deprecated upstream and is not used.
- Converted file SHA-256: `46e9f17cbeffbce48f770cb4d9ac18b35531cc08eaf0ab72bc74f9b7fc7946f1`
- Contents: 16 tactics, 129 techniques, 92 sub-techniques, 44 mitigations, and 77 case studies, which matches the release notes.

## What the conversion keeps and drops

Ids are kept exactly as published, and names and descriptions are copied unchanged. The file holds:

- `version`, `release_date`, `format_version`, `source`, `source_sha256`, and `license`.
- `tactics`: id, name, and description, in matrix order.
- `techniques`: every technique and sub-technique with its id, name, parent id (`null` for a top-level technique), tactic ids and names, and description.
- `mitigations`: id, name, description, and the technique ids it addresses.
- `case_studies`: id, name, summary (the release's description), and the technique ids it used, each once, in first-use order.

Left out because the app has no use for them: references, UUIDs, created and modified dates, object types, ATT&CK cross-references, technique maturity and platforms, mitigation categories and lifecycle phases, case study actor, target, reporter, type, and dates, the per-step text and order of case studies, the text on each mitigation-to-technique link, and the entities and software sections.

## License

From the `LICENSE` file of https://github.com/mitre-atlas/atlas-data at tag `v2026.10`:

> Copyright 2021-2026 MITRE
>
> Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
>
> Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

The ATLAS site's Terms of Use (https://atlas.mitre.org/terms) state the same Apache 2.0 license and add: "This project makes use of MITRE ATT&CK®. ATT&CK® Terms of Use - https://attack.mitre.org/resources/terms-of-use/". The `license` field inside the JSON says this. An earlier hand-made file said its content was "reproduced verbatim", which was not accurate for its shortened descriptions; that file has been removed.

## How to refresh

Run `python tools/refresh_mitre.py` from the repository root. It downloads the pinned YAML (HTTPS from raw.githubusercontent.com only, no redirects, a size cap, a timeout per read, and a 600 second deadline), checks its SHA-256 and release version, parses it with `yaml.safe_load`, checks that every tactic, parent, mitigation, and case study refers only to ids in the release, checks the converted bytes against their own pin (`ATLAS_JSON_SHA256`), and only then writes the JSON, renamed into place together with the ATT&CK files once all are ready. The app reads JSON only and does not import yaml. `python tools/refresh_mitre.py --check` verifies the file on disk against its pin without the network. To move to a new release, see the steps at the top of the tool.
