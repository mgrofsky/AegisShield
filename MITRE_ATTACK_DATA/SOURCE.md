# MITRE ATT&CK data

The three STIX 2.1 bundles in this directory are MITRE ATT&CK release 20.1, copied byte for byte from MITRE's `attack-stix-data` repository at tag `v20.1`. The app reads them through `aegisshield/pipeline/catalog_service.py` and shows the version, read from each bundle's collection object, on the Settings page.

| File | Source | SHA-256 |
| --- | --- | --- |
| `enterprise-attack.json` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/enterprise-attack/enterprise-attack-20.1.json | `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |
| `ics-attack.json` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/ics-attack/ics-attack-20.1.json | `3f6448369f9135ade84ff6437479441530d0b262f910dca991879a7146b524ff` |
| `mobile-attack.json` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/mobile-attack/mobile-attack-20.1.json | `632e2ec40848394f9873a7a3485fc32f92b861a4e7271f7e88e0cb02f11bb6af` |

The same three files are attached to the GitHub release https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1 (published there 2026-11-05) with the same SHA-256 digests. MITRE's version history page (https://attack.mitre.org/resources/versions/) dates ATT&CK v20.1 from October 13, 2026.

Live techniques and sub-techniques, as the app's catalog counts them (revoked and deprecated entries left out):

| Domain | 18.1 (before) | 20.1 (now) |
| --- | --- | --- |
| Enterprise | 691 (216 techniques, 475 sub-techniques) | 706 (227 techniques, 479 sub-techniques) |
| ICS | 83 (83 techniques, 0 sub-techniques) | 104 (78 techniques, 26 sub-techniques) |
| Mobile | 124 (77 techniques, 47 sub-techniques) | 125 (78 techniques, 47 sub-techniques) |

## License

From the `LICENSE.txt` file in the repository at tag `v20.1`, and the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), which state the same license:

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
>
> "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

Both also carry disclaimers: MITRE does not claim ATT&CK enumerates every possible adversary behavior, so covering its techniques does not guarantee full defensive coverage, and the material is provided "as is" without warranties. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.

## How to refresh

`tools/refresh_mitre.py` downloads the pinned files (HTTPS from raw.githubusercontent.com only, no redirects, a size cap, a timeout per read, and a 600 second deadline per file), checks each SHA-256 against its pin and each bundle's collection version, and only then writes them here: each file goes to a temporary file next to its target, and they are renamed into place only when all four are ready. `python tools/refresh_mitre.py --check` verifies the files on disk against the pins without the network. To move to a new release, see the steps at the top of the tool.
