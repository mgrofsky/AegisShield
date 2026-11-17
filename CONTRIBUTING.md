# Contributing

Bug reports, feature requests, and pull requests are welcome. Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a bug or asking for a feature

Open an issue and pick the matching form. Take API keys, internal host names, and anything private out of what you paste.

Do not open an issue for a security vulnerability. Follow [SECURITY.md](SECURITY.md).

## Pull requests

1. For anything larger than a small fix, open an issue first so the approach can be agreed before you write it.
2. Fork the repository and branch from `main`.
3. Set up and run the checks:

   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt -r requirements-dev.txt
   ruff check .
   pytest
   ```

   Python 3.13 is what CI uses. The app runs without any key in mock mode; see the readme. No test calls a real model provider, and a pull request must not add one.
4. Add or update tests with the change. A bug fix comes with a test that fails without it.
5. Open the pull request against `main`. The test job and code scanning must pass before it can be merged.

## House rules

- Only `aegisshield/ui` imports Streamlit. Services take the model client as an argument.
- Keys are passed by value and never stored, logged, or written to an export.
- The app never contacts an address a visitor types.
- Third-party actions in workflows are pinned by full commit SHA. Python requirements are pinned by version.
- If you change code named in [NIST-SP-800-53-CONTROLS.md](NIST-SP-800-53-CONTROLS.md), update it and its JSON together.
- Bundled third-party data (MITRE ATT&CK, MITRE ATLAS, OWASP) is refreshed with the tools in `tools/`, never edited by hand.

## License

By contributing you agree that your contribution is licensed under the [AGPL-3.0](LICENSE), the license of this project.
