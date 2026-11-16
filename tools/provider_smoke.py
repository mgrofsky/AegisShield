"""One real model list and one short real call to a provider, for a developer.

Reads the credential from environment variables only, builds the app's own
client the way the app does (``providers.list_models``, then
``factory.get_llm``), lists the models, and makes one ``chat_text`` call of
at most 64 output tokens. It prints the provider, the model, and pass or
fail, and never prints the credential. A failure is shown as the app's fixed
sentence, or as the error's class name only.

Cost: the model list is not a model call. The one call sends a prompt of
about 20 tokens and asks for at most 64 output tokens, billed by the
provider at the chosen model's rate. Nothing runs without ``--real``.

Environment variables:
    bedrock  AEGIS_SMOKE_BEDROCK_API_KEY, AEGIS_SMOKE_BEDROCK_REGION, and
             optionally AEGIS_SMOKE_BEDROCK_MODEL
    claude   AEGIS_SMOKE_CLAUDE_API_KEY, optionally AEGIS_SMOKE_CLAUDE_MODEL
    openai   AEGIS_SMOKE_OPENAI_API_KEY, optionally AEGIS_SMOKE_OPENAI_MODEL
    gemini   AEGIS_SMOKE_GEMINI_API_KEY, optionally AEGIS_SMOKE_GEMINI_MODEL

Without a model variable, the provider's preselected model is used when it
is listed, and otherwise the first model in the list.

Run from the repository root:
    AEGIS_SMOKE_BEDROCK_API_KEY=... AEGIS_SMOKE_BEDROCK_REGION=us-east-1 \\
        python tools/provider_smoke.py --provider bedrock --real
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegisshield.config import Settings, with_model_choice  # noqa: E402
from aegisshield.core.errors import AegisError  # noqa: E402
from aegisshield.llm import factory, providers  # noqa: E402
from aegisshield.llm.providers import Credential, Provider  # noqa: E402

logger = logging.getLogger(__name__)

MAX_OUTPUT_TOKENS = 64
SYSTEM = "Answer in one short sentence."
USER = "Say hello and name the model you are."
NEEDS_REAL = ("This makes a real, billed call to the provider. Run it again with --real to make "
              "it.")


def credential_from_env(provider: Provider, env: Mapping[str, str]) -> Credential:
    """The provider's credential from ``AEGIS_SMOKE_<PROVIDER>_*`` only."""
    prefix = f"AEGIS_SMOKE_{provider.value.upper()}_"
    region = env.get(prefix + "REGION", "") if provider is Provider.BEDROCK else ""
    return Credential(api_key=env.get(prefix + "API_KEY", ""), region=region)


def _pick_model(provider: Provider, listed: Sequence[Any], wanted: str,
                settings: Settings) -> str | None:
    ids = [m.id for m in listed]
    if wanted:
        return wanted if wanted in ids else None
    return providers.preselected_model(provider, listed, settings) or (ids[0] if ids else None)


def _failure(exc: Exception) -> str:
    # An app error carries a fixed sentence; anything else is shown by class
    # name only, since its text can quote request details.
    return str(exc) if isinstance(exc, AegisError) else type(exc).__name__


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None,
         env: Mapping[str, str] | None = None,
         list_models: Callable[..., Any] | None = None,
         get_llm: Callable[..., Any] | None = None) -> int:
    """Run the check; 0 on pass, 1 on fail, 2 when ``--real`` is missing.

    ``list_models`` and ``get_llm`` default to the app's own; tests pass
    fakes.
    """
    out = stdout or sys.stdout
    env = os.environ if env is None else env
    list_models = list_models or providers.list_models
    get_llm = get_llm or factory.get_llm
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0],
                                 epilog=(__doc__ or "").split("\n\n", 1)[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=[p.value for p in Provider], required=True)
    ap.add_argument("--real", action="store_true",
                    help="Make the real, billed call (one list and one call of at most "
                         f"{MAX_OUTPUT_TOKENS} output tokens).")
    args = ap.parse_args(argv)
    if not args.real:
        out.write(NEEDS_REAL + "\n")
        return 2
    provider = Provider(args.provider)
    cred = credential_from_env(provider, env)
    settings = Settings()
    out.write(f"provider: {providers.PROVIDER_LABELS[provider]}\n")
    try:
        listed = list_models(provider, cred)
        out.write(f"models listed: {len(listed)}\n")
        model = _pick_model(provider, listed, env.get(f"AEGIS_SMOKE_{provider.value.upper()}_MODEL",
                                                      "").strip(), settings)
        if model is None:
            out.write("model: none usable (the list is empty or does not hold the model asked for)\n"
                      "result: fail\n")
            return 1
        out.write(f"model: {model}\n")
        client = get_llm(with_model_choice(settings, provider=provider.value, model=model), cred)
        answer = client.chat_text(system=SYSTEM, user=USER, model=model,
                                  max_tokens=MAX_OUTPUT_TOKENS)
    # Any failure is a result to report, not a crash; it is shown without
    # its text (``_failure``).
    except Exception as exc:  # noqa: BLE001
        logger.warning("provider smoke check failed kind=%s", type(exc).__name__)
        out.write(f"error: {_failure(exc)}\nresult: fail\n")
        return 1
    out.write(f"answer characters: {len(answer)}\n"
              "token counts: not reported by the app's client\n"
              f"result: {'pass' if answer.strip() else 'fail'}\n")
    return 0 if answer.strip() else 1


if __name__ == "__main__":
    raise SystemExit(main())
