"""A stand-in for the ``tshark`` binary that prints canned output.

The fixtures under ``fixtures/tshark`` are hand-written in the layout tshark
prints; they were not captured from a real run (tshark was not available).

The tests copy this file into a temporary ``bin`` directory as ``tshark``,
next to a ``config.json`` naming which fixture answers which query, and put
that directory first on PATH. Every call is appended to ``calls.jsonl`` so
tests can check the exact argument list. Standard library only.
"""

import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    config = json.loads((HERE / "config.json").read_text())
    with (HERE / "calls.jsonl").open("a") as log:
        log.write(json.dumps({"argv": argv, "home": os.environ.get("HOME")}) + "\n")
    if "-n" not in argv or "-r" not in argv or not os.path.isfile(argv[argv.index("-r") + 1]):
        return 2
    time.sleep(config.get("sleep", 0))
    if config.get("exit"):
        sys.stderr.write("tshark: The file appears to be damaged or corrupt.\n")
        return config["exit"]
    if "-z" in argv:
        name = config.get("stats", {}).get(argv[argv.index("-z") + 1])
    else:
        name = config.get("fields", {}).get(argv[argv.index("-Y") + 1])
    text = (Path(config["fixtures"]) / name).read_text() if name else ""
    if config.get("cut_short"):
        # What tshark 4.x does with a capture whose last record stops early:
        # the message on stderr, the output for the packets before it, exit 2.
        sys.stderr.write(
            f'tshark: The file "{argv[argv.index("-r") + 1]}" appears to have been cut short '
            "in the middle of a packet.\n"
        )
        text = text if config["cut_short"] == "with_output" else ""
    repeat = config.get("repeat", 1)
    for _ in range(repeat):
        sys.stdout.write(text)
    sys.stdout.flush()
    return 2 if config.get("cut_short") else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
