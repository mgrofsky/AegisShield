# Scan fixtures

`garak_0.17.1_limit.report.jsonl` is a real report written by garak 0.17.1
(`promptinject.HijackHateHumans` and `encoding.InjectBase64`, two prompts
each, seed 11) against a stand-in surface that repeats any double-quoted
string it is given, through the app's own shim with a request limit of 3.
The fourth prompt hit the limit, so one attempt has no answer.

Two substitutions were made after recording, and nothing else was changed:
the scan's temporary directory became `/tmp/aegis-aiscan-fixture`, and the
garak environment's path became `/opt/garak-env`. The file holds no token,
no home directory, and no user name (`test_report.py` checks this).
