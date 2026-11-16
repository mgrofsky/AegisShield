"""Build tests/fixtures/deck_replay.json.gz from a recorded run.

Usage (one step, no network):

    python tools/build_deck_replay.py tests/fixtures/live_progress_frames.json.gz

The recorded frames are one real run's job records as a once-a-second poll
saw them. This keeps every frame, every key, every type, every id, count,
score, and time, and replaces only the free text (threat scenarios, fixes,
test titles, the attack tree root, and the streamed ``live`` text) with a
neutral example: an online retail checkout service. Text is chosen by
threat id and field, never by searching the original wording, and the
streamed text is regenerated at the same pace so the typing in the deck
moves forward the way it did in the recording.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

# Gzipped: the replay is about 2 MB of JSON.
OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "deck_replay.json.gz"
WINDOW = 400  # the longest live text the recorder kept
FIX_MAX = 298  # the recorder's cap on a fix sentence, with "..."

ROOT = "Compromise Checkout Service (orders and payment tokens)"

# One entry per threat id: scenario, impact, recommendation, fix, test
# title, test feature, four gherkin steps, attack path steps.
T = {
    "TC-S01": (
        "An attacker replays leaked password lists against the storefront login and takes over shopper accounts that reuse passwords, then checks out with their saved cards and changes the delivery address before the owner notices.",
        "High integrity impact: orders placed and addresses changed in the shopper's name. Medium confidentiality impact on saved addresses.",
        "Add breached password checks, rate limits per account and IP, and step-up verification before a saved card is charged.",
        "Check new and changed passwords against a breached password list and block known leaked ones. Rate limit login attempts per account, per IP, and per device fingerprint, with exponential backoff. Require step-up verification (a one-time passkey prompt) before a saved card is used for a new delivery address. Alert on bursts of failed logins across many accounts from one network.",
        "Attacker replays leaked passwords to take over a shopper account",
        "Resistance to credential stuffing on the storefront login",
        ("Given a shopper account protected only by a reused password", "And an attacker holds a list of leaked email and password pairs", "When the attacker submits the pairs in bulk from rotating IP addresses", "Then the login is rate limited and a saved card cannot be charged without step-up verification"),
        ("Collect leaked password lists", "Script bulk login attempts", "Rotate IP addresses", "Charge a saved card", "Redirect the delivery address"),
    ),
    "TC-S02": (
        "An attacker registers a look-alike storefront domain and sends order confirmation emails that send shoppers to a fake sign-in page, harvesting passwords and session cookies through a relay proxy to log into the real store.",
        "High confidentiality impact on shopper credentials. Medium integrity impact from fraudulent orders.",
        "Offer passkeys, publish DMARC with a reject policy, and bind sessions to the device that signed in.",
        "Offer passkeys as the default sign-in and keep passwords as a fallback only. Publish SPF, DKIM, and a DMARC reject policy for every sending domain. Bind session cookies to the device with short lifetimes and rotate them on privilege changes. Watch certificate transparency logs for look-alike domains and file takedowns quickly.",
        "Phishing relay captures a shopper session cookie",
        "Session theft through a look-alike storefront",
        ("Given a shopper who signs in with a password", "And an attacker runs a relay proxy on a look-alike domain", "When the shopper signs in through the phishing link", "Then the captured session cookie is rejected from a different device"),
        ("Register a look-alike domain", "Send fake order emails", "Relay the sign-in page", "Capture the session cookie"),
    ),
    "TC-S03": (
        "An attacker abuses a loose redirect check in the payment provider callback and receives the authorization code for a shopper's stored wallet, then uses it to approve payments as that shopper.",
        "High integrity impact on payments approved in the shopper's name.",
        "Match callback redirect URIs exactly and require PKCE on every authorization code exchange.",
        "Register exact redirect URIs for every payment and wallet integration and reject any partial or pattern match. Require PKCE on every authorization code exchange and make codes single use with a short expiry. Bind the state parameter to the shopper session and log every callback that fails validation for review.",
        "Open redirect leaks a wallet authorization code",
        "Strict redirect validation on payment callbacks",
        ("Given a wallet integration that accepts redirect URIs by prefix", "And an attacker controls a page under that prefix", "When the attacker starts an authorization with the crafted redirect", "Then the callback is refused because the URI is not an exact match"),
        ("Find the loose redirect check", "Craft a callback URL", "Capture the authorization code", "Exchange the code for a token", "Approve a payment"),
    ),
    "TC-T01": (
        "An attacker edits the cart request in the browser and lowers item prices or raises discount values before checkout, and the order service trusts the client totals instead of recalculating them on the server.",
        "High integrity impact: goods sold below cost and revenue lost.",
        "Recalculate every price, tax, and discount on the server from the catalog and the promotion rules.",
        "Recalculate prices, taxes, shipping, and discounts on the server from the catalog and the promotion engine, and ignore every total sent by the client. Sign the cart state when it is created and verify the signature at checkout. Flag orders whose paid total differs from the server total and hold them for review.",
        "Client side price change accepted at checkout",
        "Server side price and discount recalculation",
        ("Given a cart that holds two items at catalog price", "And an attacker edits the request to lower the unit price", "When the attacker submits the checkout", "Then the order total is recalculated from the catalog and the edited price is ignored"),
        ("Intercept the cart request", "Lower the unit price", "Submit the checkout", "Ship goods below cost"),
    ),
    "TC-T02": (
        "An attacker with access to a build runner pushes a modified payment script to the CDN, and the checkout page loads it and sends card numbers typed by shoppers to an outside server.",
        "High confidentiality impact on card numbers typed during checkout.",
        "Serve checkout scripts with Subresource Integrity, a strict Content Security Policy, and signed builds.",
        "Serve every checkout script with Subresource Integrity hashes and a strict Content Security Policy that lists only the payment provider. Sign build artifacts and verify signatures before deploy. Load card fields in the payment provider's hosted frame so card numbers never touch the store's own scripts. Monitor script hashes in production.",
        "Modified payment script skims card numbers",
        "Integrity of scripts on the checkout page",
        ("Given a checkout page that loads a payment script from the CDN", "And an attacker replaces that script with a modified copy", "When a shopper opens the checkout page", "Then the browser refuses the script because its integrity hash does not match"),
        ("Gain build runner access", "Modify the payment script", "Publish it to the CDN", "Send card numbers out"),
    ),
    "TC-T03": (
        "An attacker sends crafted webhook calls that look like payment provider confirmations, and the order service marks unpaid orders as paid and releases them for shipping.",
        "High integrity impact: goods shipped without payment.",
        "Verify webhook signatures and confirm each payment with the provider before an order is released.",
        "Verify the signature on every payment webhook with the provider's current key, and reject calls older than five minutes. Confirm the payment status with the provider API before an order moves to paid. Make the paid transition idempotent and log every rejected webhook with its source address for review.",
        "Forged payment webhook marks an order paid",
        "Signed and confirmed payment webhooks",
        ("Given an unpaid order waiting for confirmation", "And an attacker can reach the webhook endpoint", "When the attacker sends a forged paid event without a valid signature", "Then the order stays unpaid and the call is logged"),
        ("Find the webhook endpoint", "Forge a paid event", "Skip the signature check", "Release unpaid orders"),
    ),
    "TC-R01": (
        "A shopper disputes an order they placed, and the store cannot show who placed it because checkout events are not logged with the session, device, and address that were used.",
        "Medium impact: chargebacks lost and refunds paid without evidence.",
        "Log every checkout event with session, device, and address details in tamper-evident storage.",
        "Write an audit event for every checkout step with the account, session, device fingerprint, IP address, and delivery address. Send audit events to append-only storage with retention that covers the dispute window. Give the support team a read-only view of the trail so they can answer chargebacks with evidence.",
        "Disputed order has no audit trail",
        "Audit trail for checkout events",
        ("Given an order placed from a signed-in session", "And the shopper later disputes the charge", "When support opens the order's audit trail", "Then the session, device, and address used at checkout are shown"),
        ("Place an order", "Dispute the charge", "Find no audit trail", "Win the chargeback"),
    ),
    "TC-R02": (
        "A support agent issues refunds to their own card through the admin console, and the refunds cannot be traced to the agent because admin actions share one service account.",
        "High impact: refund fraud that cannot be attributed to a person.",
        "Give every agent a named account and log each refund with the approver.",
        "Give every support agent a named account with single sign-on and remove shared service logins from the admin console. Require a second approver for refunds above a set amount. Log every refund with the agent, approver, original payment method, and destination, and alert when a refund goes to a card that did not pay for the order.",
        "Refund fraud through a shared admin account",
        "Attributable refunds in the admin console",
        ("Given a support agent signed in with a named account", "And a refund above the approval limit", "When the agent issues the refund", "Then a second approver is required and both names are logged"),
        ("Use the shared admin login", "Issue refunds to own card", "Hide the actor", "Repeat across orders"),
    ),
    "TC-R03": (
        "An attacker who gains access to the order database deletes the log rows for orders they changed, and the store cannot reconstruct what happened.",
        "Medium impact: incident response and fraud recovery are slowed.",
        "Ship logs off the host as they are written and protect them with write-once retention.",
        "Ship application and database logs to a separate account as they are written, with write-once retention and no delete rights for application roles. Hash-chain audit records so a gap or an edit is detected. Alert on log volume drops and on any attempt to change retention settings.",
        "Attacker deletes order log rows",
        "Tamper-evident order logs",
        ("Given order logs stored with write-once retention", "And an attacker has database access", "When the attacker tries to delete log rows", "Then the delete is refused and an alert is raised"),
        ("Gain database access", "Change order records", "Delete log rows", "Cover the change"),
    ),
    "TC-I01": (
        "An attacker changes the order number in the order details URL and reads other shoppers' names, addresses, and order contents because the endpoint does not check that the order belongs to the caller.",
        "High confidentiality impact on shopper names, addresses, and purchase history.",
        "Check object ownership on every order endpoint and use unguessable order references.",
        "Check on the server that every requested order belongs to the signed-in account before returning it. Replace sequential order numbers in URLs with random references. Add automated tests that call each order endpoint as a different user. Alert on accounts that request many orders they do not own.",
        "Order details exposed by changing the order number",
        "Object level authorization on order endpoints",
        ("Given two shoppers with one order each", "And the first shopper is signed in", "When the first shopper requests the second shopper's order number", "Then the service returns not found and logs the attempt"),
        ("Find the order details URL", "Change the order number", "Read another shopper's order", "Script the enumeration"),
    ),
    "TC-I02": (
        "Detailed error pages in production show stack traces, internal hostnames, and database query text when the checkout API fails, which helps an attacker plan further attacks.",
        "Medium confidentiality impact on internal details.",
        "Return generic errors in production and send details only to internal logs.",
        "Turn off debug error pages in production and return a generic error with a reference number. Send stack traces and query text only to internal logs with access controls. Add a release check that fails when debug settings are on. Review error responses in the API gateway for leaked headers.",
        "Stack traces exposed by checkout errors",
        "Generic errors on the checkout API",
        ("Given the checkout API running in production mode", "And a request that causes a server error", "When the error is returned", "Then the response holds only a generic message and a reference number"),
        ("Trigger a checkout error", "Read the stack trace", "Map internal hosts", "Plan the next attack"),
    ),
    "TC-I03": (
        "An object storage bucket that holds order export files is readable by anyone with the link, and an attacker finds the links in a public code repository and downloads shopper data.",
        "High confidentiality impact on exported shopper and order data.",
        "Block public access on storage, use short-lived signed links, and scan repositories for secrets.",
        "Turn on block public access for every storage bucket and account. Serve export files only through short-lived signed links tied to the requesting admin. Scan code repositories and build logs for storage links and keys before merge. Review bucket policies weekly and alert on any policy that allows public reads.",
        "Public bucket exposes order exports",
        "Private storage for order exports",
        ("Given an order export stored in object storage", "And a link to it is posted in a public repository", "When an outside user opens the link", "Then access is denied because public reads are blocked"),
        ("Search public repositories", "Find export links", "Download export files", "Harvest shopper data"),
    ),
    "TC-D01": (
        "An attacker floods the discount code endpoint with guesses, exhausting the promotion service and slowing checkout for every shopper during a sale.",
        "High availability impact during peak sales.",
        "Rate limit discount code checks per session and IP, and cache valid code lookups.",
        "Apply rate limits on discount code checks per session, per IP, and per account, with exponential backoff and a global ceiling. Require a bot check for anonymous sessions that exceed the limit. Cache valid code lookups and keep the promotion service behind a queue so checkout does not wait on it. Alert on spikes in failed code checks...",
        "Attacker floods the discount code endpoint",
        "Rate limits on discount code checks",
        ("Given a sale with heavy checkout traffic", "And an attacker sends thousands of discount code guesses", "When the guesses exceed the per session limit", "Then further checks are refused and checkout latency stays normal"),
        ("Script discount code guesses", "Flood the endpoint", "Exhaust the promotion service", "Slow every checkout"),
    ),
    "TC-D02": (
        "A bot holds inventory by adding limited stock items to thousands of carts without paying, so real shoppers see items as sold out until the carts expire.",
        "High availability impact on limited releases and lost sales.",
        "Reserve stock only at payment, cap cart holds per account, and detect automated carts.",
        "Reserve stock only when payment starts, not when an item is added to a cart. Cap the quantity of limited items per account and per payment method. Expire cart holds quickly during limited releases. Detect automated carts with behavior signals and challenge them before items are held.",
        "Bot holds limited stock in thousands of carts",
        "Fair inventory holds during limited releases",
        ("Given a limited release with one hundred units", "And a bot opens thousands of carts with the item", "When the bot does not start payment", "Then no stock is held and real shoppers can buy the item"),
        ("Create many guest sessions", "Add limited items to carts", "Hold stock without paying", "Block real shoppers"),
    ),
    "TC-D03": (
        "An attacker sends search queries with huge page sizes and wildcard filters, and the catalog search cluster runs out of memory and takes product pages down with it.",
        "High availability impact on catalog and product pages.",
        "Cap page sizes, reject costly query shapes, and isolate search from product pages.",
        "Cap the page size and result window on every search endpoint and reject wildcard and regex filters from anonymous callers. Set query timeouts and memory limits on the search cluster. Serve product pages from a cache that does not depend on search. Alert on slow queries and on spikes from one client.",
        "Costly search queries exhaust the catalog cluster",
        "Bounded catalog search queries",
        ("Given the catalog search endpoint", "And a request with a page size of one million and a wildcard filter", "When the request is received", "Then it is rejected and the cluster keeps serving"),
        ("Craft costly search queries", "Send them in parallel", "Exhaust cluster memory", "Take product pages down"),
    ),
    "TC-E01": (
        "An attacker forges an access token signed with a weak shared secret, or with the algorithm set to none, and calls admin order endpoints as a store manager.",
        "High integrity and confidentiality impact on every order.",
        "Accept only asymmetric signing algorithms and validate issuer, audience, and expiry.",
        "Validate access tokens with an explicit allow list of asymmetric algorithms and reject none and shared-secret signatures. Check issuer, audience, expiry, and key id on every request. Rotate signing keys on a schedule and publish them through a key set endpoint. Test the admin API with forged tokens in CI.",
        "Forged token with a weak key reaches admin endpoints",
        "Strict access token validation",
        ("Given the admin order API", "And a token signed with the algorithm set to none", "When the token is sent to an admin endpoint", "Then the request is rejected as unauthorized"),
        ("Read a valid token", "Change the role claim", "Sign with a weak key", "Call admin endpoints", "Change any order"),
    ),
    "TC-E02": (
        "An attacker finds a support tool that accepts a role field in the profile update request, sets their own role to administrator, and gains access to refunds and customer records.",
        "High impact: full admin access from a shopper account.",
        "Never accept role fields from clients and enforce role changes through an admin-only workflow.",
        "Remove role and permission fields from every client-facing update schema and reject unknown fields. Change roles only through an admin workflow with approval and audit logging. Add tests that try to set privileged fields through public endpoints. Alert on any role change outside the workflow.",
        "Mass assignment sets a shopper role to admin",
        "Role changes only through the admin workflow",
        ("Given a shopper account", "And a profile update request with a role field set to admin", "When the request is sent", "Then the role field is rejected and the account stays a shopper"),
        ("Inspect the profile update request", "Add a role field", "Become administrator", "Access refunds"),
    ),
    "TC-E03": (
        "An attacker exploits a vulnerable image processing library in the product photo upload service, runs code in the container, and reaches the internal network where the order database runs.",
        "High impact: code running inside the store's network.",
        "Process uploads in a sandbox with no network, patch libraries quickly, and segment the network.",
        "Process uploaded images in a sandboxed worker with no network access, a read-only filesystem, and a non-root user. Patch image libraries on a fixed schedule and scan dependencies in CI. Segment the network so upload workers cannot reach the order database. Watch for unexpected outbound connections from workers.",
        "Image upload exploit reaches the internal network",
        "Sandboxed image processing for product photos",
        ("Given the product photo upload service", "And an image crafted to exploit the image library", "When the image is processed", "Then the worker has no network access and cannot reach the order database"),
        ("Craft a malicious image", "Upload a product photo", "Run code in the worker", "Move to the order database", "Read order records"),
    ),
}

# The model's improvement suggestions, streamed before the threats.
SUGGESTIONS = (
    "Describe how saved cards are stored and which payment provider handles tokenization.",
    "List every third party script loaded on the checkout page and who can change it.",
    "Say how admin and support accounts sign in and whether refunds need approval.",
    "Describe how order data is exported and where the exports are kept.",
    "Note the expected traffic during sales and the limits on search and discount endpoints.",
    "Say which services can reach the order database from inside the network.",
    "Describe how webhooks from the payment provider are verified.",
    "List the logs kept for checkout and how long they are retained.",
    "Describe the build and deploy pipeline and who can publish scripts to the CDN.",
    "Say whether passkeys or one-time codes are offered to shoppers.",
    "Describe how product photos are processed after upload.",
    "List the access token algorithms and how signing keys are rotated.",
    "Describe how bots are detected during limited releases.",
)

FIELD_INDEX = {"Scenario": 0, "Potential Impact": 1, "Recommendations": 2}
TYPE_LETTER = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information Disclosure",
               "D": "Denial of Service", "E": "Elevation of Privilege"}


def clip_fix(text: str) -> str:
    if len(text) <= FIX_MAX:
        return text
    return text[: FIX_MAX - 3].rstrip() + "..."


def tree_lines(tid: str) -> list[str]:
    node = tid[3:]
    lines = [f'    {node[0]} --> {node}["{tid}: {T[tid][4]}"]']
    for i, step in enumerate(T[tid][7]):
        lines.append(f'    {node} --> {node}{"abcde"[i]}["{step}"]')
    return lines


def gherkin(tid: str) -> str:
    v = T[tid]
    steps = "\n".join("    " + s for s in v[6])
    return f"## {tid}\n\n```gherkin\nFeature: {v[5]}\n  Scenario: {v[4]}\n{steps}\n```\n"


def window(full: str, end: int) -> str:
    end = max(0, min(end, len(full)))
    if end <= WINDOW:
        return full[:end]
    return "..." + full[end - (WINDOW - 3) : end]


class LiveRewriter:
    """New live text for each frame, paced like the recording."""

    def __init__(self, lives: list[dict]) -> None:
        self.groups: dict[tuple, int] = {}
        self.totals: dict[tuple, int] = {}
        self.prev_orig: dict[tuple, str] = {}
        self.prev_new: dict[tuple, str] = {}
        self.stride_field: dict[str, int] = {}
        self.suggestion = -1
        self.last_suggestion = ""
        for live in lives:
            g = self._group(live, count_only=True)
            if g is not None:
                self.totals[g] = self.totals.get(g, 0) + 1

    def _stride_field(self, live: dict, commit: bool) -> int:
        item = live["item"]
        field = live.get("field")
        if field in FIELD_INDEX:
            idx = FIELD_INDEX[field]
        else:
            # An unnamed field continues the last named one for this threat.
            idx = self.stride_field.get(item, 0)
        if commit:
            self.stride_field[item] = idx
        return idx

    def _group(self, live: dict, count_only: bool = False) -> tuple | None:
        stage, item = live.get("stage"), live.get("item")
        if stage in ("mitigations", "test_cases", "attack_tree") and item in T:
            return (stage, item)
        return None

    def rewrite(self, live: dict | None) -> dict | None:
        if live is None:
            return None
        out = dict(live)
        stage, item, text = live.get("stage"), live.get("item"), live.get("text") or ""
        if not text:
            return out
        if stage == "stride":
            if item in T:
                full = T[item][self._stride_field(live, commit=True)]
            else:
                if not text.startswith(self.last_suggestion) or not self.last_suggestion:
                    self.suggestion += 1
                self.last_suggestion = text
                full = SUGGESTIONS[self.suggestion % len(SUGGESTIONS)]
            out["text"] = full[: len(text)]
            return out
        group = self._group(live)
        if group is None:
            # Item-less framing (a table pipe, an opening brace, a Mermaid
            # comment) and DREAD numbers carry no prose: kept as recorded.
            return out
        if self.prev_orig.get(group) == text:
            out["text"] = self.prev_new[group]
            return out
        k = self.groups.get(group, 0)
        self.groups[group] = k + 1
        n = self.totals[group]
        if stage == "attack_tree":
            lines = tree_lines(item)
            line = lines[min(len(lines) - 1, k * len(lines) // n)]
            new = line[: max(len(text), 8)]
        else:
            full = f"| {item} | {T[item][3]}" if stage == "mitigations" else gherkin(item)
            new = window(full, round(len(full) * (k + 1) / n))
        self.prev_orig[group] = text
        self.prev_new[group] = new
        out["text"] = new
        return out


def rewrite_frames(frames: list[dict]) -> list[dict]:
    lives = [f["progress"]["deck"].get("live") for f in frames if f["progress"]["deck"].get("live")]
    live_rw = LiveRewriter(lives)
    out = []
    for frame in frames:
        frame = json.loads(json.dumps(frame))
        deck = frame["progress"]["deck"]
        if deck["tree"].get("root"):
            deck["tree"]["root"] = ROOT
        for th in deck["threats"]:
            th["scenario"] = T[th["id"]][0]
        for tid, fix in deck["fixes"].items():
            fix["text"] = clip_fix(T[tid][3])
        for tid, test in deck["tests"].items():
            test["title"] = T[tid][4]
        deck["live"] = live_rw.rewrite(deck.get("live"))
        out.append(frame)
    return out


def shape(o):
    if isinstance(o, dict):
        return {k: shape(v) for k, v in o.items()}
    if isinstance(o, list):
        return [shape(v) for v in o]
    return type(o).__name__


def main(src: str) -> None:
    data = json.load(gzip.open(src, "rt", encoding="utf-8"))
    frames = data["frames"]
    for frame in frames:
        for th in frame["progress"]["deck"]["threats"]:
            if th["id"] not in T or TYPE_LETTER[th["id"][3]] != th["type"]:
                raise SystemExit(f"unexpected threat {th['id']} {th['type']}")
    new = rewrite_frames(frames)
    for a, b in zip(frames, new, strict=True):
        if shape(a) != shape(b):
            raise SystemExit("the record shape changed")
    out = {
        "note": (
            "Replay of one recorded threat model run ("
            "tests/fixtures/live_progress_frames.json.gz), one frame per second as a poll saw it. "
            "Every key, id, count, score, and time is as recorded; the free text (scenarios, fixes, "
            "test titles, attack tree labels, streamed live text) is rewritten to a neutral example, "
            "an online retail checkout service. Built by tools/build_deck_replay.py."
        ),
        "frames": new,
        "final": data["final"],
    }
    text = json.dumps(out, separators=(",", ":"), ensure_ascii=False) + "\n"
    # mtime=0 so the same input always gives the same bytes.
    with OUT.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as fh:
        fh.write(text.encode("utf-8"))
    sys.stdout.write(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(new)} frames)\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
