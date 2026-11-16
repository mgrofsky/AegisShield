"""Build the packet-capture fixtures the PCAP tests read.

Deterministic and standard library only, so the files can be rebuilt and
checked anywhere: ``python tools/build_minimal_pcap.py`` writes

- ``minimal.pcap``: one DNS query for ``example.com`` over UDP/IPv4/Ethernet.
- ``truncated.pcap``: two valid DNS queries, then a third packet record whose
  data stops partway, the way a capture stopped mid-write ends.

Every length field (pcap record, IPv4 total length, UDP length) agrees with
the bytes that follow it, and the IPv4 header checksum is correct, so real
``tshark`` reads the valid records without complaint. ``capture_bytes`` and
``dns_query_frame`` are also used by tests to build captures of any size.
"""

from __future__ import annotations

import struct
import sys
from collections.abc import Iterable
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "aegisshield" / "services" / "fixtures"

# Classic pcap, little-endian, microsecond timestamps, Ethernet link type.
PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535
# A fixed start time keeps the files byte-for-byte reproducible.
START_SECONDS = 1_700_000_000

_SRC_MAC = bytes.fromhex("020000000001")
_DST_MAC = bytes.fromhex("020000000002")


def _checksum(header: bytes) -> int:
    """The IPv4 header checksum (one's complement sum of 16-bit words)."""
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def dns_query(name: str, txid: int) -> bytes:
    """A DNS query message: one question for ``name``, type A, class IN."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return header + labels + b"\x00" + struct.pack("!HH", 1, 1)


def udp_ipv4_frame(payload: bytes, *, src: str, dst: str, sport: int, dport: int, ident: int) -> bytes:
    """An Ethernet frame carrying ``payload`` in UDP over IPv4. The UDP
    checksum is 0 (not used), which IPv4 allows."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0,
        bytes(int(o) for o in src.split(".")), bytes(int(o) for o in dst.split(".")),
    )
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    return _DST_MAC + _SRC_MAC + struct.pack("!H", 0x0800) + ip_header + udp


def dns_query_frame(name: str, index: int) -> bytes:
    """Query number ``index`` for ``name`` from 192.0.2.10 to 192.0.2.53
    (TEST-NET-1 documentation addresses)."""
    return udp_ipv4_frame(
        dns_query(name, 0x1000 + index % 0xF000),
        src="192.0.2.10", dst="192.0.2.53", sport=40000 + index % 20000, dport=53, ident=index & 0xFFFF,
    )


def capture_bytes(frames: Iterable[bytes], *, cut_last_to: int | None = None) -> bytes:
    """A pcap file holding ``frames``, one record each, a millisecond apart.

    With ``cut_last_to``, the last record's header still gives the frame's
    full length but only that many of its bytes follow, and the file ends.
    """
    out = bytearray(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))
    frames = list(frames)
    for index, frame in enumerate(frames):
        data = frame
        if cut_last_to is not None and index == len(frames) - 1:
            data = frame[:cut_last_to]
        out += struct.pack("<IIII", START_SECONDS, index * 1000, len(frame), len(frame)) + data
    return bytes(out)


def minimal_capture() -> bytes:
    """One DNS query for example.com."""
    return capture_bytes([dns_query_frame("example.com", 0)])


def truncated_capture() -> bytes:
    """Two valid DNS queries, then a third record cut short after 20 bytes."""
    frames = [dns_query_frame(name, i) for i, name in enumerate(("example.com", "example.org", "example.net"))]
    return capture_bytes(frames, cut_last_to=20)


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else FIXTURES
    (target / "minimal.pcap").write_bytes(minimal_capture())
    (target / "truncated.pcap").write_bytes(truncated_capture())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
