"""The capture fixtures are well formed, checked without tshark, so a
malformed file cannot pass where tshark is absent. They are also exactly
what ``tools/build_minimal_pcap.py`` builds."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "aegisshield" / "services" / "fixtures"


def _builder():
    spec = importlib.util.spec_from_file_location("build_minimal_pcap", ROOT / "tools" / "build_minimal_pcap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _records(data: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """(orig_len, captured bytes) per record, and any bytes after the last whole record."""
    magic, major, minor, _zone, _sig, _snap, link = struct.unpack("<IHHiIII", data[:24])
    assert (magic, major, minor, link) == (0xA1B2C3D4, 2, 4, 1)
    out, pos = [], 24
    while pos + 16 <= len(data):
        _sec, _usec, incl, orig = struct.unpack("<IIII", data[pos:pos + 16])
        if pos + 16 + incl > len(data):
            break
        out.append((orig, data[pos + 16:pos + 16 + incl]))
        pos += 16 + incl
    return out, data[pos:]


def _check_frame(orig: int, frame: bytes) -> None:
    assert orig == len(frame)
    assert frame[12:14] == b"\x08\x00"
    ip = frame[14:34]
    total = struct.unpack("!H", ip[2:4])[0]
    assert total == len(frame) - 14
    words = struct.unpack("!10H", ip)
    folded = sum(words)
    while folded >> 16:
        folded = (folded & 0xFFFF) + (folded >> 16)
    assert folded == 0xFFFF, "IPv4 header checksum"
    udp_len = struct.unpack("!H", frame[38:40])[0]
    assert udp_len == total - 20


def test_minimal_capture_ends_on_a_record_boundary_with_agreeing_lengths() -> None:
    data = (FIXTURES / "minimal.pcap").read_bytes()
    records, rest = _records(data)
    assert rest == b"" and len(records) == 1
    _check_frame(*records[0])
    assert b"\x07example\x03com\x00" in records[0][1]


def test_truncated_capture_has_two_whole_records_then_a_cut_one() -> None:
    data = (FIXTURES / "truncated.pcap").read_bytes()
    records, rest = _records(data)
    assert len(records) == 2
    for orig, frame in records:
        _check_frame(orig, frame)
    _sec, _usec, incl, orig = struct.unpack("<IIII", rest[:16])
    assert incl == orig and len(rest) - 16 < incl


def test_fixtures_match_the_builder() -> None:
    builder = _builder()
    assert (FIXTURES / "minimal.pcap").read_bytes() == builder.minimal_capture()
    assert (FIXTURES / "truncated.pcap").read_bytes() == builder.truncated_capture()
