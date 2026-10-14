"""A tiny, read-mostly DNS message parser/writer (port of DNSMessage.swift)."""

from __future__ import annotations


def header(p: bytes) -> tuple[int, int] | None:
    """(ancount, qdcount) or None when too short."""
    if len(p) < 12:
        return None
    return (p[6] << 8) | p[7], (p[4] << 8) | p[5]


def _skip_name(p: bytes, offset: int) -> int | None:
    """Advances past one (possibly pointer-compressed) name; returns the offset right after it."""
    o, steps = offset, 0
    while True:
        if o >= len(p) or steps >= 128:
            return None
        steps += 1
        ln = p[o]
        if ln == 0:
            return o + 1
        if ln & 0xC0 == 0xC0:
            return o + 2  # pointer: 2 bytes, terminal
        o += 1 + ln


def _read_name(p: bytes, offset: int) -> tuple[str, int] | None:
    """Decodes the labels (pointers are not followed — question names are never compressed)."""
    o, steps = offset, 0
    labels: list[str] = []
    while True:
        if o >= len(p) or steps >= 128:
            return None
        steps += 1
        ln = p[o]
        if ln == 0:
            return ".".join(labels), o + 1
        if ln & 0xC0 == 0xC0:
            return None
        if o + 1 + ln > len(p):
            return None
        labels.append(p[o + 1:o + 1 + ln].decode("utf-8", "replace"))
        o += 1 + ln


def query_name(p: bytes) -> str | None:
    """The first question's name, lowercased and dot-joined with no trailing dot; None if malformed."""
    h = header(p)
    if h is None or h[1] < 1:
        return None
    name = _read_name(p, 12)
    return name[0].lower() if name else None


def resolved_ipv4_addresses(p: bytes) -> list[str]:
    """Resolved IPv4 addresses (type-A records) in the answer section of a response."""
    h = header(p)
    if h is None:
        return []
    ancount, qdcount = h
    offset = 12
    for _ in range(qdcount):
        after = _skip_name(p, offset)
        if after is None:
            return []
        offset = after + 4  # QTYPE + QCLASS
    out: list[str] = []
    for _ in range(ancount):
        after = _skip_name(p, offset)
        if after is None or after + 10 > len(p):
            break
        offset = after
        rtype = (p[offset] << 8) | p[offset + 1]
        rdlength = (p[offset + 8] << 8) | p[offset + 9]
        offset += 10
        if offset + rdlength > len(p):
            break
        if rtype == 1 and rdlength == 4:
            out.append(f"{p[offset]}.{p[offset+1]}.{p[offset+2]}.{p[offset+3]}")
        offset += rdlength
    return out


def query_type(query: bytes) -> int | None:
    """The first question's QTYPE (1=A, 28=AAAA); None if malformed."""
    h = header(query)
    if h is None or h[1] < 1:
        return None
    name = _read_name(query, 12)
    if name is None:
        return None
    offset = name[1]
    if offset + 4 > len(query):
        return None
    return (query[offset] << 8) | query[offset + 1]


def noerror_nodata_response(query: bytes) -> bytes:
    """NODATA (RCODE 0, zero answers): the standard answer for AAAA when IPv6 is blocked."""
    return _fixed_rcode_response(query, 0)


def blocked_response(query: bytes) -> bytes:
    """NXDOMAIN (RCODE 3): what a `.block` domain gets back."""
    return _fixed_rcode_response(query, 3)


def servfail_response(query: bytes) -> bytes:
    """SERVFAIL (RCODE 2): whenever a query cannot be answered safely. Never a guess that could leak."""
    return _fixed_rcode_response(query, 2)


def _fixed_rcode_response(query: bytes, rcode: int) -> bytes:
    if len(query) < 12:
        return query
    out = bytearray(query)
    out[2] |= 0x80                    # QR = 1 (this is a response)
    out[3] = (out[3] & 0xF0) | (rcode & 0x0F)
    out[3] |= 0x80                    # RA = 1 (recursion available)
    out[6] = out[7] = 0               # ANCOUNT = 0
    out[8] = out[9] = 0               # NSCOUNT = 0
    out[10] = out[11] = 0             # ARCOUNT = 0
    # Drop anything past the question section (be safe even if the query carried more).
    after_question = _skip_name(out, 12)
    if after_question is not None and after_question + 4 <= len(out):
        return bytes(out[:after_question + 4])
    return bytes(out)