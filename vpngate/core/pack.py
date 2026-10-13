"""SoftEther PACK (port of Pack.swift): ordered list of named elements, big-endian wire format."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

# Pack value type codes.
TYPE_INT = 0
TYPE_DATA = 1
TYPE_STR = 2
TYPE_UNISTR = 3
TYPE_INT64 = 4


class PackError(Exception):
    pass


class PackTruncated(PackError):
    pass


class PackBadType(PackError):
    def __init__(self, type_code: int) -> None:
        super().__init__(f"bad pack type {type_code}")
        self.type_code = type_code


class PackBadName(PackError):
    pass


@dataclass
class PackValue:
    """One value: ('int', u32) / ('data', bytes) / ('str', text) / ('unistr', text) / ('int64', u64)."""
    kind: str
    value: Union[int, bytes, str]

    @property
    def type_code(self) -> int:
        return {"int": TYPE_INT, "data": TYPE_DATA, "str": TYPE_STR,
                "unistr": TYPE_UNISTR, "int64": TYPE_INT64}[self.kind]


@dataclass
class PackElement:
    name: str
    values: list[PackValue] = field(default_factory=list)


def _u32(b: bytes, pos: int) -> tuple[int, int]:
    if pos + 4 > len(b):
        raise PackTruncated()
    return int.from_bytes(b[pos:pos + 4], "big"), pos + 4


class Pack:
    def __init__(self) -> None:
        self.elements: list[PackElement] = []

    # MARK: add
    def add(self, name: str, value: PackValue) -> None:
        # SoftEther compares element names case-insensitively and rejects packs with duplicates.
        self.elements = [e for e in self.elements if e.name.lower() != name.lower()]
        self.elements.append(PackElement(name, [value]))

    def add_int(self, name: str, v: int) -> None:
        self.add(name, PackValue("int", v & 0xFFFFFFFF))

    def add_bool(self, name: str, v: bool) -> None:
        self.add_int(name, 1 if v else 0)

    def add_str(self, name: str, v: str) -> None:
        self.add(name, PackValue("str", v))

    def add_uni(self, name: str, v: str) -> None:
        self.add(name, PackValue("unistr", v))

    def add_data(self, name: str, v: bytes) -> None:
        self.add(name, PackValue("data", bytes(v)))

    def add_int64(self, name: str, v: int) -> None:
        self.add(name, PackValue("int64", v))

    def add_ints(self, name: str, values: list[int]) -> None:
        """A multi-valued integer element (PackAddIntEx array), e.g. the redirect "Port" list."""
        self.elements = [e for e in self.elements if e.name.lower() != name.lower()]
        self.elements.append(PackElement(name, [PackValue("int", v & 0xFFFFFFFF) for v in values]))

    def add_ipv4(self, name: str, ip: int) -> None:
        """IPv4 address stored the way SoftEther's PackAddIp does it."""
        self.add_bool(name + "@ipv6_bool", False)
        self.add_data(name + "@ipv6_array", b"\x00" * 16)
        self.add_int(name + "@ipv6_scope_id", 0)
        self.add_int(name, ip)

    # MARK: lookup
    def element(self, name: str) -> PackElement | None:
        low = name.lower()
        for e in self.elements:
            if e.name.lower() == low:
                return e
        return None

    def value(self, name: str) -> PackValue | None:
        e = self.element(name)
        return e.values[0] if e and e.values else None

    def int(self, name: str) -> int | None:
        v = self.value(name)
        if v and v.kind == "int":
            return int(v.value)
        if v and v.kind == "int64":
            return int(v.value) & 0xFFFFFFFF
        return None

    def int64(self, name: str) -> int | None:
        v = self.value(name)
        if v and v.kind == "int64":
            return int(v.value)
        if v and v.kind == "int":
            return int(v.value)
        return None

    def str(self, name: str) -> str | None:
        v = self.value(name)
        if v and v.kind in ("str", "unistr"):
            return str(v.value)
        return None

    def data(self, name: str) -> bytes | None:
        v = self.value(name)
        if v and v.kind == "data":
            return bytes(v.value)
        return None

    def _element_values(self, name: str) -> list[PackValue]:
        e = self.element(name)
        return e.values if e else []

    def ints(self, name: str) -> list[int]:
        return [int(v.value) & 0xFFFFFFFF for v in self._element_values(name)
                if v.kind in ("int", "int64")]

    def int64s(self, name: str) -> list[int]:
        return [int(v.value) for v in self._element_values(name) if v.kind in ("int", "int64")]

    def strs(self, name: str) -> list[str]:
        return [str(v.value) for v in self._element_values(name) if v.kind in ("str", "unistr")]

    def datas(self, name: str) -> list[bytes]:
        return [bytes(v.value) for v in self._element_values(name) if v.kind == "data"]

    # MARK: serialize
    def serialize(self) -> bytes:
        out = bytearray()
        out += len(self.elements).to_bytes(4, "big")
        for e in self.elements:
            name_bytes = e.name.encode("utf-8")
            out += (len(name_bytes) + 1).to_bytes(4, "big")
            out += name_bytes
            out += (e.values[0].type_code if e.values else 0).to_bytes(4, "big")
            out += len(e.values).to_bytes(4, "big")
            for v in e.values:
                if v.kind == "int":
                    out += int(v.value).to_bytes(4, "big")
                elif v.kind == "data":
                    d = v.value
                    out += len(d).to_bytes(4, "big")
                    out += d
                elif v.kind == "str":
                    b = v.value.encode("utf-8")
                    out += len(b).to_bytes(4, "big")
                    out += b
                elif v.kind == "unistr":
                    b = v.value.encode("utf-8")
                    out += (len(b) + 1).to_bytes(4, "big")
                    out += b
                    out += b"\x00"
                elif v.kind == "int64":
                    out += int(v.value).to_bytes(8, "big")
        return bytes(out)

    # MARK: parse
    @classmethod
    def parse(cls, data: bytes) -> "Pack":
        b = bytes(data)
        pos = 0
        count, pos = _u32(b, pos)
        if count >= 4096:
            raise PackTruncated()
        pack = cls()
        for _ in range(count):
            nl, pos = _u32(b, pos)
            nl -= 1
            if nl < 0 or nl >= 64:
                raise PackBadName()
            if pos + nl > len(b):
                raise PackTruncated()
            name = b[pos:pos + nl].decode("utf-8", "replace")
            pos += nl
            type_code, pos = _u32(b, pos)
            n, pos = _u32(b, pos)
            if n >= 65536:
                raise PackTruncated()
            values: list[PackValue] = []
            for _ in range(n):
                if type_code == TYPE_INT:
                    v, pos = _u32(b, pos)
                    values.append(PackValue("int", v))
                elif type_code == TYPE_DATA:
                    ln, pos = _u32(b, pos)
                    if pos + ln > len(b):
                        raise PackTruncated()
                    values.append(PackValue("data", b[pos:pos + ln]))
                    pos += ln
                elif type_code == TYPE_STR:
                    ln, pos = _u32(b, pos)
                    if pos + ln > len(b):
                        raise PackTruncated()
                    values.append(PackValue("str", b[pos:pos + ln].decode("utf-8", "replace")))
                    pos += ln
                elif type_code == TYPE_UNISTR:
                    ln, pos = _u32(b, pos)
                    if pos + ln > len(b):
                        raise PackTruncated()
                    raw = b[pos:pos + ln]
                    pos += ln
                    if raw.endswith(b"\x00"):
                        raw = raw[:-1]
                    values.append(PackValue("unistr", raw.decode("utf-8", "replace")))
                elif type_code == TYPE_INT64:
                    hi, pos = _u32(b, pos)
                    lo, pos = _u32(b, pos)
                    values.append(PackValue("int64", (hi << 32) | lo))
                else:
                    raise PackBadType(type_code)
            pack.elements.append(PackElement(name, values))
        return pack