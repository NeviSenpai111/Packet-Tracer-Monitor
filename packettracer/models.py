"""Serializable event/state models.

These dataclasses define the wire format consumed by the frontend (and the
future Claude-designed UI). Keep field names stable — they are the contract.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass(slots=True)
class ProcessInfo:
    pid: int
    name: str

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name}


@dataclass(slots=True)
class PacketEvent:
    ts: float                       # epoch seconds (float)
    proto: str                      # "TCP" | "UDP" | "ICMP" | "ICMPv6" | "OTHER"
    src_ip: str
    dst_ip: str
    size: int                       # bytes on the wire
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    dst_host: Optional[str] = None  # resolved hostname for dst_ip, if known
    flags: Optional[str] = None     # TCP flags, e.g. "S", "SA", "PA"
    process: Optional[ProcessInfo] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["process"] = self.process.to_dict() if self.process else None
        return d


@dataclass(slots=True)
class DnsEvent:
    ts: float
    query: str
    qtype: str                      # "A" | "AAAA" | "CNAME" | ...

    def to_dict(self) -> dict:
        return {"ts": self.ts, "query": self.query, "qtype": self.qtype}
