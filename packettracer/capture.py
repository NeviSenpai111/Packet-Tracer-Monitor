"""Scapy-based sniffer that emits enriched, *outgoing* packet events.

Runs scapy's ``AsyncSniffer`` in its own thread. Each captured packet is
classified (must be sourced from a local IP), parsed, enriched with process and
DNS info, recorded into stats, and pushed onto a thread-safe handoff queue that
the asyncio server drains.
"""

from __future__ import annotations

import logging
import queue
import threading
import time

from . import config
from .dns_cache import DnsCache
from .models import DnsEvent, PacketEvent, ProcessInfo
from .netinfo import LocalAddresses
from .processes import ProcessResolver
from .stats import StatsAggregator

log = logging.getLogger("packettracer.capture")

# DNS record type numbers we care about for IP->host learning.
_DNS_A = 1
_DNS_AAAA = 28
_QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 28: "AAAA", 16: "TXT"}


def _decode_name(name) -> str:
    """Normalize a scapy DNS name (bytes or str) to a clean hostname."""
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    return name.rstrip(".")


class Sniffer:
    def __init__(self, out_queue: "queue.Queue") -> None:
        self.out = out_queue
        self.local = LocalAddresses()
        self.procs = ProcessResolver()
        self.dns = DnsCache()
        self.stats = StatsAggregator()
        self._sniffer = None
        self._running = threading.Event()

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        from scapy.all import AsyncSniffer  # heavy import, deferred

        bpf = self.local.bpf_filter()
        log.info("starting sniffer iface=%s filter=%r", config.IFACE, bpf)
        self._sniffer = AsyncSniffer(
            iface=config.IFACE,
            filter=bpf,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        # AsyncSniffer opens its capture socket on a background thread, so a
        # permission error (no root / cap_net_raw) surfaces *after* start()
        # rather than raising here. Briefly verify the thread actually came up
        # and re-raise any captured exception so callers can react.
        time.sleep(0.3)
        exc = getattr(self._sniffer, "exception", None)
        if exc is not None:
            raise exc
        thread = getattr(self._sniffer, "thread", None)
        if thread is not None and not thread.is_alive():
            raise RuntimeError("packet capture thread exited during startup")
        self._running.set()

    def stop(self) -> None:
        self._running.clear()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001 - best-effort shutdown
                pass
        self.dns.shutdown()

    # -- packet handling -----------------------------------------------------
    def _emit(self, kind: str, payload) -> None:
        try:
            self.out.put_nowait((kind, payload))
        except queue.Full:
            # Drop under backpressure rather than block the sniffer thread.
            pass

    def _on_packet(self, pkt) -> None:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        # Periodic housekeeping (cheap, guarded by timers internally).
        self.local.maybe_refresh()
        self.procs.maybe_refresh()

        # --- L3 ---
        if IP in pkt:
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            src_ip, dst_ip = ip.src, ip.dst
        else:
            return  # non-IP (ARP, etc.) — ignore

        # Direction guard: only packets *we* sent. (BPF already filters, but
        # interfaces may have changed since the filter was built.)
        if not self.local.is_local(src_ip):
            return

        ts = float(getattr(pkt, "time", time.time()))
        size = len(pkt)

        # --- L4 ---
        proto = "OTHER"
        src_port = dst_port = None
        flags = None
        if TCP in pkt:
            proto = "TCP"
            tcp = pkt[TCP]
            src_port, dst_port = int(tcp.sport), int(tcp.dport)
            flags = str(tcp.flags)
        elif UDP in pkt:
            proto = "UDP"
            udp = pkt[UDP]
            src_port, dst_port = int(udp.sport), int(udp.dport)
        elif ICMP in pkt:
            proto = "ICMP"
        elif IPv6 in pkt and ip.nh == 58:
            proto = "ICMPv6"

        # --- DNS enrichment (queries/responses) ---
        if (src_port == 53 or dst_port == 53) and self._has_dns(pkt):
            self._handle_dns(pkt, ts)

        process = self.procs.lookup(proto, src_port)
        dst_host = self.dns.get(dst_ip)

        evt = PacketEvent(
            ts=ts,
            proto=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            size=size,
            src_port=src_port,
            dst_port=dst_port,
            dst_host=dst_host,
            flags=flags,
            process=process,
        )
        self.stats.record(evt)
        self._emit("packet", evt)

    # -- DNS helpers ---------------------------------------------------------
    @staticmethod
    def _has_dns(pkt) -> bool:
        from scapy.layers.dns import DNS

        return DNS in pkt

    def _handle_dns(self, pkt, ts: float) -> None:
        from scapy.layers.dns import DNS, DNSRR

        dns = pkt[DNS]
        # Query (qr == 0): surface the requested name.
        if dns.qr == 0 and dns.qd is not None:
            qname = _decode_name(dns.qd.qname)
            qtype = _QTYPE_NAMES.get(int(dns.qd.qtype), str(dns.qd.qtype))
            self._emit("dns", DnsEvent(ts=ts, query=qname, qtype=qtype))
            return

        # Response (qr == 1): learn IP -> host mappings. In modern scapy the
        # answer section is a list of DNSRR; older versions use a single
        # record / chain — handle both.
        if dns.qr == 1 and dns.an is not None:
            try:
                answers = list(dns.an)
            except TypeError:
                answers = [dns.an]
            for rr in answers:
                if isinstance(rr, DNSRR) and int(rr.type) in (_DNS_A, _DNS_AAAA):
                    self.dns.learn(str(rr.rdata), _decode_name(rr.rrname))
