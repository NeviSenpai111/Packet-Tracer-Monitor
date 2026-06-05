"""Promiscuous LAN capture for the network monitor (page 2).

Sniffs all traffic the interface can see (no source filter), learns devices from
ARP / IP / mDNS, attributes each packet to the LAN device involved, and feeds a
per-device aggregator. An optional active ARP sweep discovers quiet devices.

What's actually visible depends on the network: on a switched LAN this host sees
device discovery (ARP), broadcast/multicast (mDNS/SSDP/DHCP) and its own traffic;
full visibility into other devices' unicast needs port mirroring or running on
the gateway.
"""

from __future__ import annotations

import ipaddress
import logging
import queue
import threading
import time

from . import config
from .dns_cache import DnsCache
from .lan import DeviceRegistry
from .netstats import NetworkStats

log = logging.getLogger("packettracer.netcapture")

_DNS_A = 1
_DNS_AAAA = 28
_QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 28: "AAAA", 16: "TXT"}


def _decode_name(name) -> str:
    if isinstance(name, bytes):
        name = name.decode("utf-8", "ignore")
    return name.rstrip(".")


class NetworkSniffer:
    def __init__(self, out_queue: "queue.Queue") -> None:
        self.out = out_queue
        self.dns = DnsCache()
        self.registry = DeviceRegistry(dns_cache=self.dns)
        self.stats = NetworkStats()
        self._sniffer = None
        self._running = threading.Event()
        self._discovery_thread: threading.Thread | None = None

    # -- topology helpers ----------------------------------------------------
    def gateway_ip(self) -> str | None:
        gws = self.registry.gateways()
        return sorted(gws)[0] if gws else None

    def subnet(self) -> str | None:
        nets = self.registry.networks()
        if not nets:
            return None
        # Prefer the subnet that actually contains the default gateway (the real
        # LAN), not e.g. a docker bridge that happens to be listed first.
        for gw in self.registry.gateways():
            gw_addr = ipaddress.ip_address(gw)
            for net in nets:
                if gw_addr in net:
                    return str(net)
        return str(nets[0])

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        from scapy.all import AsyncSniffer  # heavy import, deferred

        log.info("starting network sniffer iface=%s promisc=%s", config.IFACE, config.NET_PROMISC)
        self._sniffer = AsyncSniffer(
            iface=config.IFACE,
            prn=self._on_packet,
            store=False,
            promisc=config.NET_PROMISC,
        )
        self._sniffer.start()
        # AsyncSniffer opens its socket on a background thread; a permission
        # error surfaces after start(). Verify and re-raise (see capture.py).
        time.sleep(0.3)
        exc = getattr(self._sniffer, "exception", None)
        if exc is not None:
            raise exc
        thread = getattr(self._sniffer, "thread", None)
        if thread is not None and not thread.is_alive():
            raise RuntimeError("network capture thread exited during startup")
        self._running.set()
        if config.DISCOVERY_ENABLED:
            self._discovery_thread = threading.Thread(
                target=self._discovery_loop, name="arp-discovery", daemon=True
            )
            self._discovery_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001 - best-effort
                pass
        self.dns.shutdown()

    def _emit(self, kind: str, payload: dict) -> None:
        try:
            self.out.put_nowait((kind, payload))
        except queue.Full:
            pass

    # -- packet handling -----------------------------------------------------
    def _on_packet(self, pkt) -> None:
        from scapy.layers.l2 import ARP, Ether
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        self.registry.maybe_refresh_topology()
        ts = float(getattr(pkt, "time", time.time()))
        size = len(pkt)

        eth_src = eth_dst = None
        if Ether in pkt:
            eth_src = pkt[Ether].src
            eth_dst = pkt[Ether].dst

        # --- ARP: pure device discovery (learn IP<->MAC), record as activity ---
        if ARP in pkt:
            arp = pkt[ARP]
            self.registry.observe(arp.psrc, arp.hwsrc, ts)
            if arp.pdst and arp.pdst != "0.0.0.0":
                self.registry.observe(arp.pdst, arp.hwdst, ts)
            if self.registry.is_lan_ip(arp.psrc):
                self.stats.record(arp.psrc, "ARP", size, ts)
                self._emit("packet", {
                    "ts": ts, "proto": "ARP", "src_ip": arp.psrc, "src_port": None,
                    "dst_ip": arp.psrc, "dst_port": None, "size": size,
                    "dst_host": self.dns.get(arp.psrc), "flags": None, "process": None,
                    "peer_ip": arp.pdst, "peer_host": None,
                })
            return

        # --- L3 ---
        if IP in pkt:
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            src_ip, dst_ip = ip.src, ip.dst
        else:
            return

        lan_src = self.registry.is_lan_ip(src_ip)
        lan_dst = self.registry.is_lan_ip(dst_ip)
        if not lan_src and not lan_dst:
            return  # neither endpoint is on our LAN

        # Learn identity only for the endpoint that lives on our subnet (its
        # Ethernet MAC is the real device MAC for same-subnet delivery).
        if lan_src:
            self.registry.observe(src_ip, eth_src, ts)
        if lan_dst:
            self.registry.observe(dst_ip, eth_dst, ts)

        # --- L4 ---
        proto = "OTHER"
        src_port = dst_port = None
        flags = None
        if TCP in pkt:
            proto = "TCP"
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"
        elif IPv6 in pkt and getattr(ip, "nh", None) == 58:
            proto = "ICMPv6"

        # DNS / mDNS learning for device & peer hostnames.
        if src_port in (53, 5353) or dst_port in (53, 5353):
            self._handle_dns(pkt, ts)

        # Attribute the packet to a LAN device node (prefer a non-gateway host;
        # the gateway is the constellation hub, not an orbiting node).
        gws = self.registry.gateways()
        node_ip = None
        for cand in (dst_ip, src_ip):
            if self.registry.is_lan_ip(cand) and cand not in gws:
                node_ip = cand
                break
        if node_ip is None:
            for cand in (dst_ip, src_ip):
                if self.registry.is_lan_ip(cand):
                    node_ip = cand
                    break
        if node_ip is None:
            return

        # The "peer" is the other endpoint (what the device is talking to).
        if node_ip == src_ip:
            peer_ip, peer_port = dst_ip, dst_port
        else:
            peer_ip, peer_port = src_ip, src_port

        self.stats.record(node_ip, proto, size, ts)
        self._emit("packet", {
            "ts": ts,
            "proto": proto,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": node_ip,           # node the particle flies to
            "dst_port": peer_port,        # remote service port (activity hint)
            "size": size,
            "dst_host": self.dns.get(node_ip),
            "flags": flags,
            "process": None,
            "peer_ip": peer_ip,
            "peer_host": self.dns.get(peer_ip),
        })

    def _handle_dns(self, pkt, ts: float) -> None:
        from scapy.layers.dns import DNS, DNSRR

        if DNS not in pkt:
            return
        dns = pkt[DNS]
        # Query (qr == 0): surface the lookup in the network DNS feed.
        if dns.qr == 0 and dns.qd is not None:
            query = _decode_name(dns.qd.qname)
            qtype = _QTYPE_NAMES.get(int(dns.qd.qtype), str(dns.qd.qtype))
            self._emit("dns", {"ts": ts, "query": query, "qtype": qtype})
            return
        # Response (qr == 1): learn IP -> host mappings (incl. .local via mDNS).
        if dns.qr == 1 and dns.an is not None:
            try:
                answers = list(dns.an)
            except TypeError:
                answers = [dns.an]
            for rr in answers:
                if isinstance(rr, DNSRR) and int(rr.type) in (_DNS_A, _DNS_AAAA):
                    self.dns.learn(str(rr.rdata), _decode_name(rr.rrname))

    # -- active discovery ----------------------------------------------------
    def _discovery_loop(self) -> None:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import sendp

        while self._running.is_set():
            try:
                for net in self.registry.networks():
                    if net.num_addresses > config.DISCOVERY_MAX_HOSTS:
                        continue
                    for host in net.hosts():
                        if not self._running.is_set():
                            break
                        try:
                            sendp(
                                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(host)),
                                iface=config.IFACE,
                                verbose=0,
                            )
                        except Exception:  # noqa: BLE001 - send is best-effort
                            pass
                        time.sleep(config.DISCOVERY_SEND_GAP_SEC)
            except Exception as e:  # noqa: BLE001
                log.debug("discovery sweep error: %s", e)
            # Sleep the interval in small slices so stop() is responsive.
            waited = 0.0
            while self._running.is_set() and waited < config.DISCOVERY_INTERVAL_SEC:
                time.sleep(0.5)
                waited += 0.5
