"""LAN topology + device tracking for the network monitor.

- Discovers this host's IPv4 subnets and the default gateway(s).
- DeviceRegistry tracks every device seen on those subnets: IP<->MAC, vendor
  (OUI), hostname (learned from mDNS/DNS/PTR), first/last seen, and whether it's
  this host or the gateway.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time

import psutil

from . import oui


def local_ipv4_networks() -> list[ipaddress.IPv4Network]:
    """Networks (CIDR) for each non-loopback IPv4 interface address."""
    nets: list[ipaddress.IPv4Network] = []
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            if a.address.startswith("127."):
                continue
            try:
                net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network) and not net.is_loopback:
                nets.append(net)
    return nets


def default_gateways() -> set[str]:
    """Default-route gateway IPv4 addresses, parsed from /proc/net/route."""
    gws: set[str] = set()
    try:
        with open("/proc/net/route") as fh:
            next(fh, None)  # header
            for line in fh:
                f = line.split()
                if len(f) < 4:
                    continue
                dest, gw, flags = f[1], f[2], int(f[3], 16)
                # default route (dest 0.0.0.0) with an up gateway (flags 0x2)
                if dest == "00000000" and (flags & 0x2):
                    gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16)))
                    if gw_ip != "0.0.0.0":
                        gws.add(gw_ip)
    except (OSError, ValueError):
        pass
    return gws


def _ip_in_nets(ip: str, nets: list[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


_BAD_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def _usable_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.lower()
    if mac in _BAD_MACS:
        return None
    # Skip multicast MACs (least-significant bit of first octet set).
    try:
        if int(mac.split(":", 1)[0], 16) & 0x01:
            return None
    except ValueError:
        return None
    return mac


class Device:
    __slots__ = ("ip", "mac", "vendor", "first_seen", "last_seen", "is_self", "is_gateway")

    def __init__(self, ip: str, ts: float) -> None:
        self.ip = ip
        self.mac: str | None = None
        self.vendor: str | None = None
        self.first_seen = ts
        self.last_seen = ts
        self.is_self = False
        self.is_gateway = False


class DeviceRegistry:
    """Thread-safe registry of LAN devices, keyed by IP."""

    def __init__(self, dns_cache=None) -> None:
        self._lock = threading.Lock()
        self._by_ip: dict[str, Device] = {}
        self._nets: list[ipaddress.IPv4Network] = []
        self._local_ips: set[str] = set()
        self._gateways: set[str] = set()
        self._dns = dns_cache
        self._last_topo = 0.0
        self.refresh_topology()

    def refresh_topology(self) -> None:
        nets = local_ipv4_networks()
        gws = default_gateways()
        local_ips = {a.address for addrs in psutil.net_if_addrs().values() for a in addrs
                     if a.family == socket.AF_INET and not a.address.startswith("127.")}
        with self._lock:
            self._nets = nets
            self._gateways = gws
            self._local_ips = local_ips
            self._last_topo = time.time()

    def maybe_refresh_topology(self, interval: float = 30.0) -> None:
        if time.time() - self._last_topo >= interval:
            self.refresh_topology()

    def networks(self) -> list[ipaddress.IPv4Network]:
        with self._lock:
            return list(self._nets)

    def gateways(self) -> set[str]:
        with self._lock:
            return set(self._gateways)

    def is_lan_ip(self, ip: str) -> bool:
        with self._lock:
            return _ip_in_nets(ip, self._nets)

    def observe(self, ip: str, mac: str | None, ts: float) -> None:
        """Record that ``ip`` (optionally with ``mac``) exists on the LAN."""
        with self._lock:
            if not _ip_in_nets(ip, self._nets):
                return
            d = self._by_ip.get(ip)
            if d is None:
                d = Device(ip, ts)
                self._by_ip[ip] = d
            d.last_seen = ts
            d.is_self = ip in self._local_ips
            d.is_gateway = ip in self._gateways
            mac = _usable_mac(mac)
            if mac and d.mac != mac:
                d.mac = mac
                d.vendor = oui.vendor_for(mac)

    def count(self) -> int:
        with self._lock:
            return len(self._by_ip)

    def snapshot(self) -> list[dict]:
        """Per-device identity dicts (no traffic stats — joined in netstats)."""
        with self._lock:
            devices = list(self._by_ip.values())
        out = []
        for d in devices:
            hostname = self._dns.get(d.ip) if self._dns else None
            out.append({
                "ip": d.ip,
                "mac": d.mac,
                "vendor": d.vendor,
                "hostname": hostname,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "is_self": d.is_self,
                "is_gateway": d.is_gateway,
            })
        return out
