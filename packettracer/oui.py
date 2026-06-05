"""Best-effort MAC vendor lookup from a small curated OUI prefix table.

Keyed by the first three octets (24-bit OUI) as uppercase hex, no separators.
This is intentionally a small common-device list, not the full IEEE registry —
unknown prefixes return None and the UI falls back to the IP/MAC.
"""

from __future__ import annotations

# A compact set of prefixes common on home networks. Extend as needed.
_OUI: dict[str, str] = {
    # Apple
    "F018 98": "Apple", "3C0754": "Apple", "A4C361": "Apple", "DC2B2A": "Apple",
    "F45C89": "Apple", "ACBC32": "Apple", "8866A5": "Apple", "9803D8": "Apple",
    # Samsung
    "FCA621": "Samsung", "8CF5A3": "Samsung", "5CF5DA": "Samsung", "E8508B": "Samsung",
    # Google / Nest
    "F4F5E8": "Google", "3C5AB4": "Google", "A4778C": "Google", "DA A1 19": "Google",
    # Amazon (Echo / Fire)
    "FC65DE": "Amazon", "44650D": "Amazon", "68F728": "Amazon", "0C47C9": "Amazon",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    # Intel
    "001B21": "Intel", "3C9772": "Intel", "A0A8CD": "Intel", "94659C": "Intel",
    # TP-Link
    "5091E3": "TP-Link", "F4EC38": "TP-Link", "AC84C6": "TP-Link", "1C61B4": "TP-Link",
    # Netgear / ASUS / D-Link routers
    "A040A0": "Netgear", "2C3033": "Netgear", "049226": "ASUS", "AC220B": "ASUS",
    "1CBDB9": "D-Link",
    # Espressif (ESP32/IoT)
    "240AC4": "Espressif", "30AEA4": "Espressif", "A4CF12": "Espressif", "7C9EBD": "Espressif",
    # Sonos / Philips Hue / Roku / Ubiquiti
    "5CAAFD": "Sonos", "001788": "Philips Hue", "CCB8A8": "Roku", "FC EC DA": "Ubiquiti",
    "788A20": "Ubiquiti", "245A4C": "Ubiquiti",
    # Xiaomi / Huawei
    "286C07": "Xiaomi", "640980": "Xiaomi", "00E0FC": "Huawei", "48AD08": "Huawei",
    # Sony / LG / Microsoft
    "FC0FE6": "Sony", "001E3D": "LG", "C83F26": "LG", "00155D": "Microsoft (Hyper-V)",
    # Virtualization
    "080027": "VirtualBox", "000C29": "VMware", "525400": "QEMU/KVM",
}

# Normalize keys (strip spaces) once at import.
_OUI = {k.replace(" ", "").upper(): v for k, v in _OUI.items()}


def vendor_for(mac: str | None) -> str | None:
    if not mac:
        return None
    hexs = mac.replace(":", "").replace("-", "").upper()
    if len(hexs) < 6:
        return None
    return _OUI.get(hexs[:6])
