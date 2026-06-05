"""Learn IP -> hostname from cleartext on-the-wire metadata.

DNS sniffing only catches names the host actually *looked up* on the wire — it
misses locally-cached lookups and encrypted DNS (DoH/DoT). Two cleartext signals
fill the gap and reveal the real destination of a connection:

  * **TLS SNI** — every HTTPS ``ClientHello`` carries the target server name in
    cleartext in the Server Name Indication extension (TLS 1.2 and 1.3 alike).
  * **HTTP Host** — plaintext HTTP requests carry a ``Host:`` header.

Both are parsed defensively straight from the TCP payload bytes (no scapy TLS
layer needed), with bounds checks so a malformed/partial record just yields None.
"""

from __future__ import annotations

_TLS_HANDSHAKE = 0x16
_HS_CLIENT_HELLO = 0x01
_EXT_SERVER_NAME = 0x0000
_SNI_HOST_NAME = 0x00

_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                 b"PATCH ", b"CONNECT ", b"TRACE ")


def _valid_hostname(h: str) -> bool:
    if not h or len(h) > 253 or "." not in h:
        return False
    # hostnames are ASCII letters/digits/hyphen/dot (IDNs arrive punycoded)
    return all(c.isalnum() or c in "-._" for c in h)


def extract_tls_sni(payload: bytes) -> str | None:
    """Return the SNI host from a TLS ClientHello payload, or None."""
    try:
        if len(payload) < 5 or payload[0] != _TLS_HANDSHAKE:
            return None
        # TLS record header: type(1) version(2) length(2); body follows.
        body = payload[5:]
        if not body or body[0] != _HS_CLIENT_HELLO:
            return None
        # Handshake header: msg_type(1) length(3); then ClientHello body.
        p = 4
        p += 2          # client_version
        p += 32         # random
        if p >= len(body):
            return None
        sid_len = body[p]; p += 1 + sid_len               # session_id
        if p + 2 > len(body):
            return None
        cs_len = int.from_bytes(body[p:p + 2], "big"); p += 2 + cs_len  # cipher_suites
        if p >= len(body):
            return None
        comp_len = body[p]; p += 1 + comp_len             # compression_methods
        if p + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[p:p + 2], "big"); p += 2
        end = min(len(body), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(body[p:p + 2], "big")
            elen = int.from_bytes(body[p + 2:p + 4], "big")
            p += 4
            if etype == _EXT_SERVER_NAME and p + 5 <= len(body):
                # server_name_list(2) then entry: type(1) name_len(2) name
                ntype = body[p + 2]
                nlen = int.from_bytes(body[p + 3:p + 5], "big")
                if ntype == _SNI_HOST_NAME and p + 5 + nlen <= len(body):
                    host = body[p + 5:p + 5 + nlen].decode("ascii", "ignore")
                    host = host.rstrip(".").lower()
                    return host if _valid_hostname(host) else None
            p += elen
    except (IndexError, ValueError):
        return None
    return None


def extract_http_host(payload: bytes) -> str | None:
    """Return the Host header from a plaintext HTTP request payload, or None."""
    try:
        if not payload.startswith(_HTTP_METHODS):
            return None
        head = payload[:2048]
        for line in head.split(b"\r\n")[1:]:
            if not line:
                break  # end of headers
            if line[:5].lower() == b"host:":
                host = line[5:].strip().decode("ascii", "ignore")
                host = host.rsplit(":", 1)[0].rstrip(".").lower()  # drop :port
                return host if _valid_hostname(host) else None
    except (IndexError, ValueError, UnicodeDecodeError):
        return None
    return None


def host_from_payload(payload: bytes, dst_port: int | None) -> str | None:
    """Best-effort hostname for the destination of an outgoing TCP payload."""
    if not payload:
        return None
    if dst_port == 443:
        return extract_tls_sni(payload)
    if dst_port == 80:
        return extract_http_host(payload)
    # Fall back to trying both for non-standard ports (cheap on a miss).
    return extract_tls_sni(payload) or extract_http_host(payload)
