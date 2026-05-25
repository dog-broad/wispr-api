from __future__ import annotations

import ipaddress

from fastapi import Request

# In production, Caddy enforces the upstream trust boundary: it strips
# any inbound CF-Connecting-IP from clients, then sets it to the actual
# connecting peer (`{http.request.remote.host}`) before forwarding. There
# is no Cloudflare in front of this host today, so the value Caddy
# attaches is the real client IP. When Cloudflare is added later, the
# Caddy directive should change to re-trust CF-Connecting-IP only when
# the connecting peer is inside the published Cloudflare IP range.
#
# Without that Caddy stripping, this header would be trivially spoofable
# by any client and rate limits could be bypassed by rotating the value.
_CF_CONNECTING_IP = "cf-connecting-ip"


def extract_client_ip(request: Request) -> str:
    """Best-known address of the requesting client.

    Reads ``CF-Connecting-IP`` if present; falls back to the direct peer
    address otherwise. Returns an empty string when neither is available
    (unit tests with no transport, mostly) so callers don't have to handle
    ``None``.
    """
    header = request.headers.get(_CF_CONNECTING_IP)
    if header:
        return header.strip()
    if request.client is not None and request.client.host:
        return request.client.host
    return ""


def bucket_key(ip: str) -> str:
    """Stable key for rate-limit bucketing.

    IPv4 addresses are used verbatim. IPv6 addresses are bucketed by their
    /64 prefix — individual v6 addresses are too cheap to rotate to make
    per-address limits meaningful. Unparseable inputs (including the empty
    string returned by ``extract_client_ip`` when no client is attached)
    are passed through unchanged so the caller still gets a deterministic
    bucket label.
    """
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        network = ipaddress.ip_network(f"{ip}/64", strict=False)
        return str(network.network_address)
    return str(addr)
