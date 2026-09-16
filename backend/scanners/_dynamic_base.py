"""
Shared utilities for dynamic (requires_running_app=True) scanners.

AUTHORIZATION CONSTRAINT:
  Dynamic scanners MUST NOT target external URLs, third-party infrastructure,
  production systems, or services outside the explicitly authorized assessment
  scope. Every scanner using this module enforces the is_local_target() check
  in can_scan() before making any network requests.
"""
import ipaddress
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Loopback and RFC-1918 private ranges permitted for scanning
_ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

# Hostname strings that are unambiguously local
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def is_local_target(url: str) -> bool:
    """
    Return True only when the URL's host resolves to localhost or a
    private/RFC-1918 network address.

    Hostname resolution is intentionally NOT performed to prevent DNS-rebinding
    attacks from pointing a hostname at an external server.  Only literal IP
    addresses and the explicit hostname allowlist are accepted.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        # Explicit hostname allowlist (no DNS lookup)
        if host.lower() in _LOCAL_HOSTNAMES:
            return True
        # Strict suffixes for mDNS / internal naming conventions
        if host.lower().endswith((".local", ".localhost", ".internal", ".test")):
            return True
        # Try to parse as a literal IP address
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback
    except (ValueError, TypeError):
        return False


class DynamicScanError(Exception):
    """Raised when a dynamic scanner cannot reach its target."""


def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> httpx.Response:
    """
    Issue a single HTTP request to a local target.

    verify=False is intentional: local/dev servers frequently use self-signed
    certificates and we must not reject them during a security assessment.
    Raises DynamicScanError if the target is unreachable.
    """
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,
        ) as client:
            return client.request(
                method=method,
                url=url,
                headers=headers or {},
                params=params,
                data=data,
            )
    except httpx.RequestError as exc:
        raise DynamicScanError(f"Cannot reach {url}: {exc}") from exc
