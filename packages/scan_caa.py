"""Scan CAA (Certificate Authority Authorization) records."""

import dns.resolver


def scan_caa(domain):
    """Query CAA records for domain."""
    try:
        answers = dns.resolver.resolve(domain, 'CAA')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []
