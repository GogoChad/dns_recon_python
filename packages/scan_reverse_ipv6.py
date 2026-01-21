"""Perform reverse DNS lookups for IPv6."""

import dns.resolver
import dns.reversename


def scan_reverse_ipv6(ipv6):
    """Perform reverse DNS lookup on IPv6 address."""
    try:
        rev_name = dns.reversename.from_address(ipv6)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []
