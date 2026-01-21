"""Perform reverse DNS lookups."""

import dns.resolver
import dns.reversename


def reverse_dns(ip):
    """Perform reverse DNS lookup on IP address.
    
    Args:
        ip (str): IP address to lookup
    
    Returns:
        list: Reverse DNS hostnames
    """
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []
