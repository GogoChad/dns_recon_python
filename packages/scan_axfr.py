"""Attempt DNS zone transfers (AXFR)."""

import dns.zone
import dns.query


def scan_axfr(domain, nameserver=None):
    """Attempt AXFR zone transfer.
    
    Args:
        domain (str): Domain name
        nameserver (str, optional): Nameserver to query
    
    Returns:
        list: Zone transfer results if successful
    """
    try:
        if nameserver:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            return [name.to_text() for name in zone.nodes.keys()]
    except Exception:
        pass
    return []
