"""Scan SOA (Start of Authority) records."""

import dns.resolver


def scan_soa(domain):
    """Query SOA record for domain.
    
    Args:
        domain (str): Domain name
    
    Returns:
        dict: SOA record details
    """
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        for rdata in answers:
            # Extract email from rname (format: admin.domain.com -> admin@domain.com)
            rname_str = str(rdata.rname)
            email = rname_str.replace('.', '@', 1).rstrip('.')
            
            return {
                'mname': str(rdata.mname).rstrip('.'),
                'rname': email,
                'serial': rdata.serial,
                'refresh': rdata.refresh,
                'retry': rdata.retry,
                'expire': rdata.expire,
                'minimum': rdata.minimum
            }
    except Exception:
        return {}
