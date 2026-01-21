"""Check DNSSEC configuration."""

import dns.resolver

def scan_dnssec(domain):
    """Check DNSSEC with algorithm and key details."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 5
    
    results = {'enabled': False}
    
    # Check DNSKEY with algorithm details
    try:
        answers = resolver.resolve(domain, 'DNSKEY')
        keys = []
        for rdata in list(answers)[:3]:  # First 3 keys
            key_info = {
                'flags': rdata.flags,
                'protocol': rdata.protocol,
                'algorithm': rdata.algorithm,
                'key_type': 'ZSK' if rdata.flags == 256 else 'KSK' if rdata.flags == 257 else 'unknown'
            }
            keys.append(key_info)
        if keys:
            results['keys'] = keys
            results['enabled'] = True
    except:
        pass
    
    # Check DS records with digest info
    try:
        answers = resolver.resolve(domain, 'DS')
        ds_records = []
        for rdata in list(answers)[:2]:
            ds_records.append({
                'key_tag': rdata.key_tag,
                'algorithm': rdata.algorithm,
                'digest_type': rdata.digest_type
            })
        if ds_records:
            results['ds_records'] = ds_records
            results['enabled'] = True
    except:
        pass
    
    return results if results['enabled'] else {}
