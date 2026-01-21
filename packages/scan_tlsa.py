"""TLSA (DANE) record scanner for email and service security."""

import dns.resolver

def scan_tlsa(domain, resolver_obj=None):
    """
    Scan for TLSA records (DNS-based Authentication of Named Entities).
    Used for securing SMTP, HTTPS, and other services.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    results = {}
    
    # Common TLSA targets
    tlsa_targets = [
        f"_25._tcp.{domain}",      # SMTP
        f"_443._tcp.{domain}",     # HTTPS
        f"_465._tcp.{domain}",     # SMTPS
        f"_587._tcp.{domain}",     # Submission
        f"_993._tcp.{domain}",     # IMAPS
        f"_995._tcp.{domain}",     # POP3S
    ]
    
    for target in tlsa_targets:
        try:
            answers = resolver_obj.resolve(target, 'TLSA')
            records = []
            
            for rdata in answers:
                # TLSA format: usage selector matching_type certificate_data
                usage_map = {
                    0: 'PKIX-TA (CA constraint)',
                    1: 'PKIX-EE (Service certificate)',
                    2: 'DANE-TA (Trust anchor)',
                    3: 'DANE-EE (Domain-issued)'
                }
                
                selector_map = {
                    0: 'Full certificate',
                    1: 'SubjectPublicKeyInfo'
                }
                
                matching_map = {
                    0: 'Exact match',
                    1: 'SHA-256 hash',
                    2: 'SHA-512 hash'
                }
                
                usage = rdata.usage
                selector = rdata.selector
                matching_type = rdata.mtype
                cert_data = rdata.cert.hex()[:64] + '...'  # Truncate for display
                
                record_info = {
                    'target': target,
                    'usage': usage,
                    'usage_desc': usage_map.get(usage, f'Unknown ({usage})'),
                    'selector': selector,
                    'selector_desc': selector_map.get(selector, f'Unknown ({selector})'),
                    'matching_type': matching_type,
                    'matching_desc': matching_map.get(matching_type, f'Unknown ({matching_type})'),
                    'certificate_data': cert_data,
                    'secure': usage in [2, 3]  # DANE modes are more secure
                }
                records.append(record_info)
            
            if records:
                service = target.split('._tcp.')[0].replace('_', '')
                results[f'port_{service}'] = records
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue
    
    return results if results else None
