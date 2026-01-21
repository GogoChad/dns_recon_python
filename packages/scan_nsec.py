"""NSEC/NSEC3 record scanner for DNSSEC authenticated denial."""

import dns.resolver

def scan_nsec(domain, resolver_obj=None):
    """
    Scan for NSEC and NSEC3 records (Next Secure).
    Used for DNSSEC authenticated denial of existence.
    NSEC3 provides zone enumeration protection.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    results = {}
    
    # Try NSEC
    try:
        answers = resolver_obj.resolve(domain, 'NSEC')
        nsec_records = []
        
        for rdata in answers:
            next_name = str(rdata.next)
            types = [dns.rdatatype.to_text(t) for t in rdata.windows]
            
            record_info = {
                'type': 'NSEC',
                'next_domain': next_name,
                'record_types': types,
                'enumerable': True,  # NSEC allows zone walking
                'warning': 'NSEC allows zone enumeration - consider NSEC3'
            }
            nsec_records.append(record_info)
        
        if nsec_records:
            results['nsec'] = nsec_records
            
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass
    
    # Try NSEC3
    try:
        answers = resolver_obj.resolve(domain, 'NSEC3')
        nsec3_records = []
        
        for rdata in answers:
            algorithm = rdata.algorithm
            flags = rdata.flags
            iterations = rdata.iterations
            salt = rdata.salt.hex() if rdata.salt else 'none'
            next_hash = rdata.next.hex()
            types = [dns.rdatatype.to_text(t) for t in rdata.windows]
            
            # Opt-out flag check
            opt_out = (flags & 0x01) != 0
            
            algorithm_map = {
                1: 'SHA-1'
            }
            
            # Security assessment
            secure = iterations <= 100 and not opt_out
            
            record_info = {
                'type': 'NSEC3',
                'algorithm': algorithm,
                'algorithm_name': algorithm_map.get(algorithm, f'Unknown ({algorithm})'),
                'flags': flags,
                'opt_out': opt_out,
                'iterations': iterations,
                'salt': salt,
                'next_hash': next_hash[:32] + '...',  # Truncate
                'record_types': types,
                'enumerable': False,  # NSEC3 prevents zone walking
                'secure': secure,
                'warning': f'High iteration count ({iterations})' if iterations > 100 else None
            }
            nsec3_records.append(record_info)
        
        if nsec3_records:
            results['nsec3'] = nsec3_records
            
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass
    
    # Try NSEC3PARAM (NSEC3 parameters)
    try:
        answers = resolver_obj.resolve(domain, 'NSEC3PARAM')
        for rdata in answers:
            params = {
                'algorithm': rdata.algorithm,
                'flags': rdata.flags,
                'iterations': rdata.iterations,
                'salt': rdata.salt.hex() if rdata.salt else 'none'
            }
            results['nsec3_params'] = params
    except:
        pass
    
    return {domain: results} if results else None
