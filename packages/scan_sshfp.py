"""SSHFP record scanner for SSH host key verification."""

import dns.resolver

def scan_sshfp(domain, resolver_obj=None):
    """
    Scan for SSHFP records (SSH Fingerprint).
    Allows SSH clients to verify host keys via DNS.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'SSHFP')
        records = []
        
        algorithm_map = {
            1: 'RSA',
            2: 'DSA',
            3: 'ECDSA',
            4: 'Ed25519'
        }
        
        fp_type_map = {
            1: 'SHA-1',
            2: 'SHA-256'
        }
        
        for rdata in answers:
            algorithm = rdata.algorithm
            fp_type = rdata.fp_type
            fingerprint = rdata.fingerprint.hex()
            
            # Format fingerprint nicely (SSH style)
            formatted_fp = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
            
            record_info = {
                'algorithm': algorithm,
                'algorithm_name': algorithm_map.get(algorithm, f'Unknown ({algorithm})'),
                'fingerprint_type': fp_type,
                'fingerprint_type_name': fp_type_map.get(fp_type, f'Unknown ({fp_type})'),
                'fingerprint': formatted_fp,
                'secure': fp_type == 2 and algorithm in [3, 4]  # SHA-256 + modern algo
            }
            records.append(record_info)
        
        return {domain: records} if records else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
