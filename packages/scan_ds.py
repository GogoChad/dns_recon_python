"""DS record scanner for DNSSEC delegation."""

import dns.resolver

def scan_ds(domain, resolver_obj=None):
    """
    Scan for DS records (Delegation Signer).
    Links child zone DNSSEC to parent zone - critical for DNSSEC chain of trust.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'DS')
        records = []
        
        algorithm_map = {
            3: 'DSA',
            5: 'RSA/SHA-1',
            6: 'DSA-NSEC3-SHA1',
            7: 'RSASHA1-NSEC3-SHA1',
            8: 'RSA/SHA-256',
            10: 'RSA/SHA-512',
            13: 'ECDSA P-256/SHA-256',
            14: 'ECDSA P-384/SHA-384',
            15: 'Ed25519',
            16: 'Ed448'
        }
        
        digest_type_map = {
            1: 'SHA-1',
            2: 'SHA-256',
            3: 'GOST R 34.11-94',
            4: 'SHA-384'
        }
        
        for rdata in answers:
            key_tag = rdata.key_tag
            algorithm = rdata.algorithm
            digest_type = rdata.digest_type
            digest = rdata.digest.hex()
            
            # Security assessment
            secure = algorithm in [8, 10, 13, 14, 15, 16] and digest_type in [2, 4]
            
            record_info = {
                'key_tag': key_tag,
                'algorithm': algorithm,
                'algorithm_name': algorithm_map.get(algorithm, f'Unknown ({algorithm})'),
                'digest_type': digest_type,
                'digest_type_name': digest_type_map.get(digest_type, f'Unknown ({digest_type})'),
                'digest': digest,
                'secure': secure,
                'warning': None if secure else 'Using weak algorithm or digest'
            }
            records.append(record_info)
        
        return {domain: records} if records else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
