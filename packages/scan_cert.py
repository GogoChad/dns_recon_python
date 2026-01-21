"""CERT record scanner for X.509 certificates in DNS."""

import dns.resolver

def scan_cert(domain, resolver_obj=None):
    """
    Scan for CERT records (Certificate storage in DNS).
    Can store X.509 certificates, PGP keys, etc.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'CERT')
        records = []
        
        cert_type_map = {
            1: 'PKIX (X.509)',
            2: 'SPKI',
            3: 'PGP',
            4: 'IPKIX',
            5: 'ISPKI',
            6: 'IPGP',
            7: 'ACPKIX',
            8: 'IACPKIX',
            253: 'URI',
            254: 'OID'
        }
        
        for rdata in answers:
            cert_type = rdata.certificate_type
            key_tag = rdata.key_tag
            algorithm = rdata.algorithm
            certificate = rdata.certificate.hex()[:64] + '...'  # Truncate
            
            record_info = {
                'certificate_type': cert_type,
                'type_name': cert_type_map.get(cert_type, f'Unknown ({cert_type})'),
                'key_tag': key_tag,
                'algorithm': algorithm,
                'certificate_data': certificate,
                'is_x509': cert_type == 1
            }
            records.append(record_info)
        
        return {domain: records} if records else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
