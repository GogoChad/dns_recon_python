"""DNSKEY record scanner for full DNSSEC key analysis."""

import dns.resolver

def scan_dnskey(domain, resolver_obj=None):
    """
    Scan for DNSKEY records (DNS Public Key).
    Complete DNSSEC key information including ZSK and KSK.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'DNSKEY')
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
        
        for rdata in answers:
            flags = rdata.flags
            protocol = rdata.protocol
            algorithm = rdata.algorithm
            key = rdata.key
            
            # Determine key type from flags
            # Bit 7: Zone Key flag (must be 1)
            # Bit 15: Secure Entry Point (SEP) - indicates KSK if 1
            is_zone_key = (flags & 0x0100) != 0
            is_ksk = (flags & 0x0001) != 0
            is_revoked = (flags & 0x0080) != 0
            
            key_type = 'KSK (Key Signing Key)' if is_ksk else 'ZSK (Zone Signing Key)'
            
            # Calculate key tag (RFC 4034)
            key_tag = 0
            key_data = rdata.to_wire()
            for i in range(len(key_data)):
                if i % 2 == 0:
                    key_tag += key_data[i] << 8
                else:
                    key_tag += key_data[i]
            key_tag += (key_tag >> 16) & 0xFFFF
            key_tag &= 0xFFFF
            
            # Security assessment
            secure = algorithm in [8, 10, 13, 14, 15, 16] and not is_revoked
            
            record_info = {
                'flags': flags,
                'key_type': key_type,
                'is_ksk': is_ksk,
                'is_zsk': not is_ksk and is_zone_key,
                'protocol': protocol,
                'algorithm': algorithm,
                'algorithm_name': algorithm_map.get(algorithm, f'Unknown ({algorithm})'),
                'key_tag': key_tag,
                'key_length_bits': len(key) * 8,
                'public_key': key.hex()[:64] + '...',  # Truncate for display
                'revoked': is_revoked,
                'secure': secure,
                'warning': 'REVOKED KEY' if is_revoked else ('Weak algorithm' if not secure else None)
            }
            records.append(record_info)
        
        # Separate KSKs and ZSKs for better organization
        ksks = [r for r in records if r['is_ksk']]
        zsks = [r for r in records if r['is_zsk']]
        
        result = {}
        if ksks:
            result['ksk_keys'] = ksks
        if zsks:
            result['zsk_keys'] = zsks
        
        return {domain: result} if result else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
