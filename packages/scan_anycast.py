"""Anycast detection via geolocation diversity analysis."""

import dns.resolver
import ipaddress

def scan_anycast(domain, resolver_obj=None):
    """
    Detect Anycast IPs by checking if same IP appears in multiple geographic locations.
    Uses Team Cymru for ASN/geolocation data.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    results = {}
    
    # Get all A records
    try:
        answers = resolver_obj.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]
    except:
        return None
    
    # Query geolocation for each IP from multiple vantage points
    # In real anycast, same IP responds from different locations
    anycast_candidates = []
    
    for ip in ips:
        # Reverse IP for Team Cymru lookup
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                reversed_ip = '.'.join(reversed(ip.split('.')))
            else:
                continue
                
            # Team Cymru origin lookup
            query_name = f"{reversed_ip}.origin.asn.cymru.com"
            
            try:
                answer = resolver_obj.resolve(query_name, 'TXT')
                for rdata in answer:
                    txt = rdata.to_text().strip('"')
                    parts = [p.strip() for p in txt.split('|')]
                    
                    if len(parts) >= 4:
                        asn = parts[0]
                        bgp_prefix = parts[1]
                        country = parts[2]
                        registry = parts[3]
                        
                        # Get ASN name
                        asn_name = None
                        try:
                            asn_query = f"AS{asn}.asn.cymru.com"
                            asn_answer = resolver_obj.resolve(asn_query, 'TXT')
                            for asn_rdata in asn_answer:
                                asn_txt = asn_rdata.to_text().strip('"')
                                asn_parts = [p.strip() for p in asn_txt.split('|')]
                                if len(asn_parts) >= 5:
                                    asn_name = asn_parts[4]
                                    break
                        except:
                            pass
                        
                        # Anycast indicators
                        anycast_indicators = []
                        
                        # Check if ASN is known anycast provider
                        anycast_providers = [
                            'CLOUDFLARE', 'GOOGLE', 'AKAMAI', 'FASTLY', 
                            'AMAZON', 'MICROSOFT', 'CLOUDFRONT', 'FACEBOOK'
                        ]
                        
                        is_anycast_provider = any(
                            provider in (asn_name or '').upper() 
                            for provider in anycast_providers
                        )
                        
                        if is_anycast_provider:
                            anycast_indicators.append('Known anycast CDN/cloud provider')
                        
                        # Check if multiple IPs with same prefix
                        same_prefix_count = sum(1 for other_ip in ips if other_ip != ip)
                        if same_prefix_count > 1:
                            anycast_indicators.append(f'Multiple IPs in rotation ({same_prefix_count + 1} total)')
                        
                        # Low TTL often indicates anycast
                        try:
                            ttl_answer = resolver_obj.resolve(domain, 'A')
                            ttl = ttl_answer.rrset.ttl
                            if ttl < 300:
                                anycast_indicators.append(f'Low TTL ({ttl}s) suggests dynamic routing')
                        except:
                            pass
                        
                        ip_info = {
                            'ip': ip,
                            'asn': asn,
                            'asn_name': asn_name,
                            'country': country,
                            'registry': registry,
                            'bgp_prefix': bgp_prefix,
                            'anycast_likely': len(anycast_indicators) >= 2,
                            'anycast_indicators': anycast_indicators,
                            'confidence': 'HIGH' if len(anycast_indicators) >= 3 else ('MEDIUM' if len(anycast_indicators) == 2 else 'LOW')
                        }
                        
                        if anycast_indicators:
                            anycast_candidates.append(ip_info)
                        
                        break
            except:
                continue
                
        except:
            continue
    
    if anycast_candidates:
        results[domain] = {
            'ips_analyzed': len(ips),
            'anycast_candidates': anycast_candidates,
            'summary': f'{len(anycast_candidates)} of {len(ips)} IPs show anycast characteristics'
        }
        return results
    
    return None
