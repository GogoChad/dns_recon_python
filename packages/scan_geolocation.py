"""Geolocation lookup using DNS-based IP geolocation services."""

import dns.resolver
import socket

def scan_geolocation(ip):
    """Get geolocation info for IP using DNS-based services.
    
    Args:
        ip (str): IP address
    
    Returns:
        dict: Geolocation information (country, city, ASN)
    """
    result = {'ip': ip}
    
    # Try to get ASN info via DNS (Team Cymru)
    try:
        # Reverse IP for DNS query
        parts = ip.split('.')
        if len(parts) == 4:
            reversed_ip = '.'.join(reversed(parts))
            asn_query = f"{reversed_ip}.origin.asn.cymru.com"
            
            answers = dns.resolver.resolve(asn_query, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                # Format: "ASN | IP | BGP Prefix | CC | Registry | Allocated"
                parts = [p.strip() for p in txt.split('|')]
                if len(parts) >= 4:
                    result['asn'] = parts[0]
                    result['bgp_prefix'] = parts[2]
                    result['country'] = parts[3]
                    if len(parts) >= 5:
                        result['registry'] = parts[4]
                break
    except:
        pass
    
    # Try to get ASN name
    if 'asn' in result:
        try:
            asn_name_query = f"AS{result['asn']}.asn.cymru.com"
            answers = dns.resolver.resolve(asn_name_query, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                # Format: "ASN | CC | Registry | Allocated | AS Name"
                parts = [p.strip() for p in txt.split('|')]
                if len(parts) >= 5:
                    result['asn_name'] = parts[4]
                break
        except:
            pass
    
    # Try reverse DNS for hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result['hostname'] = hostname
        
        # Infer location from hostname
        h_lower = hostname.lower()
        
        # Common airport codes and city names in hostnames
        location_hints = {
            'par': 'Paris, FR', 'lhr': 'London, UK', 'ams': 'Amsterdam, NL',
            'fra': 'Frankfurt, DE', 'cdg': 'Paris, FR', 'jfk': 'New York, US',
            'sfo': 'San Francisco, US', 'lax': 'Los Angeles, US', 'ord': 'Chicago, US',
            'dfw': 'Dallas, US', 'sea': 'Seattle, US', 'iad': 'Washington DC, US',
            'sin': 'Singapore, SG', 'hkg': 'Hong Kong, HK', 'nrt': 'Tokyo, JP',
            'syd': 'Sydney, AU', 'yyz': 'Toronto, CA', 'gru': 'São Paulo, BR',
            'dxb': 'Dubai, AE', 'muc': 'Munich, DE', 'zrh': 'Zurich, CH',
        }
        
        for code, location in location_hints.items():
            if code in h_lower:
                result['location_hint'] = location
                break
    except:
        pass
    
    return result if len(result) > 1 else {}
