"""Scan AAAA (IPv6) records with enhanced analysis."""

import dns.resolver

resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 5

def scan_aaaa(domain):
    """Query AAAA records with IPv6 property analysis."""
    try:
        answers = resolver.resolve(domain, 'AAAA')
        results = []
        
        for rdata in answers:
            ipv6 = str(rdata)
            properties = []
            
            # Analyze IPv6 address type
            if ipv6.startswith('2001:db8:'):
                properties.append('documentation')
            elif ipv6.startswith('fe80:'):
                properties.append('link-local')
            elif ipv6.startswith('fc') or ipv6.startswith('fd'):
                properties.append('unique-local')
            elif ipv6.startswith('ff'):
                properties.append('multicast')
            elif ipv6.startswith('::'):
                properties.append('loopback' if ipv6 == '::1' else 'special')
            elif ipv6.startswith('2001:'):
                properties.append('global-unicast')
            elif ipv6.startswith('2a'):
                properties.append('RIPE-NCC-region')
            elif ipv6.startswith('2c'):
                properties.append('AFRINIC-region')
            elif ipv6.startswith('2d') or ipv6.startswith('2e'):
                properties.append('APNIC-region')
            
            if '::' in ipv6:
                properties.append('compressed')
            
            result = {'ipv6': ipv6}
            if properties:
                result['properties'] = properties
            
            results.append(result)
        
        return results
    except:
        return []
