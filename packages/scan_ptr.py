"""Scan PTR (Pointer) records for reverse DNS."""

import dns.resolver
import dns.reversename

def scan_ptr(ip):
    """Query PTR records with hostname details."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 5
    
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        results = []
        for rdata in answers:
            hostname = str(rdata).rstrip('.')
            result = {'ip': ip, 'hostname': hostname}
            # Check if hostname is cloud provider
            h_lower = hostname.lower()
            if 'amazonaws' in h_lower or 'aws' in h_lower:
                result['provider'] = 'AWS'
            elif 'googleusercontent' in h_lower or 'google' in h_lower:
                result['provider'] = 'Google Cloud'
            elif 'cloudflare' in h_lower:
                result['provider'] = 'Cloudflare'
            elif 'azure' in h_lower or 'microsoft' in h_lower:
                result['provider'] = 'Azure'
            results.append(result)
        return results
    except:
        return []
