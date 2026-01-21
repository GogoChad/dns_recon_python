"""
Scan NS (Nameserver) Records

PRESENTATION EXPLANATION:
=========================
Nameservers are the authoritative DNS servers for a domain.
They tell the world "I'm responsible for answering queries about this domain".

WHY IMPORTANT:
- Shows where DNS is hosted (Cloudflare, AWS Route53, Google Cloud DNS)
- Reveals infrastructure provider
- Multiple NS = redundancy and reliability

EXAMPLE:
example.com NS records:
  ns1.cloudflare.com (104.16.132.229) - Provider: Cloudflare
  ns2.cloudflare.com (104.16.133.229) - Provider: Cloudflare
"""

import dns.resolver


def scan_ns(domain):
    """
    Query NS (nameserver) records with IPv4/IPv6 resolution and provider detection
    
    ALGORITHM:
    1. Query NS records for domain
    2. For each nameserver hostname:
       a. Resolve to IPv4 (A records)
       b. Resolve to IPv6 (AAAA records)
       c. Detect provider from hostname patterns
    
    Args:
        domain (str): Target domain (e.g., "example.com")
    
    Returns:
        list: Array of nameserver details:
              [{'nameserver': 'ns1.example.com',
                'ipv4': ['1.2.3.4'],
                'ipv6': ['2001:db8::1'],
                'provider': 'Cloudflare'}]
    """
    # Configure resolver with reasonable timeouts
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2  # 2 seconds per query
    resolver.lifetime = 5  # 5 seconds total including retries
    
    try:
        # Query NS records from authoritative servers
        answers = resolver.resolve(domain, 'NS')
        results = []
        
        for rdata in answers:
            # Get nameserver hostname (remove trailing dot)
            ns_host = str(rdata).rstrip('.')
            
            # === RESOLVE NAMESERVER TO IPS ===
            ips_v4 = []
            ips_v6 = []
            
            # Try IPv4 resolution (A records)
            try:
                a_records = resolver.resolve(ns_host, 'A')
                ips_v4 = [str(ip) for ip in a_records]
            except:
                pass  # No IPv4 available
            
            # Try IPv6 resolution (AAAA records)
            try:
                aaaa_records = resolver.resolve(ns_host, 'AAAA')
                ips_v6 = [str(ip) for ip in aaaa_records]
            except:
                pass  # No IPv6 available
            
            # === PROVIDER DETECTION ===
            # Detect hosting provider from nameserver hostname patterns
            ns_lower = ns_host.lower()
            provider = None
            
            # Check common provider patterns
            if 'cloudflare' in ns_lower:
                provider = 'Cloudflare'
            elif 'awsdns' in ns_lower or 'amazonaws' in ns_lower:
                provider = 'AWS Route53'
            elif 'googledomains' in ns_lower or 'google' in ns_lower:
                provider = 'Google Cloud DNS'
            elif 'azure' in ns_lower:
                provider = 'Azure DNS'
            elif 'ovh' in ns_lower:
                provider = 'OVH'
            elif 'gandi' in ns_lower:
                provider = 'Gandi'
            
            # Build result dictionary
            result = {'nameserver': ns_host}
            if ips_v4:
                result['ipv4'] = ips_v4
            if ips_v6:
                result['ipv6'] = ips_v6
            if provider:
                result['provider'] = provider
            
            results.append(result)
        
        return results
    
    except Exception:
        return []  # Domain has no NS records or query failed
