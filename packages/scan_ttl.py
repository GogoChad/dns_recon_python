"""Extract TTL information from DNS records for cache analysis."""

import dns.resolver

def scan_ttl(domain):
    """Query multiple record types and extract TTL values for analysis."""
    resolver_obj = dns.resolver.Resolver()
    resolver_obj.timeout = 2
    resolver_obj.lifetime = 5
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    results = {}
    
    for rtype in record_types:
        try:
            answers = resolver_obj.resolve(domain, rtype)
            ttl = answers.rrset.ttl
            
            # Categorize TTL
            category = ''
            if ttl < 300:  # < 5 minutes
                category = 'very-short (frequent updates expected)'
            elif ttl < 3600:  # < 1 hour
                category = 'short (CDN/load-balanced)'
            elif ttl < 86400:  # < 24 hours
                category = 'moderate (standard)'
            else:
                category = 'long (static configuration)'
            
            results[rtype] = {
                'ttl': ttl,
                'category': category,
                'seconds': ttl,
                'human': f"{ttl//3600}h {(ttl%3600)//60}m {ttl%60}s" if ttl >= 3600 else f"{ttl//60}m {ttl%60}s"
            }
        except:
            pass
    
    return results
