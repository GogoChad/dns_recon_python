"""Check for wildcard DNS entries."""

import dns.resolver
import random
import string

def scan_wildcard(domain):
    """Detect wildcard DNS by checking random subdomains."""
    resolver_obj = dns.resolver.Resolver()
    resolver_obj.timeout = 1
    resolver_obj.lifetime = 2
    
    # Generate random subdomains
    random_subdomains = [
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        for _ in range(3)
    ]
    
    wildcard_ips = set()
    
    for random_sub in random_subdomains:
        test_domain = f"{random_sub}.{domain}"
        try:
            answers = resolver_obj.resolve(test_domain, 'A')
            for rdata in answers:
                wildcard_ips.add(str(rdata))
        except:
            pass
    
    if wildcard_ips:
        return {
            'wildcard_detected': True,
            'wildcard_ips': list(wildcard_ips),
            'note': 'Domain uses wildcard DNS - subdomain enumeration may be unreliable'
        }
    
    return {
        'wildcard_detected': False
    }
