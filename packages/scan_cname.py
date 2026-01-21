"""Scan CNAME records."""

import dns.resolver


def scan_cname(domain):
    """Query CNAME records and follow the complete chain.
    
    Args:
        domain (str): Domain name
    
    Returns:
        dict: CNAME chain details with final target and IPs
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 5
    
    try:
        chain = [domain]
        current = domain
        max_depth = 10
        depth = 0
        
        while depth < max_depth:
            try:
                answers = resolver.resolve(current, 'CNAME')
                for rdata in answers:
                    target = str(rdata).rstrip('.')
                    chain.append(target)
                    current = target
                    depth += 1
                    break
                else:
                    break
            except:
                break
        
        if len(chain) > 1:
            # Resolve final target to IPs
            final_ips = []
            try:
                a_records = resolver.resolve(chain[-1], 'A')
                final_ips = [str(ip) for ip in a_records]
            except:
                pass
            
            return {
                'chain': chain,
                'final_target': chain[-1],
                'chain_length': len(chain) - 1,
                'final_ips': final_ips
            }
        
        return {}
    except Exception:
        return {}
