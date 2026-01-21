"""Check for MTA-STS (Mail Transfer Agent Strict Transport Security) records."""

import dns.resolver

def scan_mta_sts(domain):
    """Query MTA-STS policy for secure email transport.
    
    Args:
        domain (str): Domain name
    
    Returns:
        dict: MTA-STS configuration and policy ID
    """
    try:
        mta_sts_domain = f"_mta-sts.{domain}"
        answers = dns.resolver.resolve(mta_sts_domain, 'TXT')
        
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=STSv1'):
                result = {'record': txt, 'enabled': True}
                
                # Extract policy ID
                if 'id=' in txt:
                    parts = txt.split('id=')
                    if len(parts) > 1:
                        policy_id = parts[1].split(';')[0].strip()
                        result['policy_id'] = policy_id
                
                # Note: Full policy at https://mta-sts.{domain}/.well-known/mta-sts.txt
                result['policy_url'] = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                
                return result
        
        return {}
    except:
        return {}
