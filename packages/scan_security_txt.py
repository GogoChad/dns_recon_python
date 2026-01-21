"""Check for security.txt file via DNS TXT records."""

import dns.resolver

def scan_security_txt(domain):
    """Look for security contact information in TXT records.
    
    Args:
        domain (str): Domain name
    
    Returns:
        dict: Security contact and policy information
    """
    result = {}
    
    try:
        # Check _security.domain TXT records
        security_domain = f"_security.{domain}"
        answers = dns.resolver.resolve(security_domain, 'TXT')
        
        for rdata in answers:
            txt = str(rdata).strip('"')
            
            # Look for security contact
            if 'Contact:' in txt or 'security@' in txt.lower():
                result['security_contact'] = txt
            if 'Encryption:' in txt:
                result['pgp_key'] = txt
            if 'Policy:' in txt:
                result['security_policy'] = txt
    except:
        pass
    
    # Also check main domain TXT for security info
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"').lower()
            if 'security@' in txt or 'abuse@' in txt or 'cert@' in txt:
                if 'contacts' not in result:
                    result['contacts'] = []
                result['contacts'].append(txt)
    except:
        pass
    
    return result
