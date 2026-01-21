"""Check for BIMI (Brand Indicators for Message Identification) records."""

import dns.resolver

def scan_bimi(domain):
    """Query BIMI records for brand logo verification.
    
    Args:
        domain (str): Domain name
    
    Returns:
        dict: BIMI configuration with logo URL and VMC certificate
    """
    try:
        bimi_domain = f"default._bimi.{domain}"
        answers = dns.resolver.resolve(bimi_domain, 'TXT')
        
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=BIMI1'):
                result = {'record': txt}
                
                # Extract logo URL
                if 'l=' in txt:
                    parts = txt.split('l=')
                    if len(parts) > 1:
                        logo_url = parts[1].split(';')[0].strip()
                        result['logo_url'] = logo_url
                
                # Extract VMC (Verified Mark Certificate)
                if 'a=' in txt:
                    parts = txt.split('a=')
                    if len(parts) > 1:
                        vmc_url = parts[1].split(';')[0].strip()
                        result['vmc_certificate'] = vmc_url
                        result['verified'] = True
                
                return result
        
        return {}
    except:
        return {}
