"""Parse TXT records for IPs and domains."""

import re
import dns.resolver


def txt_parse(domain):
    """Parse TXT records for comprehensive web audit information.
    
    Args:
        domain (str): Domain name
    
    Returns:
        dict: Extracted data including verification, security, CDN, and ownership info
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        
        result = {
            'raw_records': [],
            'security': {},
            'ownership': {},
            'services': {},
            'emails': [],
            'domains': [],
            'ips': []
        }
        
        # Patterns
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        for rdata in answers:
            txt = str(rdata).strip('"')
            result['raw_records'].append(txt)
            
            # Security & Verification tokens
            if 'google-site-verification' in txt:
                result['ownership']['google_verified'] = True
            if 'facebook-domain-verification' in txt:
                result['ownership']['facebook_verified'] = True
            if 'apple-domain-verification' in txt:
                result['ownership']['apple_verified'] = True
            if 'ms-domain-verification' in txt or 'MS=' in txt:
                result['ownership']['microsoft_verified'] = True
            if 'docusign=' in txt.lower():
                result['services']['docusign'] = True
            if 'atlassian-domain-verification' in txt:
                result['services']['atlassian'] = True
            if 'stripe-verification=' in txt:
                result['services']['stripe'] = True
            
            # SSL/TLS verification
            if 'globalsign-domain-verification' in txt.lower():
                result['security']['ssl_provider'] = 'GlobalSign'
            if 'sectigo' in txt.lower() or 'comodo' in txt.lower():
                result['security']['ssl_provider'] = 'Sectigo'
            if 'digicert' in txt.lower():
                result['security']['ssl_provider'] = 'DigiCert'
            
            # CDN & Infrastructure
            if 'cloudflare-verify' in txt.lower():
                result['services']['cloudflare'] = True
            if 'fastly-domain-delegation' in txt.lower():
                result['services']['cdn'] = 'Fastly'
            if 'amazonses:' in txt.lower():
                result['services']['email_service'] = 'Amazon SES'
            if 'mailgun-verification' in txt.lower():
                result['services']['email_service'] = 'Mailgun'
            if 'sendgrid' in txt.lower():
                result['services']['email_service'] = 'SendGrid'
            
            # Anti-spam & Email security
            if 'proofpoint' in txt.lower():
                result['security']['email_security'] = 'Proofpoint'
            if 'mimecast' in txt.lower():
                result['security']['email_security'] = 'Mimecast'
            
            # Extract emails
            emails = re.findall(email_pattern, txt)
            result['emails'].extend(emails)
            
            # Extract IPs
            ips = re.findall(ip_pattern, txt)
            result['ips'].extend(ips)
            
            # Extract domains
            domains = re.findall(domain_pattern, txt.lower())
            result['domains'].extend([d for d in domains if d != domain])
        
        # Clean up
        result['emails'] = list(set(result['emails']))[:5]
        result['ips'] = list(set(result['ips']))[:5]
        result['domains'] = list(set(result['domains']))[:5]
        
        # Remove empty sections
        return {k: v for k, v in result.items() if v}
        
    except Exception:
        return {}
