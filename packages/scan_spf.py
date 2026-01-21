"""
Scan SPF (Sender Policy Framework) Records

PRESENTATION EXPLANATION:
=========================
SPF prevents email spoofing by listing which servers can send email for a domain.
Published in TXT records, format: "v=spf1 include:_spf.google.com -all"

WHY CRITICAL FOR SECURITY:
- Stops attackers from spoofing @yourdomain.com emails
- "include:" = delegate to another domain's SPF
- Policy: -all (reject), ~all (softfail), +all (pass all - BAD!)

EXAMPLE:
"v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all"
  Means: Allow Google servers + 203.0.113.0/24, reject everything else
"""

import dns.resolver


def scan_spf(domain):
    """
    Parse SPF record into structured mechanisms and policy
    
    ALGORITHM:
    1. Query TXT records
    2. Find record starting with "v=spf1"
    3. Parse mechanisms:
       - include: (delegate to another SPF)
       - a: (allow domain's A record IPs)
       - mx: (allow mail server IPs)
       - ip4:/ip6: (explicit IP ranges)
       - all: final policy (-all=reject, ~all=softfail)
    
    Args:
        domain (str): Domain to check
    
    Returns:
        dict: {'record': 'full SPF string',
               'mechanisms': [{'type': 'include', 'value': '_spf.google.com'}],
               'policy': '-all'}
    """
    try:
        # Query all TXT records
        answers = dns.resolver.resolve(domain, 'TXT')
        
        # Find SPF record (starts with "v=spf1")
        for rdata in answers:
            txt = str(rdata).strip('"')
            
            if txt.startswith('v=spf1'):
                # Found SPF record - start parsing
                result = {
                    'record': txt,
                    'mechanisms': []  # List of SPF mechanisms
                }
                
                # Split record into space-separated parts
                parts = txt.split()
                
                # Parse each mechanism (skip first part "v=spf1")
                for part in parts[1:]:
                    
                    # INCLUDE mechanism - delegate to another SPF
                    if part.startswith('include:'):
                        result['mechanisms'].append({
                            'type': 'include',
                            'value': part[8:]  # Remove "include:" prefix
                        })
                    
                    # A mechanism - allow domain's A record IPs
                    elif part.startswith('a:') or part == 'a':
                        result['mechanisms'].append({
                            'type': 'a',
                            'value': part[2:] if len(part) > 1 else domain
                        })
                    
                    # MX mechanism - allow mail server IPs
                    elif part.startswith('mx'):
                        result['mechanisms'].append({
                            'type': 'mx',
                            'value': domain
                        })
                    
                    # IPv4 mechanism - explicit IP range
                    elif part.startswith('ip4:'):
                        result['mechanisms'].append({
                            'type': 'ipv4',
                            'value': part[4:]  # Remove "ip4:" prefix
                        })
                    
                    # IPv6 mechanism - explicit IPv6 range
                    elif part.startswith('ip6:'):
                        result['mechanisms'].append({
                            'type': 'ipv6',
                            'value': part[4:]  # Remove "ip6:" prefix
                        })
                    
                    # ALL mechanism - final policy decision
                    elif part in ['~all', '-all', '+all', '?all']:
                        result['policy'] = part
                        # -all = hard fail (reject)
                        # ~all = soft fail (mark as spam)
                        # +all = pass (accept all - INSECURE!)
                        # ?all = neutral
                
                return result
        
        return {}  # No SPF record found
    
    except Exception:
        return {}  # Query failed or parse error
