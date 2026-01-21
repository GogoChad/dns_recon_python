"""
Scan DMARC (Domain-based Message Authentication, Reporting & Conformance)

PRESENTATION EXPLANATION:
=========================
DMARC builds on SPF/DKIM to tell receiving servers what to do with
failed authentication. Published at _dmarc.subdomain.

POLICY LEVELS (from weak to strong):
  p=none       - Monitor mode (collect reports, don't block)
  p=quarantine - Send to spam folder
  p=reject     - Reject the email (strongest)

REPORTING:
  rua = Aggregate reports (daily summaries)
  ruf = Forensic reports (individual failure details)

EXAMPLE:
"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
  = Reject 100% of failures, send reports to dmarc@example.com
"""

import dns.resolver
import re  # Regular expressions for parsing email addresses


def scan_dmarc(domain):
    """
    Parse DMARC policy, reporting addresses, and enforcement percentage
    
    ALGORITHM:
    1. Query TXT record at _dmarc.{domain}
    2. Find record starting with "v=DMARC1"
    3. Extract:
       - p= (policy: none/quarantine/reject)
       - rua= (aggregate report email)
       - ruf= (forensic report email)
       - pct= (percentage of emails to apply policy to)
    
    Args:
        domain (str): Domain to check (will query _dmarc.{domain})
    
    Returns:
        dict: {'record': 'full DMARC string',
               'policy': 'reject',
               'aggregate_reports': 'dmarc-reports@example.com',
               'forensic_reports': 'dmarc-forensic@example.com',
               'percentage': 100}
    """
    try:
        # DMARC records are published at _dmarc subdomain
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        
        # Find DMARC record
        for rdata in answers:
            txt = str(rdata).strip('"')
            
            if txt.startswith('v=DMARC1'):
                result = {'record': txt}
                
                # === EXTRACT POLICY ===
                # What to do with emails that fail authentication
                if 'p=reject' in txt:
                    result['policy'] = 'reject'  # Strongest: reject email
                elif 'p=quarantine' in txt:
                    result['policy'] = 'quarantine'  # Medium: spam folder
                elif 'p=none' in txt:
                    result['policy'] = 'none'  # Weakest: just monitor
                
                # === EXTRACT AGGREGATE REPORTING EMAIL ===
                # Daily summaries of authentication results
                # Format: rua=mailto:dmarc@example.com
                rua_match = re.search(r'rua=mailto:([^;\s]+)', txt)
                if rua_match:
                    result['aggregate_reports'] = rua_match.group(1)
                
                # === EXTRACT FORENSIC REPORTING EMAIL ===
                # Individual failure reports (detailed)
                # Format: ruf=mailto:forensic@example.com
                ruf_match = re.search(r'ruf=mailto:([^;\s]+)', txt)
                if ruf_match:
                    result['forensic_reports'] = ruf_match.group(1)
                
                # === EXTRACT PERCENTAGE ===
                # What % of emails to apply policy to (0-100)
                # pct=100 means apply to all emails
                pct_match = re.search(r'pct=(\d+)', txt)
                if pct_match:
                    result['percentage'] = int(pct_match.group(1))
                
                return result
        
        return {}  # No DMARC record found
    
    except Exception:
        return {}  # Query failed or parse error
