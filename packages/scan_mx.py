"""
Scan MX (Mail Exchange) Records

PRESENTATION EXPLANATION:
=========================
MX records tell email senders where to deliver mail for a domain.
Each MX has a priority number (lower = higher priority).

WHY IMPORTANT:
- Multiple MX records = redundancy (if primary fails, try secondary)
- Priority determines delivery order
- MX hostname often reveals email provider (Google, Microsoft, etc.)

EXAMPLE:
example.com MX records:
  Priority 10: mail1.google.com (resolves to 142.250.185.27)
  Priority 20: mail2.google.com (resolves to 142.250.185.28)
  
Email senders try priority 10 first, then 20 if it fails.
"""

import dns.resolver

# Global resolver with reasonable timeouts
resolver = dns.resolver.Resolver()
resolver.timeout = 2  # 2 seconds per query
resolver.lifetime = 5  # 5 seconds total with retries

def scan_mx(domain):
    """
    Query MX records and resolve mail servers to IP addresses
    
    ALGORITHM:
    1. Query MX records for domain
    2. For each MX record:
       a. Extract hostname (exchange) and priority (preference)
       b. Resolve hostname to IPv4 addresses (A records)
    3. Sort by priority (lower number = higher priority)
    
    Args:
        domain (str): Domain to check (e.g., "example.com")
    
    Returns:
        list: Array of mail servers sorted by priority:
              [{'host': 'mail1.example.com',
                'priority': 10,
                'ips': ['1.2.3.4', '1.2.3.5']},
               {'host': 'mail2.example.com',
                'priority': 20,
                'ips': ['5.6.7.8']}]
              
    PRESENTATION TIP:
    Lower priority = Higher importance!
    Priority 10 is tried BEFORE priority 20.
    """
    try:
        # Query MX records from DNS
        answers = resolver.resolve(domain, 'MX')
        results = []
        
        for rdata in answers:
            # Extract mail server details
            mx_host = str(rdata.exchange).rstrip('.')  # Remove trailing dot
            priority = rdata.preference  # Lower = higher priority
            
            # === RESOLVE MX HOSTNAME TO IPs ===
            # Mail servers need IPs to be reachable
            ips = []
            try:
                a_records = resolver.resolve(mx_host, 'A')
                ips = [str(ip) for ip in a_records]
            except:
                pass  # Failed to resolve (MX may be misconfigured)
            
            # Build result dictionary
            results.append({
                'host': mx_host,
                'priority': priority,
                'ips': ips
            })
        
        # === SORT BY PRIORITY ===
        # Email senders try lowest priority first
        # Priority 10 before priority 20 before priority 30, etc.
        return sorted(results, key=lambda x: x['priority'])
    
    except:
        return []  # No MX records or query failed
