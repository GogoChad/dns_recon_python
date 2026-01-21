"""Mail server blacklist checking via DNS (DNSBL queries)."""

import dns.resolver

def scan_mail_blacklist(domain, resolver_obj=None):
    """
    Check mail server IPs against major DNS blacklists.
    Queries: Spamhaus, SpamCop, SORBS, Barracuda, etc.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    # Get MX records first
    mail_servers = []
    try:
        mx_answers = resolver_obj.resolve(domain, 'MX')
        for rdata in mx_answers:
            mx_host = str(rdata.exchange).rstrip('.')
            
            # Resolve MX to IP
            try:
                a_answers = resolver_obj.resolve(mx_host, 'A')
                for a_rdata in a_answers:
                    ip = str(a_rdata)
                    mail_servers.append({
                        'mx_host': mx_host,
                        'ip': ip,
                        'priority': rdata.preference
                    })
            except:
                continue
    except:
        # No MX records, try A record of domain
        try:
            a_answers = resolver_obj.resolve(domain, 'A')
            for rdata in a_answers:
                ip = str(rdata)
                mail_servers.append({
                    'mx_host': domain,
                    'ip': ip,
                    'priority': 0
                })
        except:
            return None
    
    if not mail_servers:
        return None
    
    # Major DNSBLs
    blacklists = {
        'zen.spamhaus.org': 'Spamhaus ZEN (combined list)',
        'bl.spamcop.net': 'SpamCop',
        'dnsbl.sorbs.net': 'SORBS',
        'b.barracudacentral.org': 'Barracuda',
        'dnsbl-1.uceprotect.net': 'UCEPROTECT Level 1',
        'cbl.abuseat.org': 'Composite Blocking List',
        'psbl.surriel.com': 'Passive Spam Block List',
        'dnsbl.dronebl.org': 'DroneBL',
        'spam.dnsbl.anonmails.de': 'AnonMails DNSBL',
    }
    
    results = []
    
    for server in mail_servers:
        ip = server['ip']
        mx_host = server['mx_host']
        
        # Reverse IP for DNSBL queries
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        blacklist_hits = []
        blacklist_details = []
        
        for dnsbl, name in blacklists.items():
            query = f"{reversed_ip}.{dnsbl}"
            
            try:
                # Query DNSBL
                answer = resolver_obj.resolve(query, 'A')
                # If we get a response, IP is listed
                response_ips = [str(rdata) for rdata in answer]
                
                # Get TXT record for details
                reason = None
                try:
                    txt_answer = resolver_obj.resolve(query, 'TXT')
                    for txt_rdata in txt_answer:
                        reason = txt_rdata.to_text().strip('"')
                        break
                except:
                    pass
                
                blacklist_hits.append(name)
                blacklist_details.append({
                    'blacklist': name,
                    'dnsbl': dnsbl,
                    'listed': True,
                    'response': response_ips[0] if response_ips else None,
                    'reason': reason
                })
                
            except dns.resolver.NXDOMAIN:
                # Not listed (good)
                continue
            except:
                # Query failed or timeout
                continue
        
        # Reputation score
        total_checked = len(blacklists)
        listed_count = len(blacklist_hits)
        clean_count = total_checked - listed_count
        
        reputation = 'EXCELLENT' if listed_count == 0 else \
                    'GOOD' if listed_count == 1 else \
                    'POOR' if listed_count <= 3 else \
                    'CRITICAL'
        
        server_result = {
            'mx_host': mx_host,
            'ip': ip,
            'priority': server['priority'],
            'reputation': reputation,
            'blacklists_checked': total_checked,
            'blacklists_listed': listed_count,
            'blacklists_clean': clean_count,
            'listed_on': blacklist_hits if blacklist_hits else None,
            'blacklist_details': blacklist_details if blacklist_details else None,
            'clean': listed_count == 0
        }
        
        results.append(server_result)
    
    if results:
        # Overall summary
        total_servers = len(results)
        clean_servers = sum(1 for r in results if r['clean'])
        
        return {
            domain: {
                'mail_servers': results,
                'summary': f'{clean_servers}/{total_servers} mail servers clean',
                'overall_status': 'CLEAN' if clean_servers == total_servers else 'ISSUES_DETECTED'
            }
        }
    
    return None
