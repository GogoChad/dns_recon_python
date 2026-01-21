"""Load balancer detection via round-robin and response analysis."""

import dns.resolver
import time
from collections import Counter

def scan_loadbalancer(domain, resolver_obj=None):
    """
    Detect load balancing by analyzing multiple DNS queries for response patterns.
    Identifies round-robin, weighted, and geographic load balancing.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    results = {}
    
    # Perform multiple queries to detect rotation
    num_queries = 10
    all_responses = []
    response_patterns = []
    
    for i in range(num_queries):
        try:
            answers = resolver_obj.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            all_responses.extend(ips)
            response_patterns.append(tuple(sorted(ips)))
            
            # Small delay to allow rotation
            if i < num_queries - 1:
                time.sleep(0.1)
        except:
            break
    
    if not all_responses:
        return None
    
    # Analyze patterns
    ip_counts = Counter(all_responses)
    pattern_counts = Counter(response_patterns)
    unique_ips = list(ip_counts.keys())
    
    # Detection logic
    indicators = []
    lb_type = None
    
    # Multiple IPs returned
    if len(unique_ips) > 1:
        indicators.append(f'{len(unique_ips)} unique IPs detected')
        
        # Check if order changes (round-robin)
        if len(pattern_counts) > 1:
            indicators.append('IP order varies between queries (round-robin)')
            lb_type = 'Round-Robin DNS'
        
        # Check distribution
        counts = list(ip_counts.values())
        max_count = max(counts)
        min_count = min(counts)
        
        if max_count == min_count:
            indicators.append('Equal distribution detected (uniform load balancing)')
            if not lb_type:
                lb_type = 'Uniform Load Balancing'
        elif max_count > min_count * 2:
            indicators.append(f'Unequal distribution (weighted load balancing)')
            lb_type = 'Weighted Load Balancing'
        
        # Low TTL indicates dynamic balancing
        try:
            answers = resolver_obj.resolve(domain, 'A')
            ttl = answers.rrset.ttl
            if ttl < 60:
                indicators.append(f'Very low TTL ({ttl}s) suggests active load balancing')
            elif ttl < 300:
                indicators.append(f'Low TTL ({ttl}s) suggests load balancing')
        except:
            pass
        
        # Check for geographic diversity via reverse DNS
        hostnames = []
        for ip in unique_ips[:5]:  # Check first 5 IPs
            try:
                reversed_ip = '.'.join(reversed(ip.split('.')))
                ptr_query = f"{reversed_ip}.in-addr.arpa"
                ptr_answer = resolver_obj.resolve(ptr_query, 'PTR')
                for rdata in ptr_answer:
                    hostname = str(rdata).rstrip('.')
                    hostnames.append(hostname)
                    break
            except:
                continue
        
        if hostnames:
            # Look for location codes in hostnames
            location_codes = []
            for hostname in hostnames:
                parts = hostname.split('.')
                for part in parts:
                    # Common location patterns: sea1, lax2, fra, etc.
                    if len(part) >= 3 and any(char.isdigit() for char in part):
                        location_codes.append(part[:3])
            
            unique_locations = len(set(location_codes))
            if unique_locations > 1:
                indicators.append(f'{unique_locations} geographic locations detected (geo load balancing)')
                lb_type = 'Geographic Load Balancing'
        
        # Determine confidence
        confidence = 'HIGH' if len(indicators) >= 3 else ('MEDIUM' if len(indicators) == 2 else 'LOW')
        
        results[domain] = {
            'load_balanced': True,
            'load_balancer_type': lb_type or 'Unknown',
            'ip_count': len(unique_ips),
            'ips': unique_ips,
            'distribution': dict(ip_counts),
            'queries_performed': num_queries,
            'patterns_detected': len(pattern_counts),
            'indicators': indicators,
            'confidence': confidence,
            'hostnames': hostnames if hostnames else None
        }
        
        return results
    
    # Single IP - not load balanced
    return {
        domain: {
            'load_balanced': False,
            'ip': unique_ips[0],
            'note': 'Single IP - no load balancing detected'
        }
    }
