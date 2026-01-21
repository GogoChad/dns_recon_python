"""HINFO record scanner for host information."""

import dns.resolver

def scan_hinfo(domain, resolver_obj=None):
    """
    Scan for HINFO records (Host Information).
    Provides CPU and OS information (rarely used due to security concerns).
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'HINFO')
        records = []
        
        for rdata in answers:
            # HINFO has two fields: CPU and OS
            cpu = rdata.cpu.decode('utf-8') if isinstance(rdata.cpu, bytes) else str(rdata.cpu)
            os = rdata.os.decode('utf-8') if isinstance(rdata.os, bytes) else str(rdata.os)
            
            record_info = {
                'cpu': cpu,
                'os': os,
                'warning': 'HINFO exposes system information - security risk'
            }
            records.append(record_info)
        
        return {domain: records} if records else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
