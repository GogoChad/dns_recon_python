"""NAPTR record scanner for VoIP/SIP and ENUM services."""

import dns.resolver

def scan_naptr(domain, resolver_obj=None):
    """
    Scan for NAPTR records (Name Authority Pointer).
    Used for VoIP/SIP, ENUM (telephone number mapping), and service discovery.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'NAPTR')
        records = []
        
        for rdata in answers:
            order = rdata.order
            preference = rdata.preference
            flags = rdata.flags.decode('utf-8') if isinstance(rdata.flags, bytes) else str(rdata.flags)
            service = rdata.service.decode('utf-8') if isinstance(rdata.service, bytes) else str(rdata.service)
            regexp = rdata.regexp.decode('utf-8') if isinstance(rdata.regexp, bytes) else str(rdata.regexp)
            replacement = str(rdata.replacement)
            
            # Determine service type
            service_type = 'Unknown'
            if 'SIP' in service.upper():
                service_type = 'SIP/VoIP'
            elif 'E2U' in service.upper():
                service_type = 'ENUM (Phone Number)'
            elif 'HTTP' in service.upper():
                service_type = 'HTTP Service'
            
            record_info = {
                'order': order,
                'preference': preference,
                'flags': flags,
                'service': service,
                'service_type': service_type,
                'regexp': regexp if regexp else None,
                'replacement': replacement if replacement != '.' else None,
                'priority_score': (order * 1000) + preference  # Combined priority
            }
            records.append(record_info)
        
        # Sort by priority
        records.sort(key=lambda x: x['priority_score'])
        
        return {domain: records} if records else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
