"""Domain age estimation from SOA serial number analysis."""

import dns.resolver
from datetime import datetime, timedelta

def scan_domain_age(domain, resolver_obj=None):
    """
    Estimate domain age and zone update patterns from SOA serial number.
    Serial formats: YYYYMMDDnn (RFC 1912) or Unix timestamp
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        soa_answers = resolver_obj.resolve(domain, 'SOA')
        soa = soa_answers[0]
        
        serial = soa.serial
        serial_str = str(serial)
        
        results = {
            'serial': serial,
            'serial_format': None,
            'estimated_date': None,
            'estimated_age_days': None,
            'age_category': None,
            'last_update_estimate': None,
            'update_pattern': None
        }
        
        # Try to parse serial as date format (YYYYMMDDnn)
        if len(serial_str) == 10 and serial_str[:8].isdigit():
            # RFC 1912 format: YYYYMMDDnn
            try:
                year = int(serial_str[:4])
                month = int(serial_str[4:6])
                day = int(serial_str[6:8])
                revision = int(serial_str[8:10])
                
                if 1990 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
                    date = datetime(year, month, day)
                    results['serial_format'] = f'RFC 1912 (YYYYMMDDnn) - revision {revision}'
                    results['estimated_date'] = date.isoformat()
                    results['last_update_estimate'] = date.strftime('%Y-%m-%d')
                    
                    # Calculate age
                    age = (datetime.now() - date).days
                    results['estimated_age_days'] = age
                    
                    # Age categories
                    if age < 30:
                        results['age_category'] = 'Very Recent (< 1 month)'
                    elif age < 365:
                        results['age_category'] = f'Recent ({age // 30} months)'
                    elif age < 1825:  # 5 years
                        results['age_category'] = f'Mature ({age // 365} years)'
                    else:
                        results['age_category'] = f'Established ({age // 365} years)'
                    
                    # Update pattern based on SOA timing fields
                    refresh = soa.refresh
                    if refresh < 3600:
                        results['update_pattern'] = f'Frequently updated (refresh every {refresh // 60}m)'
                    elif refresh < 86400:
                        results['update_pattern'] = f'Regular updates (refresh every {refresh // 3600}h)'
                    else:
                        results['update_pattern'] = f'Infrequent updates (refresh every {refresh // 86400}d)'
                    
                    return {domain: results}
            except ValueError:
                pass
        
        # Try Unix timestamp format
        if serial < 4294967295:  # Max 32-bit unsigned int
            try:
                # Check if it's a reasonable timestamp (after 2000-01-01)
                if serial > 946684800:  # 2000-01-01 timestamp
                    date = datetime.fromtimestamp(serial)
                    
                    # Must be in the past and not too old
                    if date < datetime.now() and date.year >= 1990:
                        results['serial_format'] = 'Unix timestamp'
                        results['estimated_date'] = date.isoformat()
                        results['last_update_estimate'] = date.strftime('%Y-%m-%d %H:%M:%S')
                        
                        age = (datetime.now() - date).days
                        results['estimated_age_days'] = age
                        
                        if age < 30:
                            results['age_category'] = 'Very Recent (< 1 month)'
                        elif age < 365:
                            results['age_category'] = f'Recent ({age // 30} months)'
                        elif age < 1825:
                            results['age_category'] = f'Mature ({age // 365} years)'
                        else:
                            results['age_category'] = f'Established ({age // 365} years)'
                        
                        return {domain: results}
            except (ValueError, OSError):
                pass
        
        # If we can't parse it, just return serial info
        results['serial_format'] = 'Unknown/Custom format'
        results['note'] = 'Cannot estimate age from serial number format'
        
        # SOA timing analysis
        refresh = soa.refresh
        retry = soa.retry
        expire = soa.expire
        minimum = soa.minimum
        
        results['soa_timings'] = {
            'refresh': f'{refresh}s ({refresh // 3600}h)' if refresh >= 3600 else f'{refresh}s',
            'retry': f'{retry}s',
            'expire': f'{expire}s ({expire // 86400}d)' if expire >= 86400 else f'{expire}s',
            'negative_cache_ttl': f'{minimum}s'
        }
        
        # Zone stability assessment
        if expire < 604800:  # Less than 7 days
            results['zone_stability'] = 'Low (short expiry)'
        elif expire < 2592000:  # Less than 30 days
            results['zone_stability'] = 'Moderate'
        else:
            results['zone_stability'] = 'High (long expiry)'
        
        return {domain: results}
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
