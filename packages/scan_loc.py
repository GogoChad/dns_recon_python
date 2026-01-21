"""LOC record scanner for geographic coordinates."""

import dns.resolver

def scan_loc(domain, resolver_obj=None):
    """
    Scan for LOC records (Location).
    Provides geographic coordinates of hosts/services.
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    try:
        answers = resolver_obj.resolve(domain, 'LOC')
        records = []
        
        for rdata in answers:
            # Convert to decimal degrees
            lat_deg = rdata.latitude[0]
            lat_min = rdata.latitude[1]
            lat_sec = rdata.latitude[2]
            lat_dir = 'N' if rdata.latitude[3] == 'N' else 'S'
            
            lon_deg = rdata.longitude[0]
            lon_min = rdata.longitude[1]
            lon_sec = rdata.longitude[2]
            lon_dir = 'E' if rdata.longitude[3] == 'E' else 'W'
            
            # Convert to decimal
            lat_decimal = lat_deg + (lat_min / 60.0) + (lat_sec / 3600.0)
            if lat_dir == 'S':
                lat_decimal = -lat_decimal
                
            lon_decimal = lon_deg + (lon_min / 60.0) + (lon_sec / 3600.0)
            if lon_dir == 'W':
                lon_decimal = -lon_decimal
            
            altitude = rdata.altitude / 100.0  # Convert from centimeters to meters
            size = rdata.size / 100.0
            h_precision = rdata.horizontal_precision / 100.0
            v_precision = rdata.vertical_precision / 100.0
            
            record_info = {
                'latitude': f"{lat_deg}°{lat_min}'{lat_sec}\"{lat_dir}",
                'longitude': f"{lon_deg}°{lon_min}'{lon_sec}\"{lon_dir}",
                'latitude_decimal': round(lat_decimal, 6),
                'longitude_decimal': round(lon_decimal, 6),
                'altitude_m': round(altitude, 2),
                'size_m': round(size, 2),
                'horizontal_precision_m': round(h_precision, 2),
                'vertical_precision_m': round(v_precision, 2),
                'maps_url': f"https://www.google.com/maps?q={lat_decimal},{lon_decimal}"
            }
            records.append(record_info)
        
        return {domain: records} if records else None
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None
