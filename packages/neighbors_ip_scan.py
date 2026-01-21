"""Scan neighboring IP addresses for reverse DNS - OPTIMIZED."""

import ipaddress


def neighbors_ip_scan(ip, range_size=2):
    """Scan neighboring IP addresses (reduced range for speed).
    
    Args:
        ip (str): IP address to scan around
        range_size (int): Number of IPs to check on each side (default: 2)
    
    Returns:
        list: Neighboring IP addresses
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        neighbors = []
        
        # Scan before and after (smaller range for speed)
        for offset in range(-range_size, range_size + 1):
            if offset == 0:
                continue
            try:
                neighbor = ip_obj + offset
                neighbors.append(str(neighbor))
            except:
                pass
        
        return neighbors
    except ValueError:
        return []
