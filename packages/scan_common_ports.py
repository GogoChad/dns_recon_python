"""Check for common ports and services on discovered IPs."""

import socket

def scan_common_ports(ip, timeout=1):
    """Quick check for common open ports on an IP."""
    # Most common ports for web servers and services
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP-Submission',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    results = []
    
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                results.append({
                    'port': port,
                    'service': service,
                    'state': 'open'
                })
        except:
            pass
        finally:
            sock.close()
    
    return results
