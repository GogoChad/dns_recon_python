"""Scan for SRV (Service) records - OPTIMIZED."""

import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

resolver = dns.resolver.Resolver()
resolver.timeout = 1
resolver.lifetime = 2

def _check_srv(service, domain):
    """Check single SRV record."""
    query = f"{service}.{domain}"
    try:
        answers = resolver.resolve(query, 'SRV')
        return [(query, str(rdata)) for rdata in answers]
    except:
        return []

def srv_scan(domain, services=None):
    """Query SRV records for common services.
    
    Args:
        domain (str): Domain name
        services (list, optional): List of service names to check
    
    Returns:
        dict: Found SRV records by service
    """
    if services is None:
        services = [
            '_sip._tcp', '_sip._udp', '_sips._tcp',
            '_ldap._tcp', '_ldaps._tcp',
            '_xmpp-server._tcp', '_xmpp-client._tcp',
            '_jabber._tcp', '_xmpp-federation._tcp',
            '_caldav._tcp', '_caldavs._tcp',
            '_carddav._tcp', '_carddavs._tcp',
            '_imap._tcp', '_imaps._tcp',
            '_pop3._tcp', '_pop3s._tcp',
            '_smtp._tcp', '_submission._tcp',
            '_irc._tcp', '_ircs._tcp',
            '_minecraft._tcp',
            '_teamspeak._tcp', '_mumble._tcp',
            '_http._tcp', '_https._tcp',
            '_autodiscover._tcp',
            '_kerberos._tcp', '_kerberos._udp',
            '_kpasswd._tcp', '_kpasswd._udp',
        ]
    
    results = {}
    for service in services:
        try:
            srv_domain = f"{service}.{domain}"
            answers = dns.resolver.resolve(srv_domain, 'SRV')
            results[service] = [str(rdata.target) for rdata in answers]
        except Exception:
            pass
    
    return results
