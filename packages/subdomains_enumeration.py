"""Enumerate subdomains through bruteforce - OPTIMIZED."""

import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Fast resolver
resolver = dns.resolver.Resolver()
resolver.timeout = 1
resolver.lifetime = 2

def _check_subdomain(sub, domain):
    """Check single subdomain."""
    subdomain = f"{sub}.{domain}"
    try:
        resolver.resolve(subdomain, 'A')
        return subdomain
    except:
        return None

def subdomains_enumeration(domain, wordlist=None):
    """Enumerate subdomains using parallel DNS queries.
    
    Args:
        domain (str): Domain name
        wordlist (list, optional): Custom subdomain wordlist
    
    Returns:
        list: Found subdomains
    """
    if wordlist is None:
        wordlist = [
            'www', 'mail', 'ftp', 'api', 'blog', 'shop',
            'admin', 'dev', 'staging', 'test', 'vpn',
            'cdn', 'static', 'assets', 'img', 'images',
        ]
    
    found = []
    # Parallel execution with 30 threads for speed (silent mode)
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(_check_subdomain, sub, domain): sub for sub in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    
    return found
