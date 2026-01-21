"""Crawl domain hierarchy up to TLD."""


def crawl_to_tld(domain):
    """Extract parent domains up to the TLD.
    
    Args:
        domain (str): Domain name to crawl
    
    Returns:
        list: Parent domains excluding TLD
    """
    # Common TLDs (add more as needed)
    tlds = ['com', 'org', 'net', 'edu', 'gov', 'fr', 'gouv.fr', 'co.uk']
    
    parts = domain.split('.')
    parents = []
    
    # Build parent domains
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        # Don't include TLDs
        if parent not in tlds:
            parents.append(parent)
    
    return parents
