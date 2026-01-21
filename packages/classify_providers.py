"""Classify and identify CDN/cloud providers from domain names."""


def classify_providers(domain):
    """Identify known CDN and cloud providers from domain name.
    
    Args:
        domain (str): Domain name to classify
    
    Returns:
        dict: Provider classification results
    """
    # Common provider patterns
    providers = {
        'cloudfront': 'Amazon CloudFront',
        'akamai': 'Akamai',
        'fastly': 'Fastly',
        'cloudflare': 'Cloudflare',
        'azure': 'Microsoft Azure',
        'googleapis': 'Google Cloud',
        'amazonaws': 'AWS',
    }
    
    results = []
    domain_lower = domain.lower()
    
    for pattern, name in providers.items():
        if pattern in domain_lower:
            results.append({'provider': name, 'pattern': pattern})
    
    return results
