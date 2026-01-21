"""Enhanced CDN detection beyond CNAME analysis."""

import dns.resolver

def scan_cdn_enhanced(domain, resolver_obj=None):
    """
    Enhanced CDN detection using multiple signals:
    - CNAME patterns
    - ASN analysis
    - NS record patterns
    - TXT record hints
    - IP range analysis
    """
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
    
    results = {
        'cdn_detected': False,
        'cdn_provider': None,
        'confidence': 'NONE',
        'detection_methods': []
    }
    
    # Known CDN patterns
    cdn_patterns = {
        'Cloudflare': ['cloudflare.com', 'cloudflare.net', 'cloudflare-dns.com'],
        'Akamai': ['akamai.net', 'akamaiedge.net', 'akamaitechnologies.com', 'akamaihd.net'],
        'Fastly': ['fastly.net', 'fastlylb.net'],
        'Amazon CloudFront': ['cloudfront.net', 'awsdns', 'amazonaws.com'],
        'Google Cloud CDN': ['1e100.net', 'google.com', 'goog'],
        'Microsoft Azure CDN': ['azureedge.net', 'azure.com', 'trafficmanager.net'],
        'Cloudinary': ['cloudinary.com'],
        'KeyCDN': ['keycdn.com'],
        'StackPath': ['stackpathcdn.com', 'netdna-cdn.com'],
        'BunnyCDN': ['bunnycdn.com'],
        'CDN77': ['cdn77.org'],
        'Imperva (Incapsula)': ['incapdns.net', 'incapsula.com'],
        'Sucuri': ['sucuri.net'],
        'Netlify': ['netlify.app', 'netlify.com'],
        'Vercel': ['vercel.app', 'vercel-dns.com'],
    }
    
    cdn_asns = {
        '13335': 'Cloudflare',
        '16509': 'Amazon (CloudFront)',
        '15169': 'Google',
        '8075': 'Microsoft Azure',
        '20940': 'Akamai',
        '54113': 'Fastly',
        '16625': 'Akamai',
    }
    
    indicators = []
    detected_providers = []
    
    # 1. CNAME analysis
    try:
        cname_answers = resolver_obj.resolve(domain, 'CNAME')
        for rdata in cname_answers:
            cname = str(rdata).lower().rstrip('.')
            for provider, patterns in cdn_patterns.items():
                if any(pattern in cname for pattern in patterns):
                    indicators.append(f'CNAME points to {provider}: {cname}')
                    detected_providers.append(provider)
                    results['cdn_detected'] = True
    except:
        pass
    
    # 2. NS record analysis
    try:
        ns_answers = resolver_obj.resolve(domain, 'NS')
        for rdata in ns_answers:
            ns = str(rdata).lower().rstrip('.')
            for provider, patterns in cdn_patterns.items():
                if any(pattern in ns for pattern in patterns):
                    indicators.append(f'NS hosted by {provider}: {ns}')
                    detected_providers.append(provider)
                    results['cdn_detected'] = True
    except:
        pass
    
    # 3. A record IP analysis
    try:
        a_answers = resolver_obj.resolve(domain, 'A')
        ips = [str(rdata) for rdata in a_answers]
        
        # Multiple IPs suggest CDN
        if len(ips) > 2:
            indicators.append(f'Multiple IPs ({len(ips)}) suggest CDN distribution')
        
        # Check ASN for each IP
        for ip in ips[:3]:  # Check first 3 IPs
            try:
                reversed_ip = '.'.join(reversed(ip.split('.')))
                query_name = f"{reversed_ip}.origin.asn.cymru.com"
                answer = resolver_obj.resolve(query_name, 'TXT')
                
                for txt_rdata in answer:
                    txt = txt_rdata.to_text().strip('"')
                    parts = [p.strip() for p in txt.split('|')]
                    if len(parts) >= 1:
                        asn = parts[0]
                        
                        if asn in cdn_asns:
                            provider = cdn_asns[asn]
                            indicators.append(f'IP {ip} belongs to {provider} (ASN {asn})')
                            detected_providers.append(provider)
                            results['cdn_detected'] = True
                        
                        # Get ASN name
                        try:
                            asn_query = f"AS{asn}.asn.cymru.com"
                            asn_answer = resolver_obj.resolve(asn_query, 'TXT')
                            for asn_rdata in asn_answer:
                                asn_txt = asn_rdata.to_text().strip('"')
                                asn_parts = [p.strip() for p in asn_txt.split('|')]
                                if len(asn_parts) >= 5:
                                    asn_name = asn_parts[4].upper()
                                    # Check if ASN name matches known CDN
                                    for provider, patterns in cdn_patterns.items():
                                        if any(pattern.upper().replace('.', '') in asn_name for pattern in patterns):
                                            indicators.append(f'ASN name matches {provider}: {asn_name}')
                                            detected_providers.append(provider)
                                            results['cdn_detected'] = True
                                    break
                        except:
                            pass
                        break
            except:
                continue
    except:
        pass
    
    # 4. TXT record hints
    try:
        txt_answers = resolver_obj.resolve(domain, 'TXT')
        for rdata in txt_answers:
            txt = rdata.to_text().lower()
            for provider, patterns in cdn_patterns.items():
                if any(pattern in txt for pattern in patterns):
                    indicators.append(f'TXT record references {provider}')
                    detected_providers.append(provider)
                    results['cdn_detected'] = True
    except:
        pass
    
    # 5. TTL analysis (CDNs often use low TTL)
    try:
        a_answers = resolver_obj.resolve(domain, 'A')
        ttl = a_answers.rrset.ttl
        if ttl < 300:
            indicators.append(f'Low TTL ({ttl}s) typical of CDN')
    except:
        pass
    
    # Determine primary provider and confidence
    if detected_providers:
        from collections import Counter
        provider_counts = Counter(detected_providers)
        primary_provider = provider_counts.most_common(1)[0][0]
        detection_count = provider_counts[primary_provider]
        
        results['cdn_provider'] = primary_provider
        results['confidence'] = 'HIGH' if detection_count >= 3 else ('MEDIUM' if detection_count == 2 else 'LOW')
        results['detection_methods'] = indicators
        results['all_detected_providers'] = list(set(detected_providers))
        
        return {domain: results}
    
    if indicators:
        results['detection_methods'] = indicators
        results['confidence'] = 'LOW'
        return {domain: results}
    
    return None
