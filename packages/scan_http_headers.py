"""Check HTTP/HTTPS response headers for additional discovery."""

import socket

def scan_http_headers(domain):
    """Check HTTP headers for server info, security headers, and redirects."""
    results = {}
    
    for protocol in ['http', 'https']:
        try:
            import http.client
            
            if protocol == 'https':
                conn = http.client.HTTPSConnection(domain, timeout=3)
            else:
                conn = http.client.HTTPConnection(domain, timeout=3)
            
            conn.request('HEAD', '/')
            response = conn.getresponse()
            
            headers_of_interest = [
                'Server', 'X-Powered-By', 'X-AspNet-Version', 
                'X-Generator', 'X-Drupal-Cache', 'X-Varnish',
                'Via', 'X-Cache', 'CF-Ray', 'X-Amz-Cf-Id',
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Frame-Options', 'X-Content-Type-Options',
                'Location'
            ]
            
            found_headers = {}
            for header in headers_of_interest:
                value = response.getheader(header)
                if value:
                    found_headers[header] = value
            
            if found_headers:
                results[protocol] = {
                    'status': response.status,
                    'headers': found_headers
                }
            
            conn.close()
        except:
            pass
    
    return results
