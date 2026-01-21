import argparse


def argparse_args():
    parser = argparse.ArgumentParser(
        prog='dns_mapper',
        description='DNS reconnaissance: comprehensive DNS mapping and analysis',
        epilog='Examples:\n'
               '  %(prog)s example.com                    # Basic scan\n'
               '  %(prog)s example.com -o report.html     # HTML output\n'
               '  %(prog)s example.com --fast             # Quick mode\n'
               '  %(prog)s example.com --thorough         # Deep analysis\n'
               '  %(prog)s example.com --enable-only A,MX # Only A and MX records\n'
               '  %(prog)s example.com --disable mx,srv   # Skip MX and SRV',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required
    parser.add_argument('domain', help='Domain to analyze (e.g., example.com)')
    
    # Output (auto-detect format from extension)
    parser.add_argument('-o', '--output', 
                       help='Output file (format auto-detected: .html/.json/.xlsx or use --format)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'excel', 'html'], 
                       help='Force output format (default: auto-detect from extension or text)')
    parser.add_argument('--export-all', action='store_true',
                       help='Export to all formats: dns_map.{html,json,xlsx}')
    
    # Scan control
    parser.add_argument('-d', '--depth', type=int, default=2, 
                       help='Recursion depth (default: 2)')
    parser.add_argument('--max-results', type=int, default=100, 
                       help='Max total results (default: 100)')
    
    # Strategy selection (simplified)
    strategy_group = parser.add_argument_group('Strategy selection (comma-separated)')
    strategy_group.add_argument('--enable-only', 
                               help='Run ONLY these strategies (e.g., "A,MX,NS,TXT")')
    strategy_group.add_argument('--disable', 
                               help='Skip these strategies (e.g., "srv,axfr,ip_neighbors")')
    
    # Scan modes (presets)
    mode_group = parser.add_argument_group('Scan modes (presets)')
    mode_group.add_argument('--fast', action='store_true',
                           help='Fast mode: depth=1, max=50, skip slow strategies')
    mode_group.add_argument('--thorough', action='store_true',
                           help='Thorough mode: depth=3, max=500, all strategies, 50 threads')
    
    # Advanced options (rarely needed)
    adv_group = parser.add_argument_group('Advanced options')
    adv_group.add_argument('--threads', type=int, default=30, 
                          help='Thread count (default: 30)')
    adv_group.add_argument('--timeout', type=int, default=2,
                          help='DNS timeout in seconds (default: 2)')
    adv_group.add_argument('--nameserver', 
                          help='Custom DNS server IP')
    adv_group.add_argument('--subdomain-wordlist', 
                          help='Custom subdomain wordlist file')
    adv_group.add_argument('--srv-services', 
                          help='Custom SRV services file')
    
    # Verbosity
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help='Verbose mode (-v, -vv for debug)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (errors only)')
    
    args = parser.parse_args()
    
    # Apply presets
    if args.fast:
        args.depth = 1
        args.max_results = 50
        args.threads = 20
        args.disable = (args.disable or '') + ',subdomains,ip_neighbors,srv,axfr'
    
    if args.thorough:
        args.depth = 3
        args.max_results = 500
        args.threads = 50
    
    # Parse strategy filters
    if args.enable_only:
        enabled = [s.strip().lower() for s in args.enable_only.split(',')]
        all_strategies = ['txt', 'spf', 'dmarc', 'srv', 'reverse_dns', 'ptr', 'ip_neighbors', 
                         'subdomains', 'crawl_tld', 'ns', 'soa', 'a', 'aaaa', 'cname', 'mx',
                         'caa', 'axfr', 'reverse_ipv6', 'dnssec', 'http_headers', 'wildcard',
                         'ttl', 'security_txt', 'bimi', 'mta_sts', 'geolocation', 'tlsa',
                         'sshfp', 'cert', 'hinfo', 'loc', 'naptr', 'ds', 'dnskey', 'nsec',
                         'anycast', 'loadbalancer', 'cdn_enhanced', 'mail_blacklist', 'domain_age']
        disabled = [s for s in all_strategies if s not in enabled]
        for strategy in disabled:
            setattr(args, f'disable_{strategy}', True)
    
    if args.disable:
        disabled = [s.strip().lower() for s in args.disable.split(',')]
        for strategy in disabled:
            setattr(args, f'disable_{strategy}', True)
    
    # Auto-detect output format from extension
    if args.output and not args.format:
        if args.output.endswith('.html'):
            args.format = 'html'
        elif args.output.endswith('.json'):
            args.format = 'json'
        elif args.output.endswith('.xlsx'):
            args.format = 'excel'
        else:
            args.format = 'text'
    elif not args.format:
        args.format = 'text'
    
    # Set default filenames for export-all
    args.excel_output = 'dns_map.xlsx'
    args.html_output = 'dns_map.html'
    args.json_output = 'dns_map.json'
    
    # Defaults for removed options
    args.parallel = True
    args.max_per_strategy = 50
    args.hide_providers = []
    args.neighbor_range = 2
    args.subdomain_quick = False
    args.subdomain_thorough = False
    args.srv_common_only = False
    args.show_progress = True
    args.cache = True
    args.no_color = False
    args.log_file = None
    
    # Validation
    if args.quiet and args.verbose > 0:
        parser.error("--quiet and --verbose are mutually exclusive")
    if args.fast and args.thorough:
        parser.error("--fast and --thorough are mutually exclusive")
    
    return args



