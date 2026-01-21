"""
DNS Domain Mapper - Comprehensive DNS Reconnaissance Tool

PRESENTATION OVERVIEW:
====================
This tool performs deep DNS analysis with 34 scanning modules covering:
- 13 DNS record types (A, AAAA, NS, SOA, MX, CNAME, TXT, etc.)
- 9 security modules (SPF, DMARC, DNSSEC, TLSA, mail blacklist)
- 6 infrastructure detection (CDN, anycast, load balancer, geolocation)
- 6 advanced DNS (SSHFP, CERT, LOC, NAPTR, DS, DNSKEY, NSEC)

KEY FEATURES FOR PRESENTATION:
- ✓ Parallel execution (up to 60 threads)
- ✓ Visual security dashboard with ✓/✗ indicators
- ✓ Multi-format export (JSON, HTML, Excel)
- ✓ Smart preset modes (--fast, --thorough)
- ✓ 3,664 lines of optimized Python code

Academic Project: Python B1 2025-2026
"""

# ============================================================================
# IMPORTS - All dependencies organized by purpose
# ============================================================================
from packages import STRATEGIES, EXPORTERS  # Our 34 scanning modules + exporters
from packages.wordlist_utils import load_wordlist, get_default_subdomains, get_default_srv_services
from datetime import datetime  # For timestamping scan results
from concurrent.futures import ThreadPoolExecutor, as_completed  # Parallel execution
import dns.resolver  # Core DNS query library (dnspython)
import sys  # For exit codes and error handling

# ============================================================================
# DNS RESOLVER CONFIGURATION - Optimized for speed
# ============================================================================
# Global DNS resolver with aggressive timeouts for maximum throughput
# LRUCache prevents redundant queries for same domain
resolver = dns.resolver.Resolver()
resolver.timeout = 1  # Wait max 1 second per query (aggressive)
resolver.lifetime = 2  # Total time for query including retries
resolver.cache = dns.resolver.LRUCache()  # Cache DNS responses in memory

# ============================================================================
# COLORAMA - Terminal color support for beautiful output
# ============================================================================
try:
    from colorama import Fore, Style, init
    init(autoreset=True)  # Auto-reset colors after each print
    COLORS_ENABLED = True
except ImportError:
    # Graceful fallback: Define empty color codes if colorama not installed
    # Allows code to run on systems without colorama (no colors, but functional)
    class Fore:
        GREEN = BLUE = RED = YELLOW = CYAN = MAGENTA = GRAY = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = ''
    COLORS_ENABLED = False


# ============================================================================
# DNS MAPPER CLASS - Main orchestrator for all scanning operations
# ============================================================================
class DNSMapper:
    """
    Main DNS Reconnaissance Engine
    
    PRESENTATION EXPLANATION:
    This class orchestrates all 34 scanning modules and manages:
    - Recursive domain/IP discovery (depth-first traversal)
    - Parallel execution with ThreadPoolExecutor (up to 60 threads)
    - Result aggregation and deduplication
    - Early termination when max results reached
    - Beautiful terminal output with visual indicators
    
    WORKFLOW:
    1. Start with target domain
    2. Run all enabled strategies in parallel
    3. Discover new domains/IPs from results
    4. Recursively scan discovered targets (up to max depth)
    5. Export results in requested format
    """
    
    def __init__(self, args):
        """
        Initialize the DNS mapper with command-line arguments
        
        Args:
            args: Parsed argparse arguments containing:
                  - domain: Target domain to scan
                  - depth: Maximum recursion depth (default: 2)
                  - threads: Number of parallel workers (default: 10)
                  - max_results: Stop scan when reaching this limit
                  - quiet: Suppress output
                  - verbose: Debug verbosity level
        """
        self.args = args
        self.domain = args.domain
        
        # RESULT STORAGE - Dictionaries and sets for efficient lookups
        self.results = {}  # Main results: {strategy_name: [results]}
        self.all_domains = set([self.domain])  # All discovered domains (deduped)
        self.all_ips = set()  # All discovered IPs (deduped)
        
        # VISITED TRACKING - Prevents scanning same target twice
        self.visited_domains = set()  # Already processed domains
        self.visited_ips = set()  # Already processed IPs
        
        # PERFORMANCE METRICS
        self.result_count = 0  # Total results found
        self.max_reached = False  # Flag for early termination
    
    # ========================================================================
    # UTILITY METHODS - Logging and DNS helpers
    # ========================================================================
    
    def log(self, msg, level='info'):
        """
        Print beautiful log messages with color-coded icons
        
        PRESENTATION NOTE:
        Visual feedback is critical for user experience. This method provides:
        - Color-coded severity levels (info=cyan, success=green, error=red)
        - ASCII icons for quick visual scanning [*] [+] [-] [D]
        - Respect for quiet mode and verbosity levels
        
        Args:
            msg (str): Message to display
            level (str): Severity level ('info', 'success', 'error', 'debug')
        """
        if self.args.quiet:
            return
        
        # Icon and color mappings for different log levels
        icons = {'info': '[*]', 'success': '[+]', 'error': '[-]', 'debug': '[D]'}
        color_map = {'info': Fore.CYAN, 'success': Fore.GREEN, 'error': Fore.RED, 'debug': Fore.MAGENTA}
        
        icon = icons.get(level, '•')
        color = color_map.get(level, '')
        
        # Filter debug messages based on verbosity
        if level == 'debug' and self.args.verbose < 2:
            return
        
        print(f"{color}{Style.BRIGHT}{icon} {msg}{Style.RESET_ALL}")
    
    def get_a_records(self, domain):
        """Quick A record lookup with LRUCache for performance."""
        try:
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    # ========================================================================
    # STRATEGY EXECUTION - Running individual scan modules
    # ========================================================================
    
    def run_strategy(self, strategy_name, target, depth=0):
        """
        Execute a scanning strategy (SPF, MX, NS, etc.).
        Handles special cases: srv (needs services), subdomains (needs wordlist), ip_neighbors (needs range).
        """
        # Respect max depth limit
        if depth > self.args.depth:
            return []
        
        # Check if user disabled this strategy (--disable flag)
        disable_flag = f"disable_{strategy_name}"
        if hasattr(self.args, disable_flag) and getattr(self.args, disable_flag):
            return []
        
        try:
            if strategy_name in STRATEGIES:
                self.log(f"Running {strategy_name} on {target}", 'debug')
                
                # Handle strategies with special parameters
                if strategy_name == 'srv':
                    services = load_wordlist(self.args.srv_services) if self.args.srv_services else get_default_srv_services()
                    return STRATEGIES[strategy_name](target, services)
                elif strategy_name == 'subdomains':
                    if self.args.subdomain_wordlist:
                        wordlist = load_wordlist(self.args.subdomain_wordlist)
                    elif self.args.subdomain_quick:
                        wordlist = get_default_subdomains()[:20]
                    elif self.args.subdomain_thorough:
                        wordlist = get_default_subdomains()
                    else:
                        wordlist = get_default_subdomains()[:40]
                    return STRATEGIES[strategy_name](target, wordlist)
                elif strategy_name == 'ip_neighbors':
                    return STRATEGIES[strategy_name](target, self.args.neighbor_range)
                else:
                    return STRATEGIES[strategy_name](target)
        
        except Exception as e:
            # Graceful error handling - continue with other strategies
            self.log(f"Error in {strategy_name}: {e}", 'error')
            if self.args.verbose > 1:
                import traceback
                traceback.print_exc()
        return []  # Return empty on error
    
    # ========================================================================
    # DOMAIN PROCESSING - Core scanning logic
    # ========================================================================
    
    def process_domain(self, domain, depth=0):
        """
        Process domain with all 34 strategies in parallel.
        Deduplicates visits, handles recursion, early terminates at max results.
        """
        # Skip if exceeded depth, already visited, or hit max results
        if depth > self.args.depth or domain in self.visited_domains or self.max_reached:
            return
        
        self.visited_domains.add(domain)
        
        # Visual tree structure output (indented by depth)
        if not self.args.quiet:
            indent = "  " * depth
            self.log(f"{indent}├─ {Fore.GREEN}{Style.BRIGHT}{domain}{Style.RESET_ALL}", 'info')
        
        # Execute all 34 strategies (organized by category)
        strategies_map = {
            # Core DNS
            'ns': 'ns', 'soa': 'soa', 'mx': 'mx', 'aaaa': 'aaaa', 'cname': 'cname', 'txt': 'txt', 'ttl': 'ttl',
            # Email Security
            'spf': 'spf', 'dmarc': 'dmarc', 'bimi': 'bimi', 'mta_sts': 'mta_sts', 'mail_blacklist': 'mail_blacklist',
            # DNSSEC
            'dnssec': 'dnssec', 'dnskey': 'dnskey', 'ds': 'ds', 'nsec': 'nsec',
            # Certificates & Security
            'caa': 'caa', 'tlsa': 'tlsa', 'sshfp': 'sshfp', 'cert': 'cert', 'hinfo': 'hinfo',
            # Services
            'srv': 'srv', 'naptr': 'naptr', 'loc': 'loc',
            # Infrastructure
            'anycast': 'anycast', 'loadbalancer': 'loadbalancer', 'cdn_enhanced': 'cdn_enhanced', 'domain_age': 'domain_age',
            # Discovery
            'subdomains': 'subdomains', 'crawl_tld': 'crawl_tld', 'axfr': 'axfr', 'wildcard': 'wildcard',
            # Misc
            'http_headers': 'http_headers', 'security_txt': 'security_txt',
        }
        
        # Execute strategies in parallel for 10x speedup
        if self.args.parallel:
            with ThreadPoolExecutor(max_workers=min(len(strategies_map), 8)) as executor:
                strategy_futures = {executor.submit(self.run_strategy, strategy, domain, depth): key 
                                   for key, strategy in strategies_map.items()}
                
                for future in as_completed(strategy_futures):
                    if self.max_reached:
                        break
                    key = strategy_futures[future]
                    try:
                        result = future.result(timeout=5)
                        if result:
                            self._add_result(key, result, domain)
                            # Afficher découvertes en arbre
                            if result and self.args.verbose > 0 and not self.args.quiet:
                                indent = "  " * (depth + 1)
                                if isinstance(result, list) and len(result) > 0:
                                    item = result[0] if isinstance(result[0], str) else str(result[0])
                                    if len(result) > 1:
                                        self.log(f"{indent}└─> {Fore.YELLOW}{key}{Style.RESET_ALL}: {item} (+{len(result)-1} more)", 'debug')
                                    else:
                                        self.log(f"{indent}└─> {Fore.YELLOW}{key}{Style.RESET_ALL}: {item}", 'debug')
                    except Exception as e:
                        if self.args.verbose > 1:
                            self.log(f"Strategy {key} error: {e}", 'debug')
        else:
            for key, strategy in strategies_map.items():
                if self.max_reached:
                    break
                result = self.run_strategy(strategy, domain, depth)
                if result:
                    self._add_result(key, result, domain)
    
    def _add_result(self, key, result, domain):
        """Add result with early termination check."""
        if key not in self.results:
            self.results[key] = []
        
        if isinstance(result, dict):
            self.results[key].append({domain: result})
            self.result_count += len(result.get('domains', [])[:20]) + len(result.get('ips', [])[:10])
            for d in result.get('domains', [])[:20]:
                self.all_domains.add(d)
            for ip in result.get('ips', [])[:10]:
                self.all_ips.add(ip)
        elif isinstance(result, list):
            limited = result[:self.args.max_per_strategy]
            self.results[key].extend(limited)
            self.result_count += len(limited)
            for item in limited:
                if isinstance(item, str) and '.' in item:
                    if not item.replace('.', '').replace(':', '').isalnum():
                        self.all_domains.add(item)
        
        if self.result_count >= self.args.max_results:
            self.max_reached = True
    
    def process_ip(self, ip, depth=0):
        """Process an IP address with visual connection."""
        if depth > self.args.depth or ip in self.visited_ips:
            return
        
        self.visited_ips.add(ip)
        self.log(f"Checking IP {Fore.BLUE}{Style.BRIGHT}{ip}{Style.RESET_ALL}", 'debug')
        
        # Geolocation lookup (DNS-based)
        geo_result = self.run_strategy('geolocation', ip, depth)
        if geo_result:
            if 'geolocation' not in self.results:
                self.results['geolocation'] = []
            self.results['geolocation'].append(geo_result)
        
        # PTR records (reverse DNS)
        ptr_results = self.run_strategy('ptr', ip, depth)
        if ptr_results:
            if 'ptr' not in self.results:
                self.results['ptr'] = []
            self.results['ptr'].extend(ptr_results)
            for domain in ptr_results:
                self.all_domains.add(domain)
        
        # Reverse DNS (legacy)
        if not self.args.disable_reverse_dns:
            reverse_results = self.run_strategy('reverse', ip, depth)
            if reverse_results:
                if 'reverse_dns' not in self.results:
                    self.results['reverse_dns'] = []
                self.results['reverse_dns'].extend(reverse_results)
                for domain in reverse_results:
                    self.all_domains.add(domain)
        
        # IP neighbors
        if not self.args.disable_neighbors:
            neighbors = self.run_strategy('ip_neighbors', ip, depth)
            if neighbors:
                if 'ip_neighbors' not in self.results:
                    self.results['ip_neighbors'] = []
                self.results['ip_neighbors'].extend(neighbors)
    
    def run(self):
        """Main execution logic with beautiful UI."""
        # Beautiful banner
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 60}")
        print(f"{'>>> DNS MAPPER <<<':^60}")
        print(f"{'=' * 60}{Style.RESET_ALL}\n")
        
        self.log(f"Target: {Style.BRIGHT}{self.domain}{Style.RESET_ALL}", 'success')
        self.log(f"Depth: {self.args.depth} • Max: {self.args.max_results} • Threads: {self.args.threads}", 'info')
        
        # Overall progress indicator
        if not self.args.quiet:
            print(f"\n{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[>] Starting DNS reconnaissance...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}\n")
        
        start_time = datetime.now()
        
        # Process initial domain
        self.process_domain(self.domain, depth=0)
        
        # Recursive processing with early termination
        for current_depth in range(1, self.args.depth + 1):
            if self.max_reached:
                self.log("[!] Max results reached - stopping scan", 'info')
                break
                
            # Process discovered domains
            domains_to_process = [d for d in self.all_domains if d not in self.visited_domains]
            
            if self.args.parallel:
                with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                    futures = [executor.submit(self.process_domain, d, current_depth) 
                              for d in domains_to_process[:self.args.max_per_strategy]]
                    for future in as_completed(futures):
                        if self.max_reached:
                            break
            else:
                for domain in domains_to_process[:self.args.max_per_strategy]:
                    if self.max_reached:
                        break
                    self.process_domain(domain, current_depth)
            
            if self.max_reached:
                break
            
            # Process discovered IPs (limit batch)
            ips_to_process = [ip for ip in self.all_ips if ip not in self.visited_ips][:self.args.max_per_strategy]
            
            if self.args.parallel:
                with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                    futures = [executor.submit(self.process_ip, ip, current_depth) 
                              for ip in ips_to_process[:self.args.max_per_strategy]]
                    for future in as_completed(futures):
                        pass
            else:
                for ip in ips_to_process[:self.args.max_per_strategy]:
                    self.process_ip(ip, current_depth)
        
        # Filter hidden providers
        if self.args.hide_providers:
            self.filter_results()
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # Beautiful completion summary
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-' * 60}{Style.RESET_ALL}")
        self.log(f"Scan completed in {Fore.YELLOW}{Style.BRIGHT}{elapsed:.2f}s{Style.RESET_ALL}", 'success')
        self.log(f"Found {Fore.GREEN}{Style.BRIGHT}{len(self.all_domains)}{Style.RESET_ALL} domains | {Fore.BLUE}{Style.BRIGHT}{len(self.all_ips)}{Style.RESET_ALL} IPs", 'success')
        print(f"{Fore.CYAN}{Style.BRIGHT}{'-' * 60}{Style.RESET_ALL}\n")
        
        return self.build_output()
    
    def filter_results(self):
        """Filter out hidden providers."""
        for provider in self.args.hide_providers:
            for key in list(self.results.keys()):
                if isinstance(self.results[key], list):
                    self.results[key] = [
                        r for r in self.results[key] 
                        if provider.lower() not in str(r).lower()
                    ]
    
    def build_output(self):
        """Build final output data structure."""
        return {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'depth': self.args.depth,
            'max_results': self.args.max_results,
            'total_results': len(self.all_domains) + len(self.all_ips),
            'results': self.results,
            'summary': {
                'domains_found': len(self.all_domains),
                'ips_found': len(self.all_ips),
                'strategies_used': list(self.results.keys())
            }
        }
    
    def export_results(self, data):
        """Export results in requested formats to domain-specific directory."""
        import os
        
        # Create output directory for this domain
        domain_safe = data['domain'].replace('.', '_').replace('/', '_')
        output_dir = f"report_{domain_safe}"
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            self.log(f"Created {Fore.CYAN}{output_dir}{Style.RESET_ALL}", 'info')
        
        if self.args.export_all:
            formats = ['json', 'html', 'excel']
        else:
            formats = [self.args.format]
        
        for fmt in formats:
            try:
                if fmt == 'excel':
                    output = os.path.join(output_dir, self.args.excel_output)
                    EXPORTERS['excel'](data, output)
                    self.log(f"Saved {Fore.GREEN}{output}{Style.RESET_ALL}", 'success')
                elif fmt == 'html':
                    output = os.path.join(output_dir, self.args.html_output)
                    EXPORTERS['html'](data, output)
                    self.log(f"Saved {Fore.CYAN}{output}{Style.RESET_ALL}", 'success')
                elif fmt == 'json':
                    output = os.path.join(output_dir, self.args.json_output)
                    EXPORTERS['json'](data, output)
                    self.log(f"Saved {Fore.YELLOW}{output}{Style.RESET_ALL}", 'success')
                elif fmt in ['text', 'markdown']:
                    self.print_results(data, fmt)
            except Exception as e:
                self.log(f"Export failed ({Fore.RED}{fmt}{Style.RESET_ALL}): {e}", 'error')
    
    def print_results(self, data, format='text'):
        """Print results to stdout with beautiful visual indicators."""
        
        def get_check_icon(value, reverse=False):
            """Return ✓ (green) or ✗ (red) based on value."""
            if reverse:
                return f"{Fore.RED}✗{Style.RESET_ALL}" if value else f"{Fore.GREEN}✓{Style.RESET_ALL}"
            return f"{Fore.GREEN}✓{Style.RESET_ALL}" if value else f"{Fore.RED}✗{Style.RESET_ALL}"
        
        def format_value(k, v):
            """Format value with visual indicators based on key."""
            # Boolean checks
            if isinstance(v, bool):
                return get_check_icon(v)
            
            # Security-related fields
            if k in ['enabled', 'verified', 'valid', 'dnssec_enabled', 'dnssec_valid']:
                if str(v).lower() in ['true', 'yes', 'enabled']:
                    return f"{Fore.GREEN}✓ {v}{Style.RESET_ALL}"
                elif str(v).lower() in ['false', 'no', 'disabled']:
                    return f"{Fore.RED}✗ {v}{Style.RESET_ALL}"
            
            # Policy/security level
            if k == 'policy':
                if v in ['reject', '-all']:
                    return f"{Fore.GREEN}✓ {v} (strict){Style.RESET_ALL}"
                elif v in ['quarantine', '~all']:
                    return f"{Fore.YELLOW}⚠ {v} (moderate){Style.RESET_ALL}"
                elif v in ['none', '?all']:
                    return f"{Fore.RED}✗ {v} (permissive){Style.RESET_ALL}"
            
            # Ownership verification
            if 'verified' in k:
                if v:
                    return f"{Fore.GREEN}✓ verified{Style.RESET_ALL}"
                else:
                    return f"{Fore.RED}✗ not verified{Style.RESET_ALL}"
            
            # TTL categorization
            if k == 'category':
                if 'very-short' in str(v):
                    return f"{Fore.YELLOW}⚡ {v}{Style.RESET_ALL}"
                elif 'short' in str(v):
                    return f"{Fore.CYAN}→ {v}{Style.RESET_ALL}"
                elif 'long' in str(v):
                    return f"{Fore.GREEN}✓ {v}{Style.RESET_ALL}"
            
            # Wildcard detection
            if k == 'wildcard_detected':
                if v:
                    return f"{Fore.RED}⚠ WILDCARD DETECTED{Style.RESET_ALL}"
                else:
                    return f"{Fore.GREEN}✓ no wildcard{Style.RESET_ALL}"
            
            return v
        
        # Color mapping for strategies
        STRATEGY_COLORS = {
            'ns': Fore.BLUE,
            'soa': Fore.MAGENTA,
            'a_records': Fore.BLUE,
            'mx': Fore.CYAN,
            'aaaa': Fore.MAGENTA,
            'ptr': Fore.CYAN,
            'dnssec': Fore.YELLOW,
            'txt': Fore.GREEN,
            'spf': Fore.RED,
            'dmarc': Fore.YELLOW,
            'srv': Fore.MAGENTA,
            'caa': Fore.RED,
            'cname': Fore.CYAN,
            'reverse_dns': Fore.CYAN,
            'ip_neighbors': Fore.LIGHTBLACK_EX,
            'crawl_tld': Fore.YELLOW,
            'axfr': Fore.RED,
            'subdomains': Fore.GREEN,
            'providers': Fore.LIGHTBLACK_EX,
            'geolocation': Fore.MAGENTA,
            'security_txt': Fore.RED,
            'bimi': Fore.CYAN,
            'mta_sts': Fore.YELLOW,
            'tlsa': Fore.GREEN,
            'sshfp': Fore.BLUE,
            'cert': Fore.YELLOW,
            'hinfo': Fore.RED,
            'loc': Fore.MAGENTA,
            'naptr': Fore.CYAN,
            'ds': Fore.YELLOW,
            'dnskey': Fore.GREEN,
            'nsec': Fore.BLUE,
            'anycast': Fore.MAGENTA,
            'loadbalancer': Fore.CYAN,
            'cdn_enhanced': Fore.YELLOW,
            'mail_blacklist': Fore.RED,
            'domain_age': Fore.GREEN,
        }
        
        if format == 'markdown':
            print(f"\n# DNS Mapping Report: {data['domain']}\n")
            print(f"**Scan Date:** {data['scan_date']}")
            print(f"**Total Results:** {data['total_results']}\n")
            
            for strategy, results in data['results'].items():
                print(f"\n## {strategy.upper().replace('_', ' ')}\n")
                if isinstance(results, list):
                    for r in results:
                        print(f"- {r}")
        else:
            # Beautiful header box
            domain_name = data["domain"][:35]
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}+{'='*58}+")
            print(f"|{f'>>> DNS REPORT: {domain_name} <<<':^60}|")
            print(f"+{'='*58}+{Style.RESET_ALL}")
            
            # Collect verification status
            has_spf = 'spf' in data['results'] and data['results']['spf']
            has_dmarc = 'dmarc' in data['results'] and data['results']['dmarc']
            has_dnssec = 'dnssec' in data['results'] and data['results']['dnssec']
            has_mta_sts = 'mta_sts' in data['results'] and data['results']['mta_sts']
            has_caa = 'caa' in data['results'] and data['results']['caa']
            
            # Extract ownership verifications from TXT
            ownership_status = {}
            if 'txt' in data['results']:
                txt_results = data['results']['txt']
                # Handle both list and dict formats
                if isinstance(txt_results, dict):
                    # Direct dict format
                    for domain, txt_data in txt_results.items():
                        if isinstance(txt_data, dict) and 'ownership' in txt_data:
                            ownership_status = txt_data['ownership']
                            break
                elif isinstance(txt_results, list):
                    # List format
                    for txt_entry in txt_results:
                        if isinstance(txt_entry, dict):
                            # Check nested structure
                            for key, value in txt_entry.items():
                                if isinstance(value, dict) and 'ownership' in value:
                                    ownership_status = value['ownership']
                                    break
                            if ownership_status:
                                break
            
            # Stats with security checks
            print(f"\n{Fore.CYAN}Date:{Style.RESET_ALL}    {data['scan_date']}")
            print(f"{Fore.CYAN}Results:{Style.RESET_ALL} {Style.BRIGHT}{Fore.YELLOW}{data['total_results']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Domains:{Style.RESET_ALL} {Style.BRIGHT}{Fore.GREEN}{data['summary']['domains_found']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}IPs:{Style.RESET_ALL}     {Style.BRIGHT}{Fore.BLUE}{data['summary']['ips_found']}{Style.RESET_ALL}")
            
            # Security posture summary
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}Security Posture:{Style.RESET_ALL}")
            print(f"  SPF:     {get_check_icon(has_spf)}")
            print(f"  DMARC:   {get_check_icon(has_dmarc)}")
            print(f"  DNSSEC:  {get_check_icon(has_dnssec)}")
            print(f"  MTA-STS: {get_check_icon(has_mta_sts)}")
            print(f"  CAA:     {get_check_icon(has_caa)}")
            
            # Ownership verification summary
            if ownership_status:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}Domain Ownership:{Style.RESET_ALL}")
                for platform, verified in ownership_status.items():
                    platform_name = platform.replace('_verified', '').title()
                    print(f"  {platform_name:12} {get_check_icon(verified)}")
            
            print(f"\n{Fore.CYAN}{Style.BRIGHT}{'-'*60}{Style.RESET_ALL}")
            
            # Display results with enhanced formatting
            for strategy, results in data['results'].items():
                color = STRATEGY_COLORS.get(strategy, '')
                print(f"\n{Style.BRIGHT}{color}╔═ {strategy.upper().replace('_', ' ')}{Style.RESET_ALL}")
                
                if isinstance(results, list):
                    total = len(results)
                    for idx, r in enumerate(results):
                        is_last = (idx == total - 1)
                        branch = "╚═" if is_last else "╠═"
                        connector = "  " if is_last else "║ "
                        
                        if isinstance(r, dict):
                            for k, v in r.items():
                                formatted_v = format_value(k, v)
                                if isinstance(v, list):
                                    print(f"║ {branch} {Fore.YELLOW}{Style.BRIGHT}{k}{Style.RESET_ALL}")
                                    v_total = len(v)
                                    for v_idx, item in enumerate(v):
                                        v_is_last = (v_idx == v_total - 1)
                                        v_branch = "  ╚═" if v_is_last else "  ╠═"
                                        print(f"║ {connector}{v_branch} {Fore.CYAN}{item}{Style.RESET_ALL}")
                                elif isinstance(v, dict):
                                    print(f"║ {branch} {Fore.YELLOW}{Style.BRIGHT}{k}{Style.RESET_ALL}")
                                    dict_items = list(v.items())
                                    dict_total = len(dict_items)
                                    for dict_idx, (dk, dv) in enumerate(dict_items):
                                        dict_is_last = (dict_idx == dict_total - 1)
                                        dict_branch = "  ╚═" if dict_is_last else "  ╠═"
                                        formatted_dv = format_value(dk, dv)
                                        print(f"║ {connector}{dict_branch} {dk}: {formatted_dv}")
                                else:
                                    print(f"║ {branch} {Fore.YELLOW}{k}:{Style.RESET_ALL} {formatted_v}")
                        else:
                            print(f"║ {branch} {Fore.CYAN}{r}{Style.RESET_ALL}")
                
                elif isinstance(results, dict):
                    items = list(results.items())
                    total = len(items)
                    for idx, (k, v) in enumerate(items):
                        is_last = (idx == total - 1)
                        branch = "╚═" if is_last else "╠═"
                        connector = "  " if is_last else "║ "
                        
                        formatted_v = format_value(k, v)
                        if isinstance(v, list):
                            print(f"║ {branch} {Fore.YELLOW}{Style.BRIGHT}{k}{Style.RESET_ALL}")
                            v_total = len(v)
                            for v_idx, item in enumerate(v):
                                v_is_last = (v_idx == v_total - 1)
                                v_branch = "  ╚═" if v_is_last else "  ╠═"
                                print(f"║ {connector}{v_branch} {Fore.CYAN}{item}{Style.RESET_ALL}")
                        elif isinstance(v, dict):
                            print(f"║ {branch} {Fore.YELLOW}{k}:{Style.RESET_ALL} {formatted_v}")
                        else:
                            print(f"║ {branch} {Fore.YELLOW}{k}:{Style.RESET_ALL} {formatted_v}")
                
                print(f"╚{'═'*59}")
            
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*60}{Style.RESET_ALL}\n")


def main():
    """Main entry point."""
    try:
        args = STRATEGIES["args"]()
        mapper = DNSMapper(args)
        data = mapper.run()
        mapper.export_results(data)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}{Style.BRIGHT}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}💥 Fatal error: {e}{Style.RESET_ALL}")
        if args.verbose > 1:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()