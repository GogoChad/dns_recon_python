from .argparse_args import argparse_args
from .classify_providers import classify_providers
from .crawl_to_tld import crawl_to_tld
from .neighbors_ip_scan import neighbors_ip_scan
from .reverse_dns import reverse_dns
from .scan_axfr import scan_axfr
from .scan_caa import scan_caa
from .scan_cname import scan_cname
from .scan_dmarc import scan_dmarc
from .scan_ns import scan_ns
from .scan_reverse_ipv6 import scan_reverse_ipv6
from .scan_soa import scan_soa
from .scan_spf import scan_spf
from .scan_mx import scan_mx
from .scan_aaaa import scan_aaaa
from .scan_ptr import scan_ptr
from .scan_dnssec import scan_dnssec
from .srv_scan import srv_scan
from .subdomains_enumeration import subdomains_enumeration
from .txt_parse import txt_parse
from .export_excel import export_excel
from .export_html import export_html
from .export_json import export_json
from .wordlist_utils import load_wordlist, get_default_subdomains, get_default_srv_services
from .scan_http_headers import scan_http_headers
from .scan_wildcard import scan_wildcard
from .scan_ttl import scan_ttl
from .scan_common_ports import scan_common_ports
from .scan_security_txt import scan_security_txt
from .scan_bimi import scan_bimi
from .scan_mta_sts import scan_mta_sts
from .scan_geolocation import scan_geolocation
from .scan_tlsa import scan_tlsa
from .scan_sshfp import scan_sshfp
from .scan_cert import scan_cert
from .scan_hinfo import scan_hinfo
from .scan_loc import scan_loc
from .scan_naptr import scan_naptr
from .scan_ds import scan_ds
from .scan_dnskey import scan_dnskey
from .scan_nsec import scan_nsec
from .scan_anycast import scan_anycast
from .scan_loadbalancer import scan_loadbalancer
from .scan_cdn_enhanced import scan_cdn_enhanced
from .scan_mail_blacklist import scan_mail_blacklist
from .scan_domain_age import scan_domain_age

STRATEGIES = {
    "args": argparse_args,
    "ns": scan_ns,
    "soa": scan_soa,
    "mx": scan_mx,
    "aaaa": scan_aaaa,
    "ptr": scan_ptr,
    "dnssec": scan_dnssec,
    "srv": srv_scan,
    "spf": scan_spf,
    "dmarc": scan_dmarc,
    "txt": txt_parse,
    "caa": scan_caa,
    "cname": scan_cname,
    "reverse": reverse_dns,
    "reverse_ipv6": scan_reverse_ipv6,
    "ip_neighbors": neighbors_ip_scan,
    "crawl_tld": crawl_to_tld,
    "http_headers": scan_http_headers,
    "wildcard": scan_wildcard,
    "ttl": scan_ttl,
    "security_txt": scan_security_txt,
    "bimi": scan_bimi,
    "mta_sts": scan_mta_sts,
    "geolocation": scan_geolocation,
    "tlsa": scan_tlsa,
    "sshfp": scan_sshfp,
    "cert": scan_cert,
    "hinfo": scan_hinfo,
    "loc": scan_loc,
    "naptr": scan_naptr,
    "ds": scan_ds,
    "dnskey": scan_dnskey,
    "nsec": scan_nsec,
    "anycast": scan_anycast,
    "loadbalancer": scan_loadbalancer,
    "cdn_enhanced": scan_cdn_enhanced,
    "mail_blacklist": scan_mail_blacklist,
    "domain_age": scan_domain_age,
}

EXPORTERS = {
    "excel": export_excel,
    "html": export_html,
    "json": export_json,
}

__all__ = ["STRATEGIES", "EXPORTERS"]
