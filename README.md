# DNS Mapper 🔍

**Comprehensive DNS reconnaissance tool** - 34 scanning modules, 3,664 lines of code

---

## ⚡ Quick Start

```bash
# Install
pip install -r requirements.txt

# Basic scan
python main.py example.com

# Fast mode
python main.py example.com --fast

# HTML report
python main.py example.com -o report.html

# Security audit
python main.py example.com --enable-only spf,dmarc,dnssec,mail_blacklist
```

---

## 🎯 34 Modules

**DNS Records**: A, AAAA, NS, SOA, MX, CNAME, TXT, PTR, SRV, CAA, TTL

**Security**: SPF, DMARC, DNSSEC, DNSKEY, DS, NSEC, TLSA, MTA-STS, BIMI, CAA

**Advanced**: SSHFP, CERT, HINFO, LOC, NAPTR

**Analysis**: Anycast detection, Load balancer, CDN detection, Mail blacklist (9 DNSBLs), Domain age, Geolocation

**Discovery**: Subdomains, IP neighbors, HTTP headers, Wildcard detection

---

## 📖 Usage

```bash
# Strategy selection
--enable-only A,MX,NS          # Run only these
--disable srv,axfr              # Skip these

# Modes
--fast                          # Quick (depth=1, max=50)
--thorough                      # Deep (depth=3, max=500, 50 threads)

# Performance
--depth 4 --threads 60 --max-results 200

# Output
-o report.html                  # HTML report
--export-all                    # JSON + HTML + Excel
```

---

## ✨ Features

✓ **Visual Indicators** - ✓/✗ for security status  
✓ **Security Dashboard** - SPF/DMARC/DNSSEC/MTA-STS/CAA overview  
✓ **Mail Blacklist** - 9 DNSBLs (Spamhaus, SpamCop, SORBS)  
✓ **DNSSEC Analysis** - Full key chain (KSK/ZSK)  
✓ **CDN Detection** - 15+ providers (Cloudflare, Akamai, Fastly)  
✓ **Geolocation** - Team Cymru ASN mapping  
✓ **Parallel Execution** - Up to 60 threads  

---

## 📊 Example Output

```
Security Posture:
  SPF:     ✓
  DMARC:   ✓
  DNSSEC:  ✗
  MTA-STS: ✓
  CAA:     ✓

Domain Ownership:
  Google       ✓
  Microsoft    ✓

╔═ MAIL BLACKLIST
║ ╚═ example.com: EXCELLENT (2/2 clean)
╚═══════════════════════════════════════

╔═ ANYCAST
║ ╚═ 2 of 2 IPs show anycast (Cloudflare)
╚═══════════════════════════════════════
```

---

## 🛠️ Requirements

Python 3.8+ • dnspython • colorama • openpyxl • requests • tqdm

---

**Project**: Python B1 2025-2026 | **Deadline**: Jan 21, 2026
# dns_recon_python
