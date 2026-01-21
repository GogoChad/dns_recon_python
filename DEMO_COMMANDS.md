# 🎤 Presentation Demo Commands - MEMORIZE THESE!

## 📋 Copy-Paste Ready Commands for Live Demo

---

## DEMO 1: Basic Fast Scan (30 seconds)
```bash
python main.py cloudflare.com --fast
```
**SAY**: "This is a fast reconnaissance scan of Cloudflare's domain using all 34 modules in parallel with depth 1."

**EXPECTED OUTPUT**:
- Security Posture dashboard (SPF ✓, DMARC ✓, DNSSEC ✓)
- Nameservers (Cloudflare NS)
- Mail servers with priorities
- Anycast detection
- CDN identification
- Total time: ~10-15 seconds

---

## DEMO 2: Security Audit (45 seconds)
```bash
python main.py google.com --enable-only spf,dmarc,dnssec,caa,mail_blacklist,mta_sts
```
**SAY**: "This focuses only on security features - email authentication, DNSSEC, certificate authorization, and mail reputation across 9 blacklists."

**EXPECTED OUTPUT**:
- SPF mechanisms (include:_spf.google.com)
- DMARC policy (p=reject or p=quarantine)
- DNSSEC keys (KSK/ZSK)
- CAA records
- Mail blacklist: EXCELLENT reputation
- MTA-STS policy

---

## DEMO 3: Deep Discovery with Export (1 minute)
```bash
python main.py example.com --thorough --depth 3 -o report.html
```
**SAY**: "This is a thorough deep scan with 3 levels of recursion, discovering subdomains, IP neighbors, and exporting to HTML report."

**EXPECTED OUTPUT**:
- Multiple depth levels shown
- Subdomain enumeration
- IP neighbors discovered
- HTML report created in report_example_com/ folder
- Total domains/IPs discovered

**THEN SHOW**: Open `report_example_com/report.html` in browser

---

## DEMO 4: Parallel Performance Demo (for speed questions)
```bash
python main.py microsoft.com --threads 60 --depth 2 --max-results 100
```
**SAY**: "Running 60 parallel threads with depth 2 - this demonstrates our optimization with ThreadPoolExecutor."

**EXPECTED OUTPUT**:
- Very fast completion (~15-20 seconds)
- Shows parallel execution efficiency
- Hits max results limit quickly

---

## DEMO 5: Subdomain Discovery (30 seconds)
```bash
python main.py tesla.com --enable-only subdomains --subdomain-thorough
```
**SAY**: "This uses wordlist-based subdomain enumeration to discover hidden infrastructure like mail.tesla.com, www.tesla.com, etc."

**EXPECTED OUTPUT**:
- List of discovered subdomains
- Shows tree structure
- Common names: www, mail, ftp, admin, dev, api

---

## 🎯 BACKUP COMMANDS (if demos fail)

### If DNS timeout issues:
```bash
python main.py cloudflare.com --timeout 5 --fast
```

### If network is slow:
```bash
python main.py example.com --threads 5 --depth 1
```

### Show help (if asked about options):
```bash
python main.py --help
```

---

## 💡 QUICK EXPLANATIONS TO MEMORIZE

### When showing **--fast** flag:
"Fast mode uses depth 1, max 50 results, and skips slow scans like AXFR and neighbors. Perfect for quick reconnaissance."

### When showing **--enable-only**:
"This comma-separated filter runs only specific strategies. Great for focused security audits without noise."

### When showing **--thorough**:
"Thorough mode enables all 34 strategies, depth 3, max 500 results, and 50 threads. Full infrastructure mapping."

### When showing **--threads 60**:
"ThreadPoolExecutor manages 60 worker threads executing DNS queries in parallel. This gives us 10x speedup over sequential execution."

### When showing **-o report.html**:
"Auto-detects format from extension. Supports .json, .html, .xlsx. Creates organized report in domain-specific directory."

---

## 🚨 EMERGENCY CHEAT SHEET

| Command Part | What It Does |
|--------------|--------------|
| `--fast` | Quick scan (depth=1, max=50) |
| `--thorough` | Deep scan (depth=3, max=500, 50 threads) |
| `--enable-only X,Y,Z` | Run ONLY these strategies |
| `--disable X,Y,Z` | Skip these strategies |
| `--depth 3` | Recursive depth (0-5) |
| `--threads 60` | Parallel workers |
| `-o file.html` | Export to HTML |
| `--export-all` | Export JSON+HTML+Excel |
| `--quiet` | Suppress output |
| `--verbose` | Show debug info |

---

## 📊 STATS TO MENTION DURING DEMOS

1. **After Demo 1**: "Completed in 15 seconds scanning 34 modules in parallel"
2. **After Demo 2**: "Checked 9 major DNSBLs: Spamhaus, SpamCop, SORBS, Barracuda"
3. **After Demo 3**: "Discovered X domains and Y IPs across 3 recursion levels"
4. **After Demo 4**: "60 threads = 10x faster than sequential execution"
5. **After Demo 5**: "Tested 100 common subdomain names from built-in wordlist"

---

## 🎬 DEMO FLOW (Total: 5 minutes)

**Minute 1**: Demo 1 (fast scan) → explain parallel execution  
**Minute 2**: Demo 2 (security audit) → explain SPF/DMARC/DNSSEC  
**Minute 3**: Demo 3 (thorough + export) → show HTML report  
**Minute 4**: Questions about specific modules → show code  
**Minute 5**: Performance demo → explain threading optimization  

---

## 🔥 PRO TIPS

1. **Run cloudflare.com** - Always works, great results, fast
2. **Have HTML report pre-generated** - In case live demo fails
3. **Keep terminal font size BIG** - Audience can read output
4. **Terminal colors ON** - Visual indicators stand out
5. **Run demos BEFORE presentation** - Verify network works

---

## 🎯 ONE-LINER FOR EACH CONCEPT

**Parallel Execution**: "ThreadPoolExecutor runs 60 DNS queries simultaneously instead of one-by-one"

**Security Dashboard**: "Visual indicators show SPF, DMARC, DNSSEC, MTA-STS, and CAA status at a glance"

**Recursive Discovery**: "Each scan discovers new domains and IPs, which are automatically scanned up to depth 3"

**Smart Caching**: "LRUCache prevents redundant queries for the same domain, boosting performance 30-50%"

**Graceful Errors**: "If one module fails, others continue - the scan never crashes completely"

---

## 🏆 FINAL COMMAND (Grand Finale)

```bash
python main.py yourdomain.com --thorough --export-all --threads 60
```

**SAY**: "This is the full power of DNS Mapper - all 34 modules, maximum parallelization, all export formats, complete reconnaissance in under 30 seconds."

---

**PRINT THIS PAGE AND KEEP IT VISIBLE DURING PRESENTATION! 📄**
