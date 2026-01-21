# Wordlists

This directory contains wordlists for DNS reconnaissance.

## Files

### `subdomains-common.txt`
Common subdomain names (~200+ entries). Used by default in normal mode.

### `subdomains-extended.txt`
Extended subdomain list (~8000+ entries). Use with `--subdomain-thorough` or specify with `--subdomain-wordlist`.

### `srv-services.txt`
Common SRV service records to query. Used by default or specify custom with `--srv-services`.

## Usage

### Use default wordlists
```bash
python main.py example.com
```

### Use custom subdomain wordlist
```bash
python main.py example.com --subdomain-wordlist wordlists/subdomains-extended.txt
```

### Use custom SRV services
```bash
python main.py example.com --srv-services wordlists/srv-services.txt
```

### Quick mode (top 20 subdomains)
```bash
python main.py example.com --subdomain-quick
```

### Thorough mode (all default subdomains)
```bash
python main.py example.com --subdomain-thorough
```
