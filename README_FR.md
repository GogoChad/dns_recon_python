# DNS Mapper - Projet Python B1 2025-2026

Outil de reconnaissance DNS pour le mapping d'environnements réseau.

## 🎯 Objectif

Cartographier les infrastructures DNS en découvrant automatiquement les domaines, sous-domaines, serveurs de noms, et adresses IP associés à une cible.

## ✨ Fonctionnalités

### Stratégies DNS implémentées (15+)
- **NS**: Serveurs de noms autoritaires
- **SOA**: Start of Authority (informations de zone)
- **MX**: Serveurs mail exchange
- **AAAA**: Adresses IPv6
- **PTR**: Reverse DNS (résolution inverse)
- **TXT**: Enregistrements texte (métadonnées)
- **SPF**: Sender Policy Framework (anti-spam)
- **DMARC**: Domain-based Message Authentication
- **CAA**: Certification Authority Authorization
- **DNSSEC**: Validation de sécurité DNS
- **SRV**: Services discovery
- **CNAME**: Alias de domaines
- **AXFR**: Zone transfer (si autorisé)
- **Subdomain enumeration**: Bruteforce de sous-domaines
- **IP neighbors**: Scan des IPs voisines
- **TLD crawling**: Remontée jusqu'aux TLDs

### Fonctionnalités avancées
- ⚡ **Exécution parallèle**: 30 threads par défaut pour des scans ultra-rapides
- 🔄 **Découverte récursive**: Suit automatiquement les domaines et IPs découverts
- 📊 **Exports multiples**: JSON, HTML, Excel, Graphviz (PNG/SVG/DOT)
- 🎨 **Interface colorée**: Sortie CLI avec codes couleurs et ASCII art
- 📝 **Wordlists personnalisables**: Support de listes de sous-domaines custom
- 🚫 **Filtrage providers**: Masquage des CDN/cloud providers (Cloudflare, AWS, etc.)
- 📈 **Rapports détaillés**: HTML interactif avec animations et recherche

## 📦 Installation

### Prérequis
```bash
# Python 3.8+
python --version

# Graphviz (pour les exports graphiques)
sudo apt install graphviz  # Debian/Ubuntu
```

### Installation des dépendances
```bash
pip install -r requirements.txt
```

**Dépendances**:
- `dnspython>=2.4.0` - Requêtes DNS
- `graphviz>=0.20.1` - Génération de graphes
- `openpyxl>=3.1.0` - Export Excel
- `tqdm>=4.67.0` - Barres de progression
- `colorama>=0.4.6` - Couleurs terminal
- `requests>=2.31.0` - Requêtes HTTP

## 🚀 Utilisation

### Scan basique
```bash
python main.py example.com
```

### Scan approfondi avec récursion
```bash
python main.py example.com --depth 3 --max-results 200
```

### Export tous formats
```bash
python main.py google.com --export-all
```

### Scan silencieux
```bash
python main.py domain.com --quiet --format json
```

### Avec wordlist personnalisée
```bash
python main.py target.com --subdomain-wordlist wordlists/subdomains-extended.txt
```

### Modes de verbosité
```bash
python main.py example.com -v        # Verbose
python main.py example.com -vv       # Debug complet
python main.py example.com --quiet   # Silencieux
```

## 📋 Options principales

### Sortie
- `--format {text,json,html,excel,graphviz}` - Format d'export
- `--export-all` - Exporter tous les formats
- `--graph-format {png,svg,pdf,dot}` - Format du graphe
- `-o OUTPUT` - Répertoire de sortie

### Reconnaissance
- `-d DEPTH, --depth DEPTH` - Profondeur de récursion (défaut: 2)
- `--max-results N` - Limite de résultats (défaut: 1000)
- `--threads N` - Nombre de threads (défaut: 30)
- `--timeout N` - Timeout DNS en secondes (défaut: 2)

### Stratégies
- `--disable-txt` - Désactiver scan TXT
- `--disable-spf` - Désactiver scan SPF
- `--disable-dmarc` - Désactiver scan DMARC
- `--disable-srv` - Désactiver scan SRV
- `--disable-subdomain-enum` - Désactiver énumération sous-domaines

### Performance
- `--no-parallel` - Désactiver exécution parallèle
- `--cache` - Activer cache DNS
- `--neighbor-range N` - Plage IPs voisines (défaut: 2)

## 📊 Formats d'export

### JSON
Structure complète avec métadonnées, domaines, IPs et résultats par stratégie.

### HTML
Rapport interactif moderne avec:
- Gradient animé violet/rose
- Cartes statistiques avec effets glassmorphism
- Recherche et filtrage en temps réel
- Design responsive mobile-friendly

### Excel
Classeur multi-feuilles avec:
- Feuille récapitulative
- Une feuille par stratégie DNS
- Mise en forme avec couleurs

### Graphviz
Graphe visuel des relations:
- Format PNG, SVG, PDF ou DOT
- Couleurs par type de stratégie
- Clusters par domaines
- Métadonnées et légende

## 🎯 Exemples

### Scan complet d'un domaine
```bash
python main.py example.com --depth 2 --max-results 100 --export-all
```

Génère dans `report_example_com/`:
- `dns_map.json` - Données structurées
- `dns_map.html` - Rapport interactif
- `dns_map.xlsx` - Tableau Excel
- `dns_map.svg` - Graphe vectoriel

### Recherche de subdomains intensive
```bash
python main.py target.com \
    --subdomain-thorough \
    --depth 3 \
    --threads 50 \
    --max-results 500
```

### Scan rapide pour OSINT
```bash
python main.py company.com \
    --subdomain-quick \
    --depth 1 \
    --classify-providers \
    --format json
```

## 🏗️ Architecture

```
dns_project/
├── main.py                 # Point d'entrée principal
├── packages/
│   ├── __init__.py        # Registre STRATEGIES & EXPORTERS
│   ├── argparse_args.py   # Configuration CLI
│   ├── scan_*.py          # Stratégies DNS (15 modules)
│   ├── export_*.py        # Exporteurs (4 formats)
│   └── wordlist_utils.py  # Gestion wordlists
├── wordlists/             # Listes de sous-domaines/services
├── requirements.txt       # Dépendances Python
└── README.md             # Documentation
```

## 🔬 Stratégies DNS détaillées

| Stratégie | Description | Sortie |
|-----------|-------------|--------|
| `ns` | Serveurs de noms | Liste de nameservers |
| `soa` | Start of Authority | mname, rname, serial |
| `mx` | Mail exchange | Serveurs mail |
| `aaaa` | IPv6 | Adresses IPv6 |
| `ptr` | Reverse DNS | Domaines depuis IPs |
| `txt` | Records TXT | Métadonnées, SPF, DKIM |
| `spf` | Sender Policy Framework | Politique email |
| `dmarc` | DMARC policy | Configuration anti-spam |
| `caa` | Certificate Authority | Autorités de certification |
| `dnssec` | DNSSEC | DNSKEY, DS, RRSIG |
| `srv` | Services | _ldap, _xmpp, etc. |
| `cname` | Canonical names | Alias |
| `axfr` | Zone transfer | Tentative de transfer |
| `subdomains` | Énumération | Brute-force sous-domaines |
| `ip_neighbors` | IPs voisines | Scan plage IP |

## 🎨 Interface CLI

```
============================================================
                     >>> DNS MAPPER <<<                     
============================================================

[+] Target: example.com
[*] Depth: 2 • Max: 100 • Threads: 30

------------------------------------------------------------
[>] Starting DNS reconnaissance...
------------------------------------------------------------

[*] Scanning example.com
[*] Scanning www.example.com
[*] Scanning mail.example.com

------------------------------------------------------------
[+] Scan completed in 3.42s
[+] Found 45 domains | 23 IPs
------------------------------------------------------------
```

## ⚡ Optimisations performance

- **Cache DNS**: LRUCache pour éviter requêtes dupliquées
- **Timeouts agressifs**: 1-2s pour fast-fail
- **Parallélisation**: ThreadPoolExecutor (30 threads par défaut)
- **Early termination**: Arrêt dès max_results atteint
- **Batch processing**: Limitation par stratégie

## 🔒 Considérations de sécurité

**Usage légal uniquement**: Cet outil est conçu pour:
- Audit de sécurité autorisé
- Red team avec autorisation
- OSINT sur domaines publics
- Recherche académique

⚠️ **Ne pas utiliser sur des cibles sans autorisation explicite.**

## 📚 Ressources

- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) - DNS Protocol
- [dnspython docs](https://dnspython.readthedocs.io/)
- [Graphviz gallery](https://graphviz.org/gallery/)
- [SecLists DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

## 👥 Auteur

Projet réalisé dans le cadre du cours Python B1 2025-2026.

## 📝 Licence

Projet académique - Usage éducatif uniquement.
