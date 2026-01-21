"""Utility functions for wordlist management."""


def load_wordlist(filepath):
    """Load wordlist from file.
    
    Args:
        filepath (str): Path to wordlist file
    
    Returns:
        list: List of words from file
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {filepath}")
        return []
    except Exception as e:
        print(f"[-] Error loading wordlist: {e}")
        return []


def get_default_subdomains():
    """Get default subdomain wordlist.
    
    Returns:
        list: Common subdomain names
    """
    return [
        # Web basics
        'www', 'web', 'site', 'host', 'home', 'portal', 'gateway',
        # Email
        'mail', 'smtp', 'pop', 'pop3', 'imap', 'webmail', 'email', 'mx', 'exchange',
        # File services
        'ftp', 'sftp', 'files', 'upload', 'download', 'share', 'storage', 'backup',
        # Nameservers
        'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'nameserver',
        # Control panels
        'cpanel', 'whm', 'panel', 'control', 'admin', 'administrator', 'manage',
        # Autodiscovery
        'autodiscover', 'autoconfig', 'wpad', 'proxy',
        # Development
        'dev', 'development', 'test', 'testing', 'qa', 'stage', 'staging',
        'demo', 'sandbox', 'beta', 'alpha', 'uat', 'preprod',
        # API/Services
        'api', 'api1', 'api2', 'rest', 'graphql', 'ws', 'websocket',
        # Mobile
        'mobile', 'm', 'app', 'apps', 'ios', 'android',
        # Content
        'blog', 'news', 'forum', 'chat', 'wiki', 'docs', 'documentation',
        # Commerce
        'shop', 'store', 'cart', 'checkout', 'payment', 'pay',
        # Media
        'media', 'cdn', 'static', 'assets', 'img', 'images', 'video', 'stream',
        # Support
        'help', 'support', 'ticket', 'helpdesk', 'faq', 'kb', 'knowledgebase',
        # Security
        'vpn', 'remote', 'secure', 'ssl', 'tls', 'cert', 'auth', 'sso', 'oauth',
        # Version control
        'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'repository',
        # CI/CD
        'jenkins', 'ci', 'cd', 'build', 'deploy', 'pipeline', 'travis',
        # Databases
        'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb',
        'redis', 'elastic', 'elasticsearch', 'cassandra',
        # Monitoring
        'status', 'monitor', 'monitoring', 'stats', 'statistics', 'analytics',
        'metrics', 'logs', 'grafana', 'prometheus', 'kibana',
        # Cloud/Containers
        'cloud', 'aws', 'azure', 'gcp', 'kubernetes', 'k8s', 'docker', 'swarm',
        # Subdomains
        'sub', 'subdomain', 'internal', 'private', 'public', 'external',
        # Regional
        'us', 'eu', 'asia', 'uk', 'de', 'fr', 'es', 'it', 'jp', 'cn', 'au',
        'east', 'west', 'north', 'south', 'central',
        # Misc
        'localhost', 'dashboard', 'console', 'account', 'my', 'user', 'client',
        'partner', 'affiliate', 'reseller', 'corporate', 'enterprise'
    ]


def get_default_srv_services():
    """Get default SRV service list.
    
    Returns:
        list: Common SRV service names
    """
    return [
        '_sip._tcp', '_sip._udp', '_sips._tcp',
        '_xmpp-server._tcp', '_xmpp-client._tcp',
        '_jabber._tcp', '_jabber-client._tcp',
        '_ldap._tcp', '_ldaps._tcp',
        '_kerberos._tcp', '_kerberos._udp',
        '_kpasswd._tcp', '_kpasswd._udp',
        '_caldav._tcp', '_caldavs._tcp',
        '_carddav._tcp', '_carddavs._tcp',
        '_imap._tcp', '_imaps._tcp',
        '_pop3._tcp', '_pop3s._tcp',
        '_smtp._tcp', '_submission._tcp',
        '_http._tcp', '_https._tcp',
        '_ftp._tcp', '_ftps._tcp',
        '_sftp._tcp', '_ssh._tcp',
        '_ntp._udp', '_nfs._tcp',
        '_autodiscover._tcp',
    ]


def save_wordlist(wordlist, filepath):
    """Save wordlist to file.
    
    Args:
        wordlist (list): Words to save
        filepath (str): Output file path
    
    Returns:
        bool: Success status
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for word in wordlist:
                f.write(f"{word}\n")
        return True
    except Exception as e:
        print(f"[-] Error saving wordlist: {e}")
        return False
