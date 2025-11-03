"""Central configuration for REX SCAN

All configurable timeouts, limits, and defaults in one place.
"""

# Timeout configurations (seconds)
TIMEOUTS = {
    "global": 30,
    "nmap": 3600,  # 1 hour for nmap scans
    "http": 10,
    "https": 10,
    "ftp": 5,
    "ssh": 10,
    "smb": 10,
    "dns": 5,
    "screenshot": 30,
    "cve_api": 15
}

# Rate limiting
RATE_LIMITS = {
    "default": 10,  # requests per second
    "http_requests": 5,
    "cve_api": 0.5,  # API calls per second (respect NVD limits)
    "directory_enum": 20,
    "credential_checks": 2
}

# Progress tracking
PROGRESS = {
    "show_bars": True,
    "update_interval": 0.1,
    "bar_format": "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
}

# Concurrent scanning
CONCURRENCY = {
    "max_workers": 10,
    "max_targets": 50,
    "service_threads": 5,
    "http_pool_size": 10
}

# Error recovery
ERROR_RECOVERY = {
    "continue_on_error": False,
    "max_retries": 3,
    "retry_delay": 2
}

# Resume capability
RESUME = {
    "checkpoint_interval": 60,  # seconds
    "state_file": ".rex_scan_state.json"
}

# Wordlist management
WORDLISTS = {
    "seclists_repo": "https://github.com/danielmiessler/SecLists.git",
    "wordlist_dir": "~/.rex_scan/wordlists",
    "default_dns": "subdomains-top1million-5000.txt",
    "default_dir": "directory-list-2.3-medium.txt"
}

# Screenshot settings
SCREENSHOTS = {
    "enabled": False,
    "viewport_width": 1920,
    "viewport_height": 1080,
    "full_page": True,
    "format": "png"
}

# DNS settings
DNS = {
    "use_doh": False,  # DNS over HTTPS
    "doh_provider": "https://cloudflare-dns.com/dns-query",
    "custom_server": None,
    "timeout": 5
}
