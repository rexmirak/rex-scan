"""DNS enumeration: passive lookups, reverse DNS, subdomain bruteforce."""
import dns.resolver
import dns.reversename
import logging
from typing import List, Dict, Set
from pathlib import Path

logger = logging.getLogger("rex_scan.dns")

# DNS-over-HTTPS support
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def dns_over_https_query(domain: str, record_type: str, doh_url: str = "https://cloudflare-dns.com/dns-query") -> List[str]:
    """Perform DNS query using DNS-over-HTTPS."""
    if not HAS_REQUESTS:
        logger.warning("requests library not available for DoH")
        return []
    
    try:
        headers = {"Accept": "application/dns-json"}
        params = {"name": domain, "type": record_type}
        resp = requests.get(doh_url, headers=headers, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("Status") == 0 and "Answer" in data:
            return [answer.get("data", "") for answer in data["Answer"]]
        return []
    except Exception as e:
        logger.debug(f"DoH query failed for {domain} ({record_type}): {e}")
        return []


def passive_dns_lookup(domain: str, use_doh: bool = False, doh_url: str = None) -> Dict:
    """Perform basic DNS lookups (A, AAAA, MX, NS, TXT)."""
    results = {"domain": domain, "records": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    
    for rtype in record_types:
        if use_doh and HAS_REQUESTS:
            # Use DNS-over-HTTPS
            doh_server = doh_url or "https://cloudflare-dns.com/dns-query"
            results["records"][rtype] = dns_over_https_query(domain, rtype, doh_server)
        else:
            # Use traditional DNS
            try:
                answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                results["records"][rtype] = [str(rdata) for rdata in answers]
            except Exception as e:
                logger.debug(f"DNS lookup {rtype} for {domain} failed: {e}")
                results["records"][rtype] = []
    
    return results


def reverse_dns_lookup(ip: str) -> List[str]:
    """Reverse DNS lookup for an IP."""
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, "PTR")
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.debug(f"Reverse DNS for {ip} failed: {e}")
        return []


def subdomain_bruteforce(domain: str, wordlist_path: str = None, limit: int = 100) -> Set[str]:
    """Bruteforce subdomains using wordlist. Returns set of discovered subdomains."""
    found = set()
    
    if not wordlist_path:
        # minimal default wordlist
        subs = ["www", "mail", "ftp", "admin", "vpn", "api", "dev", "test", "staging"]
    else:
        try:
            with open(wordlist_path, "r") as f:
                subs = [line.strip() for line in f if line.strip()][:limit]
        except Exception as e:
            logger.warning(f"Failed to read wordlist {wordlist_path}: {e}")
            return found
    
    for sub in subs:
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", raise_on_no_answer=False)
            if answers:
                found.add(fqdn)
                logger.info(f"Found subdomain: {fqdn}")
        except Exception:
            pass
    
    return found


def enumerate_dns(target: str, wordlist_path: str = None, dns_server: str = None, use_doh: bool = False) -> Dict:
    """Full DNS enumeration wrapper."""
    results = {
        "passive": passive_dns_lookup(target, use_doh=use_doh),
        "reverse": reverse_dns_lookup(target),
        "subdomains": list(subdomain_bruteforce(target, wordlist_path))
    }
    return results
