"""DNS enumeration: passive lookups, reverse DNS, subdomain bruteforce.

Supports both external tools (dnsenum, dig) and Python fallback (dnspython).
"""
import dns.resolver
import dns.reversename
import subprocess
import shutil
import logging
import time
from typing import List, Dict, Set, Optional
from pathlib import Path
from rex_scan.command_tracker import get_tracker

logger = logging.getLogger("rex_scan.dns")

# DNS-over-HTTPS support
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def has_dnsenum() -> bool:
    """Check if dnsenum is installed."""
    return shutil.which("dnsenum") is not None


def has_dig() -> bool:
    """Check if dig is installed."""
    return shutil.which("dig") is not None


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


def dnsenum_scan(domain: str, wordlist: Optional[str] = None, timeout: int = 300) -> Dict:
    """
    Run external dnsenum tool for comprehensive DNS enumeration.
    
    Returns dict with subdomains, nameservers, mail servers, zone transfer results.
    """
    if not has_dnsenum():
        raise RuntimeError("dnsenum not installed")
    
    tracker = get_tracker()
    cmd = ["dnsenum", "--noreverse"]
    
    if wordlist:
        # Convert wordlist to string if it's a Path object
        wordlist_str = str(wordlist) if not isinstance(wordlist, str) else wordlist
        cmd.extend(["-f", wordlist_str])
    
    cmd.append(domain)
    cmd_str = " ".join(cmd)
    
    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        duration = time.time() - start_time
        
        # Track command
        tracker.track(
            tool="dnsenum",
            command=cmd_str,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration=duration,
            context=f"DNS enumeration for {domain}"
        )
        
        # Parse dnsenum output
        results = {
            "tool": "dnsenum",
            "domain": domain,
            "subdomains": [],
            "nameservers": [],
            "mail_servers": [],
            "raw_output": proc.stdout
        }
        
        current_section = None
        for line in proc.stdout.splitlines():
            line = line.strip()
            
            if "Brute forcing with" in line:
                current_section = "subdomains"
            elif "Name Servers:" in line:
                current_section = "nameservers"
            elif "Mail Servers:" in line:
                current_section = "mail_servers"
            elif not line or line.startswith("----"):
                continue
            elif current_section == "subdomains" and domain in line:
                # Extract subdomain from lines like: "www.example.com    5    IN    A    192.168.1.1"
                parts = line.split()
                if parts and domain in parts[0]:
                    results["subdomains"].append(parts[0])
            elif current_section == "nameservers" and "IN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    results["nameservers"].append(parts[4])
            elif current_section == "mail_servers" and "IN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    results["mail_servers"].append(parts[4])
        
        return results
        
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        logger.warning(f"dnsenum timed out after {timeout}s")
        tracker.track(
            tool="dnsenum",
            command=cmd_str,
            stdout="",
            stderr=f"Timeout after {timeout}s",
            exit_code=-1,
            duration=duration,
            context=f"DNS enumeration for {domain} (TIMEOUT)"
        )
        return {"error": "timeout", "tool": "dnsenum"}
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"dnsenum failed: {e}")
        tracker.track(
            tool="dnsenum",
            command=cmd_str,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=duration,
            context=f"DNS enumeration for {domain} (ERROR)"
        )
        return {"error": str(e), "tool": "dnsenum"}


def enumerate_dns(target: str, wordlist_path: str = None, dns_server: str = None, 
                  use_doh: bool = False, prefer_external: bool = True) -> Dict:
    """
    Full DNS enumeration wrapper.
    
    Args:
        target: Domain or IP to enumerate
        wordlist_path: Path to subdomain wordlist
        dns_server: Custom DNS server to use
        use_doh: Use DNS-over-HTTPS
        prefer_external: Try external tools (dnsenum) before falling back to Python
    
    Returns:
        Dict with DNS enumeration results
    """
    results = {
        "method": "unknown",
        "passive": {},
        "reverse": [],
        "subdomains": []
    }
    
    # Try external dnsenum first if available and preferred
    if prefer_external and has_dnsenum() and "." in target and not target.replace(".", "").isdigit():
        logger.info(f"Using dnsenum for DNS enumeration: {target}")
        dnsenum_results = dnsenum_scan(target, wordlist_path)
        
        if "error" not in dnsenum_results:
            results["method"] = "dnsenum"
            results["subdomains"] = dnsenum_results.get("subdomains", [])
            results["nameservers"] = dnsenum_results.get("nameservers", [])
            results["mail_servers"] = dnsenum_results.get("mail_servers", [])
            results["raw_output"] = dnsenum_results.get("raw_output", "")
            # Still do passive lookups with dnspython
            results["passive"] = passive_dns_lookup(target, use_doh=use_doh)
            return results
    
    # Fallback to dnspython
    logger.info(f"Using dnspython for DNS enumeration: {target}")
    results["method"] = "dnspython"
    results["passive"] = passive_dns_lookup(target, use_doh=use_doh)
    results["reverse"] = reverse_dns_lookup(target)
    results["subdomains"] = list(subdomain_bruteforce(target, wordlist_path))
    
    return results
