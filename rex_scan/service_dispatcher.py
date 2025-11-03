"""Dispatch per-service enumeration based on discovered services.

This module contains light-weight dispatch logic. For each discovered open service,
it will call the appropriate enumeration helper. The helpers are conservative and
require consent for aggressive checks.
"""
from typing import Dict, Any
from .creds import check_ftp_anonymous, check_http_basic
from .exploitdb import searchsploit_from_nmap, has_searchsploit


PRIORITY = ["http", "https", "smb", "ssh", "ftp", "smtp", "dns"]


def service_priority(name: str) -> int:
    try:
        return PRIORITY.index(name)
    except ValueError:
        return len(PRIORITY)


def dispatch_services(
    parsed: Dict[str, Any], 
    xml_path: str, 
    creds_enabled: bool = True, 
    run_exploitdb: bool = True,
    run_smb: bool = True,
    run_ssh: bool = True,
    rate_limiter = None,
    timeout: Dict = None,
    continue_on_error: bool = False
) -> Dict:
    """
    Dispatch enumeration tasks for discovered services.
    
    Args:
        parsed: Parsed nmap results
        xml_path: Path to nmap XML file
        creds_enabled: Run credential checks
        run_exploitdb: Run searchsploit
        run_smb: Run SMB enumeration
        run_ssh: Run SSH enumeration
        rate_limiter: Rate limiter instance
        timeout: Timeout configuration dict
        continue_on_error: Continue even if modules fail
    
    Returns:
        Dict with exploits, creds, smb, ssh results
    """
    out = {
        "exploits": [], 
        "creds": [],
        "smb_enumeration": {},
        "ssh_enumeration": {}
    }
    
    # Set default timeouts
    if timeout is None:
        timeout = {
            "http": 10,
            "https": 10,
            "ftp": 5,
            "ssh": 10,
            "smb": 10
        }

    # Run searchsploit against the nmap xml if available and enabled
    if run_exploitdb and has_searchsploit():
        try:
            out["exploits"] = searchsploit_from_nmap(xml_path)
        except Exception as e:
            out["exploits"] = [f"Error running searchsploit: {e}"]
            if not continue_on_error:
                raise

    # Flatten services and sort by priority
    svc_list = []
    for h in parsed.get("hosts", []):
        addr = h.get("addresses", [])
        ip = addr[0]["addr"] if addr else None
        for p in h.get("ports", []):
            svc = p.get("service")
            name = svc.get("name") if svc else None
            port_num = p.get("portid", p.get("port"))
            svc_list.append({
                "host": ip, 
                "port": int(port_num), 
                "name": name, 
                "state": p.get("state"),
                "service": svc
            })

    svc_list.sort(key=lambda s: service_priority(s.get("name") or ""))

    # Perform per-service enumeration
    for s in svc_list:
        name = (s.get("name") or "").lower()
        host = s["host"]
        port = s["port"]
        
        if s["state"] != "open":
            continue
        
        # Rate limiting
        if rate_limiter:
            rate_limiter.wait()
        
        # FTP enumeration
        if name.startswith("ftp"):
            if creds_enabled:
                try:
                    out["creds"].append(check_ftp_anonymous(host, port, timeout=timeout.get('ftp', 5)))
                except Exception as e:
                    if not continue_on_error:
                        raise
        
        # HTTP enumeration
        if name in ("http", "https", "http-alt", "http-proxy") or port in (80, 443, 8080, 8000):
            if creds_enabled:
                try:
                    out["creds"].extend(check_http_basic(host, port, timeout=timeout.get('http', 10)))
                except Exception as e:
                    if not continue_on_error:
                        raise
        
        # SMB enumeration
        if run_smb and name in ("microsoft-ds", "netbios-ssn") or port in (139, 445):
            try:
                from .smb_enum import enumerate_smb
                smb_key = f"{host}:{port}"
                out["smb_enumeration"][smb_key] = enumerate_smb(host, port, timeout=timeout.get('smb', 10))
            except ImportError:
                pass
            except Exception as e:
                out["smb_enumeration"][f"{host}:{port}"] = {"error": str(e)}
                if not continue_on_error:
                    raise
        
        # SSH enumeration
        if run_ssh and name == "ssh" or port == 22:
            try:
                from .ssh_enum import enumerate_ssh
                ssh_key = f"{host}:{port}"
                out["ssh_enumeration"][ssh_key] = enumerate_ssh(host, port, timeout=timeout.get('ssh', 10))
            except ImportError:
                pass
            except Exception as e:
                out["ssh_enumeration"][f"{host}:{port}"] = {"error": str(e)}
                if not continue_on_error:
                    raise
    
    return out
