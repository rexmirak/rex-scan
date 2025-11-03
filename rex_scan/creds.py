"""Lightweight credential checks for discovered services.

Only performs conservative, low-impact checks by default:
- FTP anonymous login
- HTTP Basic auth common creds

All active checks require explicit consent (handled by CLI).
"""
from ftplib import FTP, error_perm
import requests
from typing import Dict, List


COMMON_HTTP_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("guest", "guest"),
]


def check_ftp_anonymous(host: str, port: int = 21, timeout: int = 5) -> Dict:
    """Check if FTP allows anonymous login."""
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login()
        ftp.quit()
        return {
            "service": "FTP",
            "host": host,
            "port": port,
            "credential_type": "anonymous",
            "success": True,
            "username": "anonymous",
            "password": "<any>",
            "details": "Anonymous FTP login successful"
        }
    except Exception as e:
        return {
            "service": "FTP",
            "host": host,
            "port": port,
            "credential_type": "anonymous",
            "success": False,
            "details": f"Anonymous login failed: {str(e)}"
        }


def check_http_basic(host: str, port: int, path: str = "/", timeout: int = 5) -> List[Dict]:
    """Check common HTTP basic auth credentials."""
    results = []
    proto = "https" if port == 443 else "http"
    url = f"{proto}://{host}:{port}{path}"
    
    for u, p in COMMON_HTTP_CREDS:
        try:
            r = requests.get(url, auth=(u, p), timeout=timeout, allow_redirects=False, verify=False)
            success = r.status_code not in (401, 403)
            results.append({
                "service": "HTTP",
                "host": host,
                "port": port,
                "credential_type": "basic_auth",
                "success": success,
                "username": u,
                "password": p,
                "status_code": r.status_code,
                "url": url,
                "details": f"HTTP {r.status_code} - {'SUCCESS' if success else 'FAILED'}"
            })
        except Exception as e:
            results.append({
                "service": "HTTP",
                "host": host,
                "port": port,
                "credential_type": "basic_auth",
                "success": False,
                "username": u,
                "password": p,
                "error": str(e),
                "url": url,
                "details": f"Connection failed: {str(e)}"
            })
            continue
    return results
