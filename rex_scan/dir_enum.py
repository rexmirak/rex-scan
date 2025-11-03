"""Directory and file enumeration for HTTP/HTTPS services."""
import subprocess
import shutil
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from pathlib import Path
import time

logger = logging.getLogger("rex_scan.dir_enum")


def has_gobuster() -> bool:
    """Check if gobuster is installed."""
    return shutil.which("gobuster") is not None


def gobuster_dir(url: str, wordlist: str, extensions: List[str] = None, timeout: int = 120) -> List[Dict]:
    """Run gobuster dir mode against a URL."""
    if not has_gobuster():
        raise RuntimeError("gobuster not found")
    
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error"]
    if extensions:
        cmd.extend(["-x", ",".join(extensions)])
    
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        results = []
        # Parse gobuster output: "path (Status: 200) [Size: 123]"
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or "Progress:" in line:
                continue
            
            # Extract path and status
            path = line.split()[0] if line.split() else ""
            status = ""
            size = ""
            
            if "(Status:" in line:
                try:
                    status = line.split("(Status: ")[1].split(")")[0]
                except:
                    pass
            
            if "[Size:" in line:
                try:
                    size = line.split("[Size: ")[1].split("]")[0]
                except:
                    pass
            
            if path:
                result = {"path": path, "status": status, "size": size}
                results.append(result)
                logger.info(f"Found directory: {path} (Status: {status})")
        
        return results
    except subprocess.TimeoutExpired:
        logger.warning(f"gobuster timed out after {timeout}s")
        return []
    except Exception as e:
        logger.error(f"gobuster failed: {e}")
        return []


def python_dir_bruteforce(url: str, wordlist: str, extensions: List[str] = None, threads: int = 10, timeout: int = 5) -> List[Dict]:
    """Pure Python directory brute-forcer (fallback if gobuster missing)."""
    results = []
    
    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Failed to read wordlist {wordlist}: {e}")
        return results
    
    # add extensions
    test_paths = []
    for path in paths[:500]:  # limit for safety
        test_paths.append(path)
        if extensions:
            for ext in extensions:
                test_paths.append(f"{path}.{ext}")
    
    def check_path(path):
        test_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        try:
            resp = requests.get(test_url, timeout=timeout, allow_redirects=False, verify=False)
            if resp.status_code not in [404]:
                return {"path": path, "status": resp.status_code, "size": len(resp.content)}
        except requests.RequestException:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, path): path for path in test_paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                logger.info(f"Found: {result['path']} ({result['status']})")
    
    return results


def enumerate_directories(url: str, wordlist: str = None, extensions: List[str] = None, use_gobuster: bool = True) -> List[Dict]:
    """Enumerate directories/files. Prefer gobuster if available, fallback to Python."""
    if not wordlist:
        # create minimal default wordlist
        default_paths = ["admin", "login", "api", "backup", "config", "test", "dev", "uploads"]
        return python_dir_bruteforce(url, None, extensions, threads=5) if False else []
    
    if use_gobuster and has_gobuster():
        logger.info(f"Using gobuster for directory enumeration: {url}")
        return gobuster_dir(url, wordlist, extensions)
    else:
        logger.info(f"Using Python bruteforcer for directory enumeration: {url}")
        return python_dir_bruteforce(url, wordlist, extensions)
