"""Directory and file enumeration for HTTP/HTTPS services.

Supports both external tools (gobuster, dirb) and Python fallback.
"""
import subprocess
import shutil
import logging
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from pathlib import Path
from rex_scan.command_tracker import get_tracker

logger = logging.getLogger("rex_scan.dir_enum")


def has_gobuster() -> bool:
    """Check if gobuster is installed."""
    return shutil.which("gobuster") is not None


def has_dirb() -> bool:
    """Check if dirb is installed."""
    return shutil.which("dirb") is not None


def gobuster_dir(url: str, wordlist: str, extensions: List[str] = None, timeout: int = 120) -> List[Dict]:
    """Run gobuster dir mode against a URL."""
    if not has_gobuster():
        raise RuntimeError("gobuster not found")
    
    tracker = get_tracker()
    # Convert wordlist to string if it's a Path object
    wordlist_str = str(wordlist) if not isinstance(wordlist, str) else wordlist
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist_str, "-q", "--no-error"]
    if extensions:
        cmd.extend(["-x", ",".join(extensions)])
    
    cmd_str = " ".join(cmd)
    start_time = time.time()
    
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                            text=True, timeout=timeout)
        duration = time.time() - start_time
        
        # Track command
        tracker.track(
            tool="gobuster",
            command=cmd_str,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration=duration,
            context=f"Directory enumeration for {url}"
        )
        
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
        duration = time.time() - start_time
        logger.warning(f"gobuster timed out after {timeout}s")
        tracker.track(
            tool="gobuster",
            command=cmd_str,
            stdout="",
            stderr=f"Timeout after {timeout}s",
            exit_code=-1,
            duration=duration,
            context=f"Directory enumeration for {url} (TIMEOUT)"
        )
        return []
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"gobuster failed: {e}")
        tracker.track(
            tool="gobuster",
            command=cmd_str,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=duration,
            context=f"Directory enumeration for {url} (ERROR)"
        )
        return []


def dirb_scan(url: str, wordlist: str, extensions: List[str] = None, timeout: int = 120) -> List[Dict]:
    """Run dirb tool against a URL."""
    if not has_dirb():
        raise RuntimeError("dirb not found")
    
    tracker = get_tracker()
    # Convert wordlist to string if it's a Path object
    wordlist_str = str(wordlist) if not isinstance(wordlist, str) else wordlist
    cmd = ["dirb", url, wordlist_str, "-S", "-w"]  # -S = silent, -w = don't stop on warnings
    
    if extensions:
        # dirb uses -X flag for extensions
        cmd.extend(["-X", f".{',. '.join(extensions)}"])
    
    cmd_str = " ".join(cmd)
    start_time = time.time()
    
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
        duration = time.time() - start_time
        
        # Track command
        tracker.track(
            tool="dirb",
            command=cmd_str,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration=duration,
            context=f"Directory enumeration for {url}"
        )
        
        results = []
        # Parse dirb output: "+ http://example.com/admin (CODE:200|SIZE:1234)"
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("+ "):
                try:
                    # Extract URL and metadata
                    parts = line.split()
                    found_url = parts[1]
                    path = found_url.replace(url.rstrip("/"), "")
                    
                    # Extract status code
                    status = ""
                    size = ""
                    if "(CODE:" in line:
                        metadata = line.split("(")[1].split(")")[0]
                        if "CODE:" in metadata:
                            status = metadata.split("CODE:")[1].split("|")[0]
                        if "SIZE:" in metadata:
                            size = metadata.split("SIZE:")[1]
                    
                    result = {"path": path, "status": status, "size": size}
                    results.append(result)
                    logger.info(f"Found directory: {path} (Status: {status})")
                except Exception as e:
                    logger.debug(f"Failed to parse dirb line: {line} - {e}")
        
        return results
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        logger.warning(f"dirb timed out after {timeout}s")
        tracker.track(
            tool="dirb",
            command=cmd_str,
            stdout="",
            stderr=f"Timeout after {timeout}s",
            exit_code=-1,
            duration=duration,
            context=f"Directory enumeration for {url} (TIMEOUT)"
        )
        return []
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"dirb failed: {e}")
        tracker.track(
            tool="dirb",
            command=cmd_str,
            stdout="",
            stderr=str(e),
            exit_code=-1,
            duration=duration,
            context=f"Directory enumeration for {url} (ERROR)"
        )
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


def enumerate_directories(url: str, wordlist: str = None, extensions: List[str] = None, 
                         prefer_external: bool = True, tool_preference: str = "gobuster") -> Dict:
    """
    Enumerate directories/files using available tools.
    
    Args:
        url: Target URL
        wordlist: Path to wordlist file
        extensions: List of file extensions to check
        prefer_external: Try external tools before Python fallback
        tool_preference: Preferred external tool ("gobuster" or "dirb")
    
    Returns:
        Dict with enumeration results and metadata
    """
    if not wordlist:
        logger.warning("No wordlist provided for directory enumeration")
        return {"method": "none", "results": [], "error": "No wordlist provided"}
    
    results_data = {
        "method": "unknown",
        "url": url,
        "results": [],
        "error": None
    }
    
    if prefer_external:
        # Try preferred tool first
        if tool_preference == "gobuster" and has_gobuster():
            logger.info(f"Using gobuster for directory enumeration: {url}")
            results_data["method"] = "gobuster"
            results_data["results"] = gobuster_dir(url, wordlist, extensions)
            return results_data
        elif tool_preference == "dirb" and has_dirb():
            logger.info(f"Using dirb for directory enumeration: {url}")
            results_data["method"] = "dirb"
            results_data["results"] = dirb_scan(url, wordlist, extensions)
            return results_data
        
        # Fallback to the other external tool
        if has_gobuster() and tool_preference != "gobuster":
            logger.info(f"Using gobuster (fallback) for directory enumeration: {url}")
            results_data["method"] = "gobuster"
            results_data["results"] = gobuster_dir(url, wordlist, extensions)
            return results_data
        elif has_dirb() and tool_preference != "dirb":
            logger.info(f"Using dirb (fallback) for directory enumeration: {url}")
            results_data["method"] = "dirb"
            results_data["results"] = dirb_scan(url, wordlist, extensions)
            return results_data
    
    # Final fallback to Python implementation
    logger.info(f"Using Python bruteforcer for directory enumeration: {url}")
    results_data["method"] = "python"
    results_data["results"] = python_dir_bruteforce(url, wordlist, extensions)
    return results_data
