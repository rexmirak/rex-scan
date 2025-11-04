"""SMB Enumeration Module

Performs comprehensive SMB enumeration including:
- Share listing
- Null session checks
- User enumeration
- OS/version detection

Requires smbclient to be installed (optional tool).
"""
import subprocess
import time
import re
from typing import Dict, List, Any
from pathlib import Path
from rex_scan.command_tracker import get_tracker


def check_smbclient() -> bool:
    """Check if smbclient is available."""
    try:
        subprocess.run(["smbclient", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def enumerate_smb_shares(host: str, port: int = 445, timeout: int = 10) -> Dict[str, Any]:
    """
    Enumerate SMB shares using smbclient.
    
    Args:
        host: Target IP or hostname
        port: SMB port (default 445)
        timeout: Command timeout in seconds
    
    Returns:
        Dict with shares, null_session status, and errors
    """
    result = {
        "host": host,
        "port": port,
        "shares": [],
        "null_session_allowed": False,
        "os_info": {},
        "errors": []
    }
    
    if not check_smbclient():
        result["errors"].append("smbclient not installed")
        return result
    
    tracker = get_tracker()
    
    # Try null session enumeration
    try:
        cmd = [
            "smbclient",
            "-L", f"//{host}",
            "-N",  # No password (null session)
            "-p", str(port)
        ]
        cmd_str = " ".join(cmd)
        start_time = time.time()
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        duration = time.time() - start_time
        
        # Track command
        tracker.track(
            tool="smbclient",
            command=cmd_str,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration=duration,
            context=f"SMB share enumeration for {host}:{port}"
        )
        
        output = proc.stdout + proc.stderr
        
        # Check if null session succeeded
        if "NT_STATUS_ACCESS_DENIED" not in output and "failed" not in output.lower():
            result["null_session_allowed"] = True
        
        # Parse shares
        share_pattern = r'\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)'
        for line in output.split('\n'):
            match = re.search(share_pattern, line)
            if match:
                share_name = match.group(1)
                share_type = match.group(2)
                comment = match.group(3).strip()
                
                result["shares"].append({
                    "name": share_name,
                    "type": share_type,
                    "comment": comment
                })
        
        # Extract OS information
        os_pattern = r'Domain=\[([^\]]+)\]\s+OS=\[([^\]]+)\]\s+Server=\[([^\]]+)\]'
        os_match = re.search(os_pattern, output)
        if os_match:
            result["os_info"] = {
                "domain": os_match.group(1),
                "os": os_match.group(2),
                "server": os_match.group(3)
            }
        
    except subprocess.TimeoutExpired:
        result["errors"].append(f"SMB enumeration timed out after {timeout}s")
    except Exception as e:
        result["errors"].append(f"SMB enumeration failed: {str(e)}")
    
    return result


def enumerate_smb_users(host: str, username: str = "", password: str = "", timeout: int = 10) -> Dict[str, Any]:
    """
    Enumerate SMB users using rpcclient.
    
    Args:
        host: Target IP or hostname
        username: SMB username (empty for null session)
        password: SMB password
        timeout: Command timeout in seconds
    
    Returns:
        Dict with users list and errors
    """
    result = {
        "host": host,
        "users": [],
        "groups": [],
        "errors": []
    }
    
    # Check if rpcclient is available
    try:
        subprocess.run(["rpcclient", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["errors"].append("rpcclient not installed")
        return result
    
    tracker = get_tracker()
    
    try:
        # Build rpcclient command
        if username:
            cmd = [
                "rpcclient",
                "-U", f"{username}%{password}",
                host,
                "-c", "enumdomusers"
            ]
        else:
            cmd = [
                "rpcclient",
                "-U", "",
                "-N",
                host,
                "-c", "enumdomusers"
            ]
        
        cmd_str = " ".join(cmd).replace(f"{password}", "***") if password else " ".join(cmd)
        start_time = time.time()
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        duration = time.time() - start_time
        
        # Track command (mask password)
        tracker.track(
            tool="rpcclient",
            command=cmd_str,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration=duration,
            context=f"SMB user enumeration for {host}"
        )
        
        output = proc.stdout
        
        # Parse user enumeration
        user_pattern = r'user:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]'
        for line in output.split('\n'):
            match = re.search(user_pattern, line)
            if match:
                result["users"].append({
                    "username": match.group(1),
                    "rid": match.group(2)
                })
        
    except subprocess.TimeoutExpired:
        result["errors"].append(f"User enumeration timed out after {timeout}s")
    except Exception as e:
        result["errors"].append(f"User enumeration failed: {str(e)}")
    
    return result


def enumerate_smb(host: str, port: int = 445, timeout: int = 10) -> Dict[str, Any]:
    """
    Comprehensive SMB enumeration.
    
    Args:
        host: Target IP or hostname
        port: SMB port (default 445)
        timeout: Connection timeout in seconds (default 10)
    
    Returns:
        Dict with all SMB enumeration results
    """
    results = {
        "target": host,
        "port": port,
        "tool": "smbclient/rpcclient",
        "shares": [],
        "users": [],
        "null_session": False,
        "os_info": {},
        "summary": []
    }
    
    # Enumerate shares
    share_results = enumerate_smb_shares(host, port, timeout=timeout)
    results["shares"] = share_results.get("shares", [])
    results["null_session"] = share_results.get("null_session_allowed", False)
    results["os_info"] = share_results.get("os_info", {})
    
    if share_results.get("errors"):
        results["summary"].extend(share_results["errors"])
    else:
        results["summary"].append(f"Found {len(results['shares'])} SMB shares")
        if results["null_session"]:
            results["summary"].append("[!]  NULL SESSION allowed - security risk!")
    
    # Try user enumeration if null session works
    if results["null_session"]:
        user_results = enumerate_smb_users(host, timeout=timeout)
        results["users"] = user_results.get("users", [])
        if user_results.get("errors"):
            results["summary"].extend(user_results["errors"])
        else:
            results["summary"].append(f"Enumerated {len(results['users'])} users via RPC")
    
    return results
