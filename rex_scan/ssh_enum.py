"""SSH Enumeration Module

Performs SSH service analysis including:
- Banner grabbing
- SSH version detection
- Cipher/algorithm enumeration
- Security analysis

Uses ssh-audit if available, falls back to basic socket connection.
"""
import subprocess
import socket
import re
from typing import Dict, List, Any


def check_ssh_audit() -> bool:
    """Check if ssh-audit is available."""
    try:
        subprocess.run(["ssh-audit", "--help"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def grab_ssh_banner(host: str, port: int = 22, timeout: int = 5) -> Dict[str, Any]:
    """
    Grab SSH banner using raw socket connection.
    
    Args:
        host: Target IP or hostname
        port: SSH port (default 22)
        timeout: Connection timeout
    
    Returns:
        Dict with banner info and version
    """
    result = {
        "host": host,
        "port": port,
        "banner": "",
        "version": "",
        "protocol": "",
        "errors": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        result["banner"] = banner
        
        # Parse banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        banner_pattern = r'SSH-([0-9.]+)-(.+)'
        match = re.search(banner_pattern, banner)
        if match:
            result["protocol"] = match.group(1)
            result["version"] = match.group(2)
        
        sock.close()
        
    except socket.timeout:
        result["errors"].append(f"Connection timed out after {timeout}s")
    except Exception as e:
        result["errors"].append(f"Banner grab failed: {str(e)}")
    
    return result


def enumerate_ssh_with_audit(host: str, port: int = 22, timeout: int = 30) -> Dict[str, Any]:
    """
    Enumerate SSH using ssh-audit tool for detailed analysis.
    
    Args:
        host: Target IP or hostname
        port: SSH port (default 22)
        timeout: Command timeout
    
    Returns:
        Dict with comprehensive SSH analysis
    """
    result = {
        "host": host,
        "port": port,
        "ciphers": {
            "encryption": [],
            "mac": [],
            "key_exchange": [],
            "host_key": []
        },
        "vulnerabilities": [],
        "recommendations": [],
        "errors": []
    }
    
    if not check_ssh_audit():
        result["errors"].append("ssh-audit not installed - limited analysis")
        return result
    
    try:
        cmd = ["ssh-audit", "-p", str(port), "-j", host]
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout
        
        # Parse ssh-audit JSON output
        import json
        try:
            data = json.loads(output)
            
            # Extract cipher information
            if "kex" in data:
                kex_data = data["kex"]
                
                # Encryption algorithms
                if "server" in kex_data and "encryption" in kex_data["server"]:
                    result["ciphers"]["encryption"] = kex_data["server"]["encryption"]
                
                # MAC algorithms
                if "server" in kex_data and "mac" in kex_data["server"]:
                    result["ciphers"]["mac"] = kex_data["server"]["mac"]
                
                # Key exchange algorithms
                if "kex_algorithms" in kex_data:
                    result["ciphers"]["key_exchange"] = kex_data["kex_algorithms"]
                
                # Host key algorithms
                if "key_algorithms" in kex_data:
                    result["ciphers"]["host_key"] = kex_data["key_algorithms"]
            
            # Extract vulnerabilities
            if "cvelist" in data:
                for cve in data["cvelist"]:
                    result["vulnerabilities"].append(cve)
            
        except json.JSONDecodeError:
            # Fallback to text parsing if JSON fails
            result["errors"].append("Could not parse ssh-audit JSON output")
        
    except subprocess.TimeoutExpired:
        result["errors"].append(f"ssh-audit timed out after {timeout}s")
    except Exception as e:
        result["errors"].append(f"ssh-audit failed: {str(e)}")
    
    return result


def analyze_ssh_security(ciphers: Dict, banner_info: Dict) -> List[str]:
    """
    Analyze SSH configuration for security issues.
    
    Args:
        ciphers: Cipher information from enumeration
        banner_info: Banner information
    
    Returns:
        List of security findings
    """
    findings = []
    
    # Check for weak ciphers
    weak_ciphers = ["3des", "arcfour", "blowfish", "cast128", "des"]
    for enc in ciphers.get("encryption", []):
        for weak in weak_ciphers:
            if weak in enc.lower():
                findings.append(f"[!]  Weak encryption cipher: {enc}")
    
    # Check for weak MAC algorithms
    weak_macs = ["md5", "96"]
    for mac in ciphers.get("mac", []):
        for weak in weak_macs:
            if weak in mac.lower():
                findings.append(f"[!]  Weak MAC algorithm: {mac}")
    
    # Check protocol version
    if banner_info.get("protocol") == "1.0":
        findings.append("[CRITICAL] SSH Protocol 1.0 detected - CRITICAL VULNERABILITY")
    elif banner_info.get("protocol") == "1.99":
        findings.append("[!]  SSH Protocol 1.99 (supports SSH-1) - security risk")
    
    # Check for version disclosure
    if banner_info.get("version"):
        findings.append(f"ℹ️  Version disclosure: {banner_info['version']}")
    
    return findings


def enumerate_ssh(host: str, port: int = 22, timeout: int = 10) -> Dict[str, Any]:
    """
    Comprehensive SSH service enumeration.
    
    Args:
        host: Target IP or hostname
        port: SSH port (default 22)
        timeout: Connection timeout in seconds (default 10)
    
    Returns:
        Dict with all SSH enumeration results
    """
    results = {
        "target": host,
        "port": port,
        "banner": {},
        "ciphers": {},
        "vulnerabilities": [],
        "security_findings": [],
        "summary": []
    }
    
    # Grab banner
    banner_info = grab_ssh_banner(host, port, timeout=timeout)
    results["banner"] = banner_info
    
    if banner_info.get("errors"):
        results["summary"].extend(banner_info["errors"])
        return results
    
    results["summary"].append(f"SSH version: {banner_info.get('version', 'Unknown')}")
    results["summary"].append(f"Protocol: SSH-{banner_info.get('protocol', 'Unknown')}")
    
    # Try detailed enumeration with ssh-audit
    if check_ssh_audit():
        audit_info = enumerate_ssh_with_audit(host, port, timeout=timeout)
        results["ciphers"] = audit_info.get("ciphers", {})
        results["vulnerabilities"] = audit_info.get("vulnerabilities", [])
        
        if audit_info.get("errors"):
            results["summary"].extend(audit_info["errors"])
        else:
            enc_count = len(results["ciphers"].get("encryption", []))
            kex_count = len(results["ciphers"].get("key_exchange", []))
            results["summary"].append(f"Encryption algorithms: {enc_count}")
            results["summary"].append(f"Key exchange algorithms: {kex_count}")
    else:
        results["summary"].append("[!]  ssh-audit not available - limited analysis")
    
    # Security analysis
    security_findings = analyze_ssh_security(results["ciphers"], banner_info)
    results["security_findings"] = security_findings
    
    if security_findings:
        results["summary"].append(f"Security issues found: {len(security_findings)}")
    
    return results
