"""Scan diff/comparison module

Compares two scans to identify changes in network services.
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set
from datetime import datetime


def load_scan_report(report_path: str) -> Dict[str, Any]:
    """
    Load a scan report JSON file.
    
    Args:
        report_path: Path to report.json
    
    Returns:
        Parsed report data
    """
    with open(report_path, 'r') as f:
        return json.load(f)


def extract_ports(nmap_data: Dict) -> Dict[str, Set[Tuple[int, str]]]:
    """
    Extract ports from nmap data.
    
    Args:
        nmap_data: Parsed nmap results
    
    Returns:
        Dict mapping IPs to set of (port, service) tuples
    """
    ports_by_host = {}
    
    for host in nmap_data.get("hosts", []):
        ip = host.get("addresses", [{}])[0].get("addr", "unknown")
        ports = set()
        
        for port in host.get("ports", []):
            if port.get("state") == "open":
                port_num = int(port.get("portid", port.get("port", 0)))
                service = port.get("service", {})
                service_name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")
                
                # Create service identifier
                if product and version:
                    service_id = f"{service_name} ({product} {version})"
                elif product:
                    service_id = f"{service_name} ({product})"
                else:
                    service_id = service_name
                
                ports.add((port_num, service_id))
        
        if ports:
            ports_by_host[ip] = ports
    
    return ports_by_host


def extract_vulns(vuln_data: Dict) -> Dict[str, List[Dict]]:
    """
    Extract vulnerabilities from scan data.
    
    Args:
        vuln_data: Vulnerability correlation data
    
    Returns:
        Dict mapping services to CVE lists
    """
    vulns_by_service = {}
    
    for service in vuln_data.get("services_with_cves", []):
        key = f"{service['host']}:{service['port']}"
        vulns_by_service[key] = service.get("cves", [])
    
    return vulns_by_service


def compare_scans(scan1_path: str, scan2_path: str) -> Dict[str, Any]:
    """
    Compare two scans and identify changes.
    
    Args:
        scan1_path: Path to first scan report.json
        scan2_path: Path to second scan report.json
    
    Returns:
        Dict with comparison results
    """
    # Load both scans
    scan1 = load_scan_report(scan1_path)
    scan2 = load_scan_report(scan2_path)
    
    # Extract data
    ports1 = extract_ports(scan1.get("nmap", {}))
    ports2 = extract_ports(scan2.get("nmap", {}))
    
    vulns1 = extract_vulns(scan1.get("vulnerabilities", {}))
    vulns2 = extract_vulns(scan2.get("vulnerabilities", {}))
    
    # Compare
    result = {
        "scan1": {
            "target": scan1.get("target"),
            "timestamp": scan1.get("timestamp"),
            "path": scan1_path
        },
        "scan2": {
            "target": scan2.get("target"),
            "timestamp": scan2.get("timestamp"),
            "path": scan2_path
        },
        "new_hosts": [],
        "removed_hosts": [],
        "new_ports": {},
        "removed_ports": {},
        "changed_services": {},
        "new_vulnerabilities": {},
        "fixed_vulnerabilities": {},
        "summary": []
    }
    
    # Find new and removed hosts
    hosts1 = set(ports1.keys())
    hosts2 = set(ports2.keys())
    
    result["new_hosts"] = list(hosts2 - hosts1)
    result["removed_hosts"] = list(hosts1 - hosts2)
    
    # Compare ports for common hosts
    common_hosts = hosts1 & hosts2
    
    for host in common_hosts:
        ports_before = ports1[host]
        ports_after = ports2[host]
        
        # New ports
        new_ports = ports_after - ports_before
        if new_ports:
            result["new_ports"][host] = list(new_ports)
        
        # Removed ports
        removed_ports = ports_before - ports_after
        if removed_ports:
            result["removed_ports"][host] = list(removed_ports)
        
        # Changed services (same port, different service)
        ports_before_dict = {p[0]: p[1] for p in ports_before}
        ports_after_dict = {p[0]: p[1] for p in ports_after}
        
        for port_num in set(ports_before_dict.keys()) & set(ports_after_dict.keys()):
            if ports_before_dict[port_num] != ports_after_dict[port_num]:
                if host not in result["changed_services"]:
                    result["changed_services"][host] = []
                result["changed_services"][host].append({
                    "port": port_num,
                    "before": ports_before_dict[port_num],
                    "after": ports_after_dict[port_num]
                })
    
    # Compare vulnerabilities
    vuln_keys1 = set(vulns1.keys())
    vuln_keys2 = set(vulns2.keys())
    
    common_services = vuln_keys1 & vuln_keys2
    
    for service_key in common_services:
        cves1 = {cve["cve_id"] for cve in vulns1[service_key]}
        cves2 = {cve["cve_id"] for cve in vulns2[service_key]}
        
        new_cves = cves2 - cves1
        if new_cves:
            result["new_vulnerabilities"][service_key] = list(new_cves)
        
        fixed_cves = cves1 - cves2
        if fixed_cves:
            result["fixed_vulnerabilities"][service_key] = list(fixed_cves)
    
    # Generate summary
    if result["new_hosts"]:
        result["summary"].append(f"[+] {len(result['new_hosts'])} new hosts discovered")
    
    if result["removed_hosts"]:
        result["summary"].append(f"[X] {len(result['removed_hosts'])} hosts disappeared")
    
    total_new_ports = sum(len(ports) for ports in result["new_ports"].values())
    if total_new_ports:
        result["summary"].append(f"[+] {total_new_ports} new ports opened")
    
    total_removed_ports = sum(len(ports) for ports in result["removed_ports"].values())
    if total_removed_ports:
        result["summary"].append(f"[X] {total_removed_ports} ports closed")
    
    total_changed = sum(len(changes) for changes in result["changed_services"].values())
    if total_changed:
        result["summary"].append(f"[!]  {total_changed} services changed")
    
    total_new_vulns = sum(len(cves) for cves in result["new_vulnerabilities"].values())
    if total_new_vulns:
        result["summary"].append(f"[!]  {total_new_vulns} new vulnerabilities")
    
    total_fixed_vulns = sum(len(cves) for cves in result["fixed_vulnerabilities"].values())
    if total_fixed_vulns:
        result["summary"].append(f"[+] {total_fixed_vulns} vulnerabilities fixed")
    
    if not result["summary"]:
        result["summary"].append("No significant changes detected")
    
    return result


def generate_diff_report(comparison: Dict[str, Any], output_path: str):
    """
    Generate a diff report.
    
    Args:
        comparison: Comparison results
        output_path: Path to save report
    """
    lines = []
    
    lines.append("╔═══════════════════════════════════════════════════════════╗")
    lines.append("║              REX SCAN - DIFF REPORT                       ║")
    lines.append("╚═══════════════════════════════════════════════════════════╝")
    lines.append("")
    
    # Scan info
    lines.append(f"Scan 1: {comparison['scan1']['target']} @ {comparison['scan1']['timestamp']}")
    lines.append(f"Scan 2: {comparison['scan2']['target']} @ {comparison['scan2']['timestamp']}")
    lines.append("")
    
    # Summary
    lines.append("═" * 60)
    lines.append("SUMMARY")
    lines.append("═" * 60)
    for summary in comparison["summary"]:
        lines.append(f"  {summary}")
    lines.append("")
    
    # New hosts
    if comparison["new_hosts"]:
        lines.append("═" * 60)
        lines.append("NEW HOSTS")
        lines.append("═" * 60)
        for host in comparison["new_hosts"]:
            lines.append(f"  [+] {host}")
        lines.append("")
    
    # Removed hosts
    if comparison["removed_hosts"]:
        lines.append("═" * 60)
        lines.append("REMOVED HOSTS")
        lines.append("═" * 60)
        for host in comparison["removed_hosts"]:
            lines.append(f"  [X] {host}")
        lines.append("")
    
    # New ports
    if comparison["new_ports"]:
        lines.append("═" * 60)
        lines.append("NEW PORTS")
        lines.append("═" * 60)
        for host, ports in comparison["new_ports"].items():
            lines.append(f"\n  Host: {host}")
            for port, service in ports:
                lines.append(f"    [+] {port}/tcp - {service}")
        lines.append("")
    
    # Removed ports
    if comparison["removed_ports"]:
        lines.append("═" * 60)
        lines.append("REMOVED PORTS")
        lines.append("═" * 60)
        for host, ports in comparison["removed_ports"].items():
            lines.append(f"\n  Host: {host}")
            for port, service in ports:
                lines.append(f"    [X] {port}/tcp - {service}")
        lines.append("")
    
    # Changed services
    if comparison["changed_services"]:
        lines.append("═" * 60)
        lines.append("CHANGED SERVICES")
        lines.append("═" * 60)
        for host, changes in comparison["changed_services"].items():
            lines.append(f"\n  Host: {host}")
            for change in changes:
                lines.append(f"    Port {change['port']}/tcp:")
                lines.append(f"      Before: {change['before']}")
                lines.append(f"      After:  {change['after']}")
        lines.append("")
    
    # New vulnerabilities
    if comparison["new_vulnerabilities"]:
        lines.append("═" * 60)
        lines.append("NEW VULNERABILITIES")
        lines.append("═" * 60)
        for service, cves in comparison["new_vulnerabilities"].items():
            lines.append(f"\n  Service: {service}")
            for cve in cves:
                lines.append(f"    [!]  {cve}")
        lines.append("")
    
    # Fixed vulnerabilities
    if comparison["fixed_vulnerabilities"]:
        lines.append("═" * 60)
        lines.append("FIXED VULNERABILITIES")
        lines.append("═" * 60)
        for service, cves in comparison["fixed_vulnerabilities"].items():
            lines.append(f"\n  Service: {service}")
            for cve in cves:
                lines.append(f"    [+] {cve}")
        lines.append("")
    
    lines.append("═" * 60)
    lines.append("End of Diff Report")
    lines.append("═" * 60)
    
    # Write to file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))
