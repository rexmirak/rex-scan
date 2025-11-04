"""Report generation: text, JSON, HTML reports."""
from pathlib import Path
from typing import Any, Dict
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rex_scan.command_tracker import get_tracker


def generate_text_report(data: Dict[str, Any], out_path: str) -> str:
    """Generate a text report from scan data."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    
    lines = []
    lines.append("╔═══════════════════════════════════════════════════════════╗")
    lines.append("║                    REX SCAN REPORT                        ║")
    lines.append("╚═══════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append(f"Target: {data.get('target', 'Unknown')}")
    lines.append(f"Scan Time: {data.get('timestamp', 'Unknown')}")
    lines.append("")
    
    # Nmap results
    lines.append("═" * 60)
    lines.append("NETWORK SCAN RESULTS")
    lines.append("═" * 60)
    
    nmap_data = data.get("nmap", {})
    for host in nmap_data.get("hosts", []):
        lines.append("")
        addrs = ", ".join([a.get("addr") for a in host.get("addresses", [])])
        hostnames = ", ".join(host.get("hostnames", []))
        lines.append(f"Host: {addrs}")
        if hostnames:
            lines.append(f"Hostnames: {hostnames}")
        
        ports = host.get("ports", [])
        if ports:
            lines.append(f"\nOpen Ports ({len(ports)}):")
            for port in ports:
                svc = port.get("service") or {}
                port_id = port.get("portid", port.get("port", "?"))
                protocol = port.get("protocol", "tcp")
                state = port.get("state", "unknown")
                name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                lines.append(f"  [{port_id}/{protocol}] {state} - {name} {product} {version}".strip())
    
    # Exploits
    exploits = data.get("exploits", [])
    if exploits and len(exploits) > 2:  # Skip header/footer lines
        lines.append("")
        lines.append("═" * 60)
        lines.append("EXPLOIT DATABASE MATCHES")
        lines.append("═" * 60)
        for line in exploits:
            lines.append(line)
    
    # Credentials
    creds = data.get("credentials", [])
    if creds:
        lines.append("")
        lines.append("═" * 60)
        lines.append("CREDENTIAL CHECK RESULTS")
        lines.append("═" * 60)
        
        successful_creds = [c for c in creds if c.get("success")]
        failed_creds = [c for c in creds if not c.get("success")]
        
        if successful_creds:
            lines.append("\n[+] SUCCESSFUL LOGINS:")
            for cred in successful_creds:
                service = cred.get("service", "Unknown")
                host = cred.get("host", "")
                port = cred.get("port", "")
                username = cred.get("username", "")
                password = cred.get("password", "")
                details = cred.get("details", "")
                lines.append(f"  [{service}] {host}:{port}")
                lines.append(f"    Username: {username}")
                lines.append(f"    Password: {password}")
                lines.append(f"    Details: {details}")
                lines.append("")
        
        if failed_creds and len(failed_creds) < 20:  # Only show failed if not too many
            lines.append("\n[X] Failed Attempts:")
            for cred in failed_creds[:10]:  # Limit to 10
                service = cred.get("service", "Unknown")
                host = cred.get("host", "")
                port = cred.get("port", "")
                username = cred.get("username", "")
                lines.append(f"  [{service}] {host}:{port} - {username} (failed)")
    
    # DNS Enumeration
    dns_results = data.get("dns_enumeration", {})
    if dns_results:
        lines.append("")
        lines.append("═" * 60)
        lines.append("DNS ENUMERATION")
        lines.append("═" * 60)
        for target, result in dns_results.items():
            lines.append(f"\nTarget: {target}")
            if result.get("subdomains"):
                lines.append(f"  Subdomains found: {len(result['subdomains'])}")
                for sub in result["subdomains"][:10]:  # Limit to first 10
                    lines.append(f"    - {sub}")
    
    # Directory Enumeration
    dir_results = data.get("directory_enumeration", {})
    if dir_results:
        lines.append("")
        lines.append("═" * 60)
        lines.append("DIRECTORY ENUMERATION")
        lines.append("═" * 60)
        for url, paths in dir_results.items():
            lines.append(f"\nURL: {url}")
            if paths and isinstance(paths, list):
                lines.append(f"  Paths/files found: {len(paths)}")
                for path_obj in paths[:20]:  # Limit to first 20
                    if isinstance(path_obj, dict):
                        path = path_obj.get("path", "")
                        status = path_obj.get("status", "")
                        size = path_obj.get("size", "")
                        lines.append(f"    - {path} (Status: {status}, Size: {size})")
                    else:
                        lines.append(f"    - {path_obj}")
    
    lines.append("")
    lines.append("═" * 60)
    lines.append("End of Report")
    lines.append("═" * 60)
    
    p.write_text("\n".join(lines))
    return str(p)


def generate_json_report(data: Dict[str, Any], out_path: str) -> str:
    """Generate a JSON report from scan data."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))
    return str(p)


def generate_html_report(data: Dict[str, Any], out_path: str, templates_dir: str = None) -> str:
    """Generate an HTML report from scan data."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if templates_dir is None:
        templates_dir = Path(__file__).parent / "templates"

    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=select_autoescape(["html", "xml"]))
    tpl = env.get_template("report.html.j2")
    html = tpl.render(data=data)
    p.write_text(html)
    return str(p)


def generate_commands_html(out_path: str, templates_dir: str = None) -> str:
    """
    Generate an HTML report of all executed commands with raw output.
    
    Args:
        out_path: Path to save the commands HTML report
        templates_dir: Directory containing Jinja2 templates
    
    Returns:
        Path to generated HTML file
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    
    if templates_dir is None:
        templates_dir = Path(__file__).parent / "templates"
    
    # Get command tracking data
    tracker = get_tracker()
    commands = tracker.get_all()
    summary = tracker.summary()
    
    # Render template
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"])
    )
    tpl = env.get_template("commands.html.j2")
    html = tpl.render(commands=commands, summary=summary)
    
    p.write_text(html)
    return str(p)
