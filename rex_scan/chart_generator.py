"""Chart generation for reports

Creates visualizations for scan data using matplotlib and plotly.
"""
from pathlib import Path
from typing import Dict, Any, List
import json


def check_matplotlib():
    """Check if matplotlib is available."""
    try:
        import matplotlib
        return True
    except ImportError:
        return False


def check_plotly():
    """Check if plotly is available."""
    try:
        import plotly
        return True
    except ImportError:
        return False


def generate_port_distribution_chart(nmap_data: Dict, output_path: str) -> bool:
    """
    Generate port distribution pie chart.
    
    Args:
        nmap_data: Parsed nmap results
        output_path: Path to save chart
    
    Returns:
        True if successful
    """
    if not check_matplotlib():
        return False
    
    try:
        import matplotlib.pyplot as plt
        
        # Count ports by service
        service_counts = {}
        
        for host in nmap_data.get("hosts", []):
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    service = port.get("service", {})
                    name = service.get("name", "unknown")
                    service_counts[name] = service_counts.get(name, 0) + 1
        
        if not service_counts:
            return False
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.pie(service_counts.values(), labels=service_counts.keys(), autopct='%1.1f%%', startangle=90)
        ax.set_title('Open Ports by Service Type', fontsize=16, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return True
    except Exception as e:
        print(f"Failed to generate port distribution chart: {e}")
        return False


def generate_vulnerability_severity_chart(vuln_data: Dict, output_path: str) -> bool:
    """
    Generate vulnerability severity bar chart.
    
    Args:
        vuln_data: Vulnerability correlation data
        output_path: Path to save chart
    
    Returns:
        True if successful
    """
    if not check_matplotlib():
        return False
    
    try:
        import matplotlib.pyplot as plt
        
        # Count by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }
        
        for service in vuln_data.get("services_with_cves", []):
            for cve in service.get("cves", []):
                severity = cve.get("severity", "UNKNOWN").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["UNKNOWN"] += 1
        
        # Remove zero counts
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        if not severity_counts:
            return False
        
        # Create bar chart
        fig, ax = plt.subplots(figsize=(10, 6))
        
        colors = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#388e3c",
            "UNKNOWN": "#757575"
        }
        
        bar_colors = [colors.get(k, "#757575") for k in severity_counts.keys()]
        
        ax.bar(severity_counts.keys(), severity_counts.values(), color=bar_colors)
        ax.set_xlabel('Severity', fontsize=12, fontweight='bold')
        ax.set_ylabel('Count', fontsize=12, fontweight='bold')
        ax.set_title('Vulnerabilities by Severity', fontsize=16, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return True
    except Exception as e:
        print(f"Failed to generate vulnerability severity chart: {e}")
        return False


def generate_credential_success_chart(cred_data: List[Dict], output_path: str) -> bool:
    """
    Generate credential check success/failure chart.
    
    Args:
        cred_data: Credential check results
        output_path: Path to save chart
    
    Returns:
        True if successful
    """
    if not check_matplotlib():
        return False
    
    try:
        import matplotlib.pyplot as plt
        
        success_count = sum(1 for c in cred_data if c.get("success"))
        failure_count = len(cred_data) - success_count
        
        if not cred_data:
            return False
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(8, 8))
        
        sizes = [success_count, failure_count]
        labels = ['Successful', 'Failed']
        colors = ['#4caf50', '#f44336']
        explode = (0.1, 0)
        
        ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', 
               startangle=90, textprops={'fontsize': 12, 'fontweight': 'bold'})
        ax.set_title('Credential Check Results', fontsize=16, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return True
    except Exception as e:
        print(f"Failed to generate credential success chart: {e}")
        return False


def generate_interactive_network_map(nmap_data: Dict, output_path: str) -> bool:
    """
    Generate interactive network topology using plotly.
    
    Args:
        nmap_data: Parsed nmap results
        output_path: Path to save HTML
    
    Returns:
        True if successful
    """
    if not check_plotly():
        return False
    
    try:
        import plotly.graph_objects as go
        
        # Prepare data for network graph
        nodes = []
        edges = []
        node_text = []
        
        for i, host in enumerate(nmap_data.get("hosts", [])):
            ip = host.get("addresses", [{}])[0].get("addr", "unknown")
            nodes.append(ip)
            
            # Node text with port info
            ports = host.get("ports", [])
            open_ports = [p for p in ports if p.get("state") == "open"]
            port_summary = f"{ip}<br>{len(open_ports)} open ports"
            node_text.append(port_summary)
        
        # Create figure
        fig = go.Figure()
        
        # Add nodes
        fig.add_trace(go.Scatter(
            x=list(range(len(nodes))),
            y=[0] * len(nodes),
            mode='markers+text',
            marker=dict(size=20, color='#667eea'),
            text=nodes,
            textposition="bottom center",
            hovertext=node_text,
            hoverinfo='text'
        ))
        
        fig.update_layout(
            title="Network Topology",
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white'
        )
        
        fig.write_html(output_path)
        return True
    except Exception as e:
        print(f"Failed to generate network map: {e}")
        return False


def generate_all_charts(scan_data: Dict, output_dir: Path) -> Dict[str, str]:
    """
    Generate all charts for a scan.
    
    Args:
        scan_data: Complete scan data
        output_dir: Directory to save charts
    
    Returns:
        Dict mapping chart names to file paths
    """
    charts = {}
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Port distribution
    port_chart = output_dir / "port_distribution.png"
    if generate_port_distribution_chart(scan_data.get("nmap", {}), str(port_chart)):
        charts["port_distribution"] = str(port_chart)
    
    # Vulnerability severity
    vuln_chart = output_dir / "vulnerability_severity.png"
    if generate_vulnerability_severity_chart(scan_data.get("vulnerabilities", {}), str(vuln_chart)):
        charts["vulnerability_severity"] = str(vuln_chart)
    
    # Credential success
    cred_chart = output_dir / "credential_success.png"
    if generate_credential_success_chart(scan_data.get("credentials", []), str(cred_chart)):
        charts["credential_success"] = str(cred_chart)
    
    # Interactive network map
    network_map = output_dir / "network_topology.html"
    if generate_interactive_network_map(scan_data.get("nmap", {}), str(network_map)):
        charts["network_topology"] = str(network_map)
    
    return charts
