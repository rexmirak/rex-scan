"""Vulnerability Correlation Module

Cross-references discovered service versions with vulnerability databases:
- CVE (Common Vulnerabilities and Exposures)
- NVD (National Vulnerability Database)
- CPE (Common Platform Enumeration) matching

Uses online APIs when available, caches results locally.
"""
import re
import json
import requests
from typing import Dict, List, Any
from pathlib import Path
import time


CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = Path.home() / ".rex_scan" / "vuln_cache"


def setup_cache():
    """Ensure cache directory exists."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def extract_cpe_from_service(service_info: Dict) -> List[str]:
    """
    Extract potential CPE identifiers from service information.
    
    Args:
        service_info: Dict with product, version, vendor info
    
    Returns:
        List of CPE 2.3 formatted strings
    """
    cpes = []
    
    product = service_info.get("product", "").lower()
    version = service_info.get("version", "").lower()
    vendor = service_info.get("vendor", "").lower()
    
    if not product:
        return cpes
    
    # Clean version string
    version = re.sub(r'[^\d.]', '', version) if version else "*"
    
    # Generate CPE string
    # Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    if vendor:
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    else:
        # Try to infer vendor from product name
        common_vendors = {
            "apache": "apache",
            "nginx": "nginx",
            "openssh": "openbsd",
            "mysql": "oracle",
            "postgresql": "postgresql",
            "microsoft": "microsoft",
            "iis": "microsoft"
        }
        
        inferred_vendor = None
        for keyword, v in common_vendors.items():
            if keyword in product:
                inferred_vendor = v
                break
        
        if inferred_vendor:
            cpe = f"cpe:2.3:a:{inferred_vendor}:{product}:{version}:*:*:*:*:*:*:*"
        else:
            cpe = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
    
    cpes.append(cpe)
    return cpes


def search_cve_by_keyword(product: str, version: str = None, max_results: int = 10) -> List[Dict]:
    """
    Search CVE database by product/version keywords.
    
    Args:
        product: Product name
        version: Product version (optional)
        max_results: Maximum results to return
    
    Returns:
        List of CVE dictionaries
    """
    setup_cache()
    
    # Build cache key
    cache_key = f"{product}_{version if version else 'all'}".replace(" ", "_").replace("/", "_")
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    # Check cache (24 hour TTL)
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < 86400:  # 24 hours
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
    
    cves = []
    
    try:
        # Build search query
        keyword = f"{product} {version}" if version else product
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results
        }
        
        response = requests.get(
            CVE_API_BASE,
            params=params,
            timeout=10,
            headers={"User-Agent": "REX-SCAN/1.0"}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                
                # Extract CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = "N/A"
                severity = "UNKNOWN"
                
                if "cvssMetricV31" in metrics:
                    cvss_v3 = metrics["cvssMetricV31"][0] if metrics["cvssMetricV31"] else {}
                    cvss_data = cvss_v3.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics:
                    cvss_v2 = metrics["cvssMetricV2"][0] if metrics["cvssMetricV2"] else {}
                    cvss_data = cvss_v2.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                
                # Extract description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                cves.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": description[:200] + "..." if len(description) > 200 else description,
                    "published": cve_data.get("published", ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
        
        # Cache results
        try:
            with open(cache_file, 'w') as f:
                json.dump(cves, f, indent=2)
        except:
            pass
        
    except requests.exceptions.RequestException as e:
        # Network error - return empty list
        pass
    except Exception as e:
        # Other errors - return empty list
        pass
    
    return cves


def correlate_vulnerabilities(nmap_data: Dict) -> Dict[str, Any]:
    """
    Correlate nmap service data with vulnerability databases.
    
    Args:
        nmap_data: Parsed nmap scan results
    
    Returns:
        Dict with vulnerability correlations per service
    """
    results = {
        "total_cves_found": 0,
        "high_severity_count": 0,
        "critical_severity_count": 0,
        "services_with_cves": [],
        "summary": []
    }
    
    for host in nmap_data.get("hosts", []):
        host_ip = host.get("addresses", [{}])[0].get("addr", "Unknown")
        
        for port in host.get("ports", []):
            service = port.get("service", {})
            product = service.get("product")
            version = service.get("version")
            port_num = port.get("portid", port.get("port"))
            
            if not product:
                continue
            
            # Search for CVEs
            cves = search_cve_by_keyword(product, version, max_results=5)
            
            if cves:
                service_vuln = {
                    "host": host_ip,
                    "port": port_num,
                    "service": service.get("name", "unknown"),
                    "product": product,
                    "version": version or "unknown",
                    "cves": cves
                }
                
                results["services_with_cves"].append(service_vuln)
                results["total_cves_found"] += len(cves)
                
                # Count severity
                for cve in cves:
                    severity = cve.get("severity", "").upper()
                    if severity == "HIGH":
                        results["high_severity_count"] += 1
                    elif severity == "CRITICAL":
                        results["critical_severity_count"] += 1
    
    # Generate summary
    if results["total_cves_found"] > 0:
        results["summary"].append(f"Found {results['total_cves_found']} potential vulnerabilities")
        
        if results["critical_severity_count"] > 0:
            results["summary"].append(f"[CRITICAL] {results['critical_severity_count']} CRITICAL severity")
        
        if results["high_severity_count"] > 0:
            results["summary"].append(f"[!]  {results['high_severity_count']} HIGH severity")
        
        results["summary"].append(f"Vulnerable services: {len(results['services_with_cves'])}")
    else:
        results["summary"].append("No known CVEs found for discovered services")
    
    return results
