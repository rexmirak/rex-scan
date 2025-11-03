"""Advanced web enumeration module

Performs comprehensive web application analysis:
- SSL/TLS certificate analysis
- HTTP security header analysis
- Technology detection
- CMS detection
"""
import ssl
import socket
import requests
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse
import re


def analyze_ssl_certificate(host: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Analyze SSL/TLS certificate.
    
    Args:
        host: Target hostname
        port: HTTPS port
        timeout: Connection timeout
    
    Returns:
        Dict with certificate information
    """
    result = {
        "host": host,
        "port": port,
        "valid": False,
        "expired": False,
        "self_signed": False,
        "subject": {},
        "issuer": {},
        "not_before": None,
        "not_after": None,
        "san": [],
        "errors": []
    }
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                # Extract subject
                subject = dict(x[0] for x in cert.get('subject', ()))
                result["subject"] = subject
                
                # Extract issuer
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                result["issuer"] = issuer
                
                # Check if self-signed
                result["self_signed"] = (subject.get('commonName') == issuer.get('commonName'))
                
                # Extract dates
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                
                if not_before:
                    result["not_before"] = not_before
                if not_after:
                    result["not_after"] = not_after
                    
                    # Check if expired
                    try:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        result["expired"] = expire_date < datetime.now()
                    except:
                        pass
                
                # Extract Subject Alternative Names (SAN)
                san = cert.get('subjectAltName', ())
                result["san"] = [x[1] for x in san if x[0] == 'DNS']
                
                result["valid"] = True
    
    except ssl.SSLError as e:
        result["errors"].append(f"SSL error: {str(e)}")
    except socket.timeout:
        result["errors"].append(f"Connection timed out")
    except Exception as e:
        result["errors"].append(f"Certificate analysis failed: {str(e)}")
    
    return result


def analyze_security_headers(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Analyze HTTP security headers.
    
    Args:
        url: Target URL
        timeout: Request timeout
    
    Returns:
        Dict with security header analysis
    """
    result = {
        "url": url,
        "headers": {},
        "missing_headers": [],
        "security_score": 0,
        "recommendations": [],
        "errors": []
    }
    
    # Security headers to check
    security_headers = {
        "Strict-Transport-Security": "HSTS not enabled - allows downgrade attacks",
        "X-Frame-Options": "Clickjacking protection missing",
        "X-Content-Type-Options": "MIME sniffing protection missing",
        "Content-Security-Policy": "CSP not configured - XSS risk",
        "X-XSS-Protection": "XSS filter not enabled",
        "Referrer-Policy": "Referrer policy not configured",
        "Permissions-Policy": "Permissions policy not configured"
    }
    
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        
        # Check each security header
        for header, message in security_headers.items():
            value = response.headers.get(header)
            if value:
                result["headers"][header] = value
                result["security_score"] += 1
            else:
                result["missing_headers"].append(header)
                result["recommendations"].append(message)
        
        # Check for information disclosure headers
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
        for header in disclosure_headers:
            value = response.headers.get(header)
            if value:
                result["headers"][header] = value
                result["recommendations"].append(f"Information disclosure: {header} reveals {value}")
        
        # Calculate percentage score
        total_checks = len(security_headers)
        result["security_score"] = int((result["security_score"] / total_checks) * 100)
    
    except requests.exceptions.Timeout:
        result["errors"].append("Request timed out")
    except Exception as e:
        result["errors"].append(f"Header analysis failed: {str(e)}")
    
    return result


def detect_technology(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Detect web technologies (Wappalyzer-style).
    
    Args:
        url: Target URL
        timeout: Request timeout
    
    Returns:
        Dict with detected technologies
    """
    result = {
        "url": url,
        "technologies": [],
        "errors": []
    }
    
    # Technology signatures
    signatures = {
        # Frameworks
        "WordPress": [r'wp-content', r'wp-includes', r'wordpress'],
        "Joomla": [r'Joomla', r'com_content', r'joomla'],
        "Drupal": [r'Drupal', r'drupal.js', r'sites/all'],
        "Django": [r'csrfmiddlewaretoken', r'__admin'],
        "Ruby on Rails": [r'csrf-token', r'rails'],
        "Laravel": [r'laravel', r'laravel_session'],
        "Angular": [r'ng-app', r'ng-controller', r'angular'],
        "React": [r'react', r'_reactRoot'],
        "Vue.js": [r'vue', r'v-app'],
        
        # Servers
        "nginx": [r'nginx'],
        "Apache": [r'Apache'],
        "IIS": [r'Microsoft-IIS', r'ASP.NET'],
        
        # CMS
        "Shopify": [r'cdn.shopify', r'shopify'],
        "Magento": [r'Magento', r'mage'],
        "Wix": [r'wix.com', r'wixstatic'],
        
        # Frameworks/Libraries
        "jQuery": [r'jquery', r'jQuery'],
        "Bootstrap": [r'bootstrap', r'Bootstrap'],
        "Font Awesome": [r'font-awesome', r'fontawesome']
    }
    
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        content = response.text.lower()
        headers_str = str(response.headers).lower()
        
        # Check signatures
        for tech, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern.lower(), content) or re.search(pattern.lower(), headers_str):
                    if tech not in result["technologies"]:
                        result["technologies"].append(tech)
                    break
    
    except Exception as e:
        result["errors"].append(f"Technology detection failed: {str(e)}")
    
    return result


def detect_cms(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Detect Content Management System.
    
    Args:
        url: Target URL
        timeout: Request timeout
    
    Returns:
        Dict with CMS detection results
    """
    result = {
        "url": url,
        "cms": None,
        "version": None,
        "confidence": "low",
        "indicators": [],
        "errors": []
    }
    
    # CMS detection patterns
    cms_patterns = {
        "WordPress": {
            "paths": ["/wp-admin", "/wp-login.php", "/wp-content"],
            "headers": ["X-Powered-By: WordPress"],
            "meta": ["WordPress"],
            "version_regex": r'WordPress\s+([\d.]+)'
        },
        "Joomla": {
            "paths": ["/administrator", "/components", "/modules"],
            "headers": [],
            "meta": ["Joomla"],
            "version_regex": r'Joomla!\s+([\d.]+)'
        },
        "Drupal": {
            "paths": ["/core", "/sites/default", "/modules"],
            "headers": ["X-Generator: Drupal"],
            "meta": ["Drupal"],
            "version_regex": r'Drupal\s+([\d.]+)'
        }
    }
    
    try:
        # Check main page
        response = requests.get(url, timeout=timeout, verify=False)
        content = response.text
        headers = response.headers
        
        for cms_name, patterns in cms_patterns.items():
            score = 0
            indicators = []
            
            # Check paths
            for path in patterns["paths"]:
                try:
                    test_url = url.rstrip('/') + path
                    test_resp = requests.head(test_url, timeout=5, verify=False)
                    if test_resp.status_code in [200, 301, 302]:
                        score += 1
                        indicators.append(f"Found {path}")
                except:
                    pass
            
            # Check headers
            for header_pattern in patterns["headers"]:
                if header_pattern.lower() in str(headers).lower():
                    score += 2
                    indicators.append(f"Header: {header_pattern}")
            
            # Check meta tags
            for meta_pattern in patterns["meta"]:
                if meta_pattern.lower() in content.lower():
                    score += 2
                    indicators.append(f"Meta: {meta_pattern}")
            
            # If we have matches
            if score > 0:
                result["cms"] = cms_name
                result["indicators"] = indicators
                
                # Try to detect version
                version_match = re.search(patterns["version_regex"], content, re.IGNORECASE)
                if version_match:
                    result["version"] = version_match.group(1)
                
                # Set confidence
                if score >= 4:
                    result["confidence"] = "high"
                elif score >= 2:
                    result["confidence"] = "medium"
                else:
                    result["confidence"] = "low"
                
                break  # Found CMS, stop checking
    
    except Exception as e:
        result["errors"].append(f"CMS detection failed: {str(e)}")
    
    return result


def enumerate_web_advanced(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Comprehensive web application enumeration.
    
    Args:
        url: Target URL
        timeout: Request timeout (seconds)
    
    Returns:
        Dict with all web enumeration results
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    results = {
        "url": url,
        "ssl_certificate": {},
        "security_headers": {},
        "technologies": [],
        "cms": {},
        "summary": []
    }
    
    # SSL certificate analysis (HTTPS only)
    if parsed.scheme == 'https':
        results["ssl_certificate"] = analyze_ssl_certificate(host, port, timeout)
        
        if results["ssl_certificate"].get("expired"):
            results["summary"].append("[!]  SSL certificate expired")
        if results["ssl_certificate"].get("self_signed"):
            results["summary"].append("[!]  Self-signed certificate")
    
    # Security headers
    results["security_headers"] = analyze_security_headers(url, timeout)
    score = results["security_headers"].get("security_score", 0)
    results["summary"].append(f"Security header score: {score}%")
    
    # Technology detection
    tech_result = detect_technology(url, timeout)
    results["technologies"] = tech_result.get("technologies", [])
    if results["technologies"]:
        results["summary"].append(f"Detected {len(results['technologies'])} technologies")
    
    # CMS detection
    results["cms"] = detect_cms(url, timeout)
    if results["cms"].get("cms"):
        cms_name = results["cms"]["cms"]
        version = results["cms"].get("version", "unknown")
        results["summary"].append(f"CMS: {cms_name} {version}")
    
    return results
