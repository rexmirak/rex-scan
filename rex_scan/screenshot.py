"""Screenshot capture for web services

Captures screenshots of web applications for visual confirmation.
"""
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List
import time


def check_playwright() -> bool:
    """Check if playwright is installed."""
    try:
        import playwright
        return True
    except ImportError:
        return False


def check_chromium() -> bool:
    """Check if chromium browser is available."""
    return shutil.which("chromium") is not None or shutil.which("chromium-browser") is not None


def capture_screenshot_playwright(url: str, output_path: str, width: int = 1920, height: int = 1080, timeout: int = 30) -> bool:
    """
    Capture screenshot using Playwright.
    
    Args:
        url: Target URL
        output_path: Path to save screenshot
        width: Viewport width
        height: Viewport height
        timeout: Page load timeout
    
    Returns:
        True if successful
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            # Launch browser
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            
            # Create context with custom viewport
            context = browser.new_context(
                viewport={'width': width, 'height': height},
                ignore_https_errors=True
            )
            
            # Create page
            page = context.new_page()
            
            # Navigate to URL
            page.goto(url, timeout=timeout * 1000, wait_until='networkidle')
            
            # Wait a bit for dynamic content
            time.sleep(2)
            
            # Take screenshot
            page.screenshot(path=output_path, full_page=True)
            
            # Cleanup
            browser.close()
            
            return True
    
    except ImportError:
        return False
    except Exception as e:
        print(f"Screenshot failed for {url}: {e}")
        return False


def capture_screenshot_cutycapt(url: str, output_path: str, width: int = 1920, height: int = 1080) -> bool:
    """
    Capture screenshot using CutyCapt (fallback).
    
    Args:
        url: Target URL
        output_path: Path to save screenshot
        width: Viewport width
        height: Viewport height
    
    Returns:
        True if successful
    """
    if not shutil.which("cutycapt"):
        return False
    
    try:
        cmd = [
            "cutycapt",
            f"--url={url}",
            f"--out={output_path}",
            f"--min-width={width}",
            f"--min-height={height}",
            "--delay=2000"
        ]
        
        subprocess.run(cmd, check=True, timeout=60, capture_output=True)
        return True
    
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def capture_screenshot(url: str, output_path: str, width: int = 1920, height: int = 1080, timeout: int = 30) -> bool:
    """
    Capture screenshot using available tool.
    
    Args:
        url: Target URL
        output_path: Path to save screenshot
        width: Viewport width
        height: Viewport height
        timeout: Timeout in seconds
    
    Returns:
        True if successful
    """
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Try Playwright first (best quality)
    if check_playwright():
        if capture_screenshot_playwright(url, output_path, width, height, timeout):
            return True
    
    # Fallback to CutyCapt
    if capture_screenshot_cutycapt(url, output_path, width, height):
        return True
    
    return False


def capture_http_screenshots(nmap_data: dict, output_dir: Path, width: int = 1920, height: int = 1080) -> dict:
    """
    Capture screenshots for all HTTP/HTTPS services.
    
    Args:
        nmap_data: Parsed nmap results
        output_dir: Directory to save screenshots
        width: Viewport width
        height: Viewport height
    
    Returns:
        Dict mapping URLs to screenshot paths
    """
    screenshots = {}
    
    for host in nmap_data.get("hosts", []):
        ip = host.get("addresses", [{}])[0].get("addr", "unknown")
        
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            
            service = port.get("service", {})
            service_name = service.get("name", "").lower()
            port_num = port.get("portid", port.get("port"))
            
            # Check if HTTP/HTTPS service
            is_http = service_name in ("http", "https", "http-alt", "http-proxy", "ssl/http")
            is_http = is_http or port_num in (80, 443, 8080, 8000, 8443)
            
            if not is_http:
                continue
            
            # Determine protocol
            protocol = "https" if ("ssl" in service_name or service_name == "https" or port_num in (443, 8443)) else "http"
            
            # Build URL
            url = f"{protocol}://{ip}:{port_num}"
            
            # Generate screenshot filename
            safe_url = url.replace("://", "_").replace("/", "_").replace(":", "_")
            screenshot_path = output_dir / f"{safe_url}.png"
            
            print(f"[*] Capturing screenshot: {url}")
            
            if capture_screenshot(url, str(screenshot_path), width, height):
                screenshots[url] = str(screenshot_path)
                print(f"[[+]] Screenshot saved: {screenshot_path.name}")
            else:
                print(f"[[X]] Screenshot failed: {url}")
    
    return screenshots


def install_playwright():
    """Install Playwright and browser dependencies."""
    try:
        print("[*] Installing Playwright...")
        subprocess.run(["pip", "install", "playwright"], check=True)
        
        print("[*] Installing Playwright browsers...")
        subprocess.run(["playwright", "install", "chromium"], check=True)
        
        print("[[+]] Playwright installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[[X]] Failed to install Playwright: {e}")
        return False
