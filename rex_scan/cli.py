#!/usr/bin/env python3
import argparse
import sys
import textwrap
import logging
import signal
from pathlib import Path
from datetime import datetime

# Core imports
from .utils import check_tool, default_desktop_path, ensure_output_path
from .nmap_runner import run_nmap
from .nmap_parser import parse_nmap_xml
from . import config

# Optional imports with graceful degradation
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    tqdm = None

try:
    import matplotlib
    import plotly
    HAS_CHARTS = True
except ImportError:
    HAS_CHARTS = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = False
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Feature modules (check availability)
try:
    from .target_parser import parse_and_validate_targets
    HAS_TARGET_PARSER = True
except ImportError:
    HAS_TARGET_PARSER = False

try:
    from .rate_limiter import RateLimiter
    HAS_RATE_LIMITER = True
except ImportError:
    HAS_RATE_LIMITER = False

try:
    from .scan_state import ScanState
    HAS_SCAN_STATE = True
except ImportError:
    HAS_SCAN_STATE = False

try:
    from .wordlist_manager import WordlistManager
    HAS_WORDLIST_MANAGER = True
except ImportError:
    HAS_WORDLIST_MANAGER = False

try:
    from .advanced_web_enum import enumerate_web_advanced
    HAS_ADVANCED_WEB = True
except ImportError:
    HAS_ADVANCED_WEB = False

try:
    from .screenshot import capture_screenshot
    HAS_SCREENSHOT = True
except ImportError:
    HAS_SCREENSHOT = False

try:
    from .chart_generator import generate_all_charts
    HAS_CHART_GEN = True
except ImportError:
    HAS_CHART_GEN = False

try:
    from .diff_scanner import compare_scans
    HAS_DIFF_SCANNER = True
except ImportError:
    HAS_DIFF_SCANNER = False

BANNER = r"""
         _               _        _      _                _                  _               _                   _          
        /\ \            /\ \    /_/\    /\ \             / /\              /\ \             / /\                /\ \     _  
       /  \ \          /  \ \   \ \ \   \ \_\           / /  \            /  \ \           / /  \              /  \ \   /\_\
      / /\ \ \        / /\ \ \   \ \ \__/ / /          / / /\ \__        / /\ \ \         / / /\ \            / /\ \ \_/ / /
     / / /\ \_\      / / /\ \_\   \ \__ \/_/          / / /\ \___\      / / /\ \ \       / / /\ \ \          / / /\ \___/ / 
    / / /_/ / /     / /_/_ \/_/    \/_/\__/\          \ \ \ \/___/     / / /  \ \_\     / / /  \ \ \        / / /  \/____/  
   / / /__\/ /     / /____/\        _/\/__\ \          \ \ \          / / /    \/_/    / / /___/ /\ \      / / /    / / /   
  / / /_____/     / /\____\/       / _/_/\ \ \     _    \ \ \        / / /            / / /_____/ /\ \    / / /    / / /    
 / / /\ \ \      / / /______      / / /   \ \ \   /_/\__/ / /       / / /________    / /_________/\ \ \  / / /    / / /     
/ / /  \ \ \    / / /_______\    / / /    /_/ /   \ \/___/ /       / / /_________\  / / /_       __\ \_\/ / /    / / /      
\/_/    \_\/    \/__________/    \/_/     \_\/     \_____\/        \/____________/  \_\___\     /____/_/\/_/     \/_/       
                                                                                                                                                                                                                       
        REX SCAN: TOOL OF TOOLS FOR ULTIMATE PENTESTING
"""

# Global state for graceful shutdown
_scan_state = {
    "interrupted": False,
    "partial_data": {},
    "output_base": None
}

def signal_handler(signum, frame):
    """Handle Ctrl-C gracefully and save partial results."""
    global _scan_state
    if _scan_state["interrupted"]:
        print("\n\n[!] Force quit - exiting without saving")
        sys.exit(130)
    
    _scan_state["interrupted"] = True
    print("\n\n[!] Scan interrupted (Ctrl-C detected)")
    print("[*] Saving partial results...")
    
    # Save partial results if we have any data
    if _scan_state["partial_data"] and _scan_state["output_base"]:
        try:
            from .report import generate_text_report, generate_json_report
            output_base = _scan_state["output_base"]
            data = _scan_state["partial_data"]
            
            # Create REX_REPORTS directory
            reports_dir = Path(output_base) / "REX_REPORTS"
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Save partial reports
            text_path = reports_dir / "partial_report.txt"
            json_path = reports_dir / "partial_report.json"
            
            generate_text_report(data, str(text_path))
            generate_json_report(data, str(json_path))
            
            print(f"[*] Partial results saved to {reports_dir}")
            print(f"    - {text_path.name}")
            print(f"    - {json_path.name}")
        except Exception as e:
            print(f"[!] Failed to save partial results: {e}")
    
    print("[*] Exiting...")
    sys.exit(130)

# Scan profile configurations
SCAN_PROFILES = {
    "stealth": {
        "nmap_timing": "T0",
        "nmap_extra": "-sS -f --randomize-hosts --data-length 24",
        "description": "Slow, evasive scanning with packet fragmentation"
    },
    "balanced": {
        "nmap_timing": "T3",
        "nmap_extra": "-sV",
        "description": "Default safe scanning with service detection"
    },
    "aggressive": {
        "nmap_timing": "T4",
        "nmap_extra": "-sV -A --version-all -p-",
        "description": "Fast comprehensive scan of all ports"
    },
    "quick": {
        "nmap_timing": "T4",
        "nmap_extra": "-sV --top-ports 100",
        "description": "Fast scan of top 100 common ports"
    },
    "full": {
        "nmap_timing": "T4",
        "nmap_extra": "-sV -A -p-",
        "description": "Complete scan of all 65535 ports with OS detection"
    },
    "custom": {
        "nmap_timing": "",
        "nmap_extra": "",
        "description": "Custom nmap flags via --nmap-flags"
    }
}


def parse_args():
    epilog = """
╔═══════════════════════════════════════════════════════════════════════════╗
║           REX SCAN: TOOL OF TOOLS FOR ULTIMATE PENTESTING                ║
║                                                                           ║
║  The ultimate network reconnaissance framework combining industry        ║
║  tools with advanced enumeration for complete penetration testing.      ║
╚═══════════════════════════════════════════════════════════════════════════╝

WHAT IS REX SCAN?
  REX SCAN is the complete penetration testing automation framework that
  combines nmap, searchsploit, gobuster with 13+ custom modules for
  comprehensive network reconnaissance and vulnerability assessment.

KEY FEATURES:
  • Network Reconnaissance (nmap) - Service detection & OS fingerprinting
  • Exploit Database Lookup       - Automatic searchsploit integration
  • SMB/SSH/Web Enumeration       - Deep service analysis
  • Vulnerability Correlation     - CVE database cross-referencing with CVSS
  • Credential Testing            - FTP, HTTP, SSH authentication checks
  • DNS Enumeration               - Subdomain discovery and zone transfers
  • Directory Bruteforcing        - Web path discovery with gobuster
  • Multi-Format Reports          - Text, JSON, HTML with beautiful formatting

SCAN PROFILES:
  --profile stealth      - Slow, evasive scanning (T0, packet fragmentation)
  --profile balanced     - Default safe scanning (T3, standard timing)
  --profile aggressive   - Fast comprehensive scan (T4, all 65535 ports)
  --profile quick        - Fast scan of top 100 common ports (T4)
  --profile full         - Complete scan of all ports with OS detection (T4, -A, -p-)
  --profile custom       - Use with --nmap-flags for complete control

CUSTOM NMAP FLAGS:
  Use --nmap-flags to pass any nmap arguments directly:
    rex_scan --target 192.168.1.100 --profile custom --nmap-flags "-sS -T5 -p- -A -v"
    rex_scan --target 192.168.1.100 --nmap-flags "-sU -p 53,161" --sudo-password <pass>

OUTPUT ORGANIZATION:
  Each scan creates: <TARGET>_<TIMESTAMP>/
    ├── REX_REPORTS/            - Consolidated reports
    │   ├── report.txt          - Human-readable summary
    │   ├── report.json         - Structured data
    │   └── report.html         - Interactive web report
    └── INDIVIDUAL/             - Per-tool outputs
        ├── nmap.xml            - Nmap results
        ├── credentials.json    - Credential attempts
        ├── vulnerabilities.json - CVE correlation results
        └── ...                 - All enumeration data

EXAMPLES:
  # Basic scan
  rex_scan --target 192.168.1.100 --consent

  # Scan with custom ports and profile
  rex_scan --target example.com --consent --profile aggressive --ports 1-10000

  # Quick scan of common ports
  rex_scan --target 192.168.1.100 --consent --profile quick

  # Full scan with all ports
  rex_scan --target 192.168.1.100 --consent --profile full --sudo-password <pass>

  # Custom nmap flags for granular control
  rex_scan --target 192.168.1.100 --consent --profile custom --nmap-flags "-sS -T5 -p- -A -v" --sudo-password <pass>

  # DNS and directory enumeration
  rex_scan --target example.com --consent --dns-wordlist wordlist.txt --dir-wordlist dirs.txt

  # Custom output location
  rex_scan --target 192.168.1.100 --consent --output /path/to/output

BEST PRACTICES:
  • Always obtain written authorization before scanning
  • Use --profile stealth for evasive scanning
  • Provide wordlists for DNS/directory enumeration
  • Review HTML reports for best visualization

LEGAL & ETHICS:
  WARNING: Unauthorized scanning may be ILLEGAL in your jurisdiction.
  Only scan systems you own or have explicit written permission to test.
  Users are solely responsible for compliance with applicable laws.

REQUIRED TOOLS:
  Core: nmap, searchsploit
  Optional: gobuster, dig, smbclient, ssh-audit, playwright
  Install: bash install_tools.sh

For more: https://github.com/yourusername/rex_scan
    """
    
    p = argparse.ArgumentParser(
        prog="rex_scan",
        description="REX SCAN: Tool of Tools for Ultimate Pentesting - Complete Network Reconnaissance Framework",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target specification
    p.add_argument("--target", "-t", help="Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)", required=False)
    p.add_argument("--targets", help="Multiple targets from file (prefix with @, e.g., @targets.txt)", default="")
    p.add_argument("--ports", "-p", help="Port range or list (e.g., '80,443' or '1-1000')", default="")
    
    # Scan profiles
    p.add_argument("--profile", choices=["stealth", "balanced", "aggressive", "quick", "full", "custom"], 
                   default="balanced", help="Scan profile: stealth (T0), balanced (T3), aggressive (T4 all ports), quick (top 100), full (T4 all ports -A), custom (use --nmap-flags)")
    
    # Timeouts
    p.add_argument("--timeout", type=int, help="Global timeout in seconds (default: 30)", default=30)
    p.add_argument("--http-timeout", type=int, help="HTTP request timeout (default: 10)", default=10)
    p.add_argument("--ssh-timeout", type=int, help="SSH connection timeout (default: 10)", default=10)
    p.add_argument("--smb-timeout", type=int, help="SMB connection timeout (default: 10)", default=10)
    
    # Rate limiting
    p.add_argument("--rate-limit", type=float, help="Max requests per second (default: 10)", default=10)
    p.add_argument("--delay", type=float, help="Additional delay between requests in seconds", default=0)
    
    # Resume and diff
    p.add_argument("--resume", help="Resume interrupted scan from folder path", default="")
    p.add_argument("--diff", nargs=2, metavar=("SCAN1", "SCAN2"), help="Compare two scan reports")
    
    # Wordlist management
    p.add_argument("--download-wordlists", action="store_true", help="Download common wordlists")
    p.add_argument("--manage-wordlists", action="store_true", help="Launch wordlist manager")
    
    # Nmap options
    p.add_argument("--nmap-timing", help="Override nmap timing template (T0-T5)", default="")
    p.add_argument("--nmap-flags", help="Custom nmap flags (e.g., '-sS -T5 -p- -A -v'). Overrides profile settings.", default="")
    p.add_argument("--sudo-password", help="Password for sudo to run privileged scans (nmap -sS)", default="")
    
    # Enumeration options
    p.add_argument("--dns-wordlist", help="Path to DNS subdomain wordlist (use 'auto' for default, 'none' to disable)", default="auto")
    p.add_argument("--dns-server", help="Custom DNS server for lookups", default="")
    p.add_argument("--dns-over-https", action="store_true", help="Use DNS-over-HTTPS for stealth")
    p.add_argument("--dir-wordlist", help="Path to directory enumeration wordlist (use 'auto' for default, 'none' to disable)", default="auto")
    p.add_argument("--dir-extensions", help="File extensions for directory enum (comma-separated)", default="")
    
    # Advanced features
    p.add_argument("--screenshots", action="store_true", default=True, help="Capture screenshots of web services (default: enabled, use --no-screenshots to disable)")
    p.add_argument("--no-screenshots", action="store_true", help="Disable screenshot capture")
    p.add_argument("--charts", action="store_true", default=True, help="Generate visual charts in reports (default: enabled, use --no-charts to disable)")
    p.add_argument("--no-charts", action="store_true", help="Disable chart generation")
    p.add_argument("--advanced-web", action="store_true", help="Enable advanced web enumeration (SSL, headers, tech)")
    
    # Output options
    p.add_argument("--output", "-o", help="Custom output base path (default: Desktop/<target>_<timestamp>)", default="")
    
    # Behavior flags
    p.add_argument("--consent", action="store_true", help="Confirm authorization to scan target")
    p.add_argument("--non-interactive", action="store_true", help="Skip all prompts (use with --yes)")
    p.add_argument("--no-creds", action="store_true", help="Disable credential testing")
    p.add_argument("--no-smb", action="store_true", help="Disable SMB enumeration")
    p.add_argument("--no-ssh", action="store_true", help="Disable SSH enumeration")
    p.add_argument("--no-vulns", action="store_true", help="Disable vulnerability correlation")
    p.add_argument("--yes", "-y", action="store_true", help="Auto-accept all prompts")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress verbose output")
    p.add_argument("--continue-on-error", action="store_true", help="Continue scan even if modules fail")
    p.add_argument("--max-targets", type=int, help="Maximum number of targets to scan", default=256)
    
    return p.parse_args()


def preflight_checks():
    missing = []
    for t in ("nmap",):
        if not check_tool(t):
            missing.append(t)
    return missing


def check_dependencies(args):
    """Check for missing optional dependencies based on requested features."""
    missing = []
    
    if args.screenshots and not HAS_SCREENSHOT:
        missing.append("playwright (for screenshots)")
    if args.charts and not HAS_CHART_GEN:
        missing.append("matplotlib, plotly (for charts)")
    if args.diff and not HAS_DIFF_SCANNER:
        missing.append("pandas (for diff mode)")
    if args.rate_limit and not HAS_RATE_LIMITER:
        missing.append("aiohttp (for rate limiting)")
    
    if missing:
        print(f"\n[!] Missing optional dependencies for requested features:")
        for dep in missing:
            print(f"    - {dep}")
        print(f"\nInstall with: pip install -r requirements.txt")
        print(f"Or: pip install {' '.join([d.split('(')[0].strip() for d in missing])}")
        return False
    return True


def main():
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    args = parse_args()
    print(BANNER)

    # setup logging (verbose by default)
    log_level = logging.INFO if not args.quiet else logging.WARNING
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")
    logger = logging.getLogger("rex_scan")
    
    # Handle special modes first
    
    # Diff mode - compare two scans and exit
    if args.diff:
        if not HAS_DIFF_SCANNER:
            logger.error("Diff mode requires pandas. Install with: pip install pandas")
            sys.exit(1)
        try:
            logger.info("Comparing scans...")
            diff_results = compare_scans(args.diff[0], args.diff[1])
            print("\n" + "="*60)
            print("SCAN COMPARISON RESULTS")
            print("="*60)
            print(diff_results)
            sys.exit(0)
        except Exception as e:
            logger.error(f"Diff comparison failed: {e}")
            sys.exit(1)
    
    # Wordlist download mode
    if args.download_wordlists:
        if not HAS_WORDLIST_MANAGER:
            logger.error("Wordlist manager not available")
            sys.exit(1)
        try:
            logger.info("Downloading wordlists...")
            wm = WordlistManager()
            wm.download_seclists()
            wm.download_common_wordlists()
            logger.info("Wordlists downloaded successfully")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Wordlist download failed: {e}")
            sys.exit(1)
    
    # Resume mode
    if args.resume:
        if not HAS_SCAN_STATE:
            logger.error("Resume capability not available")
            sys.exit(1)
        try:
            logger.info(f"Resuming scan from: {args.resume}")
            scan_state = ScanState.load(args.resume)
            args.target = scan_state.target
            logger.info(f"Resuming scan for target: {args.target}")
        except Exception as e:
            logger.error(f"Failed to resume scan: {e}")
            sys.exit(1)
    
    # Check dependencies for requested features
    if not check_dependencies(args):
        if not args.continue_on_error:
            sys.exit(1)
    
    # Handle negation flags
    if args.no_screenshots:
        args.screenshots = False
    if args.no_charts:
        args.charts = False
    
    # Handle wordlist 'none' option
    if args.dns_wordlist == 'none':
        args.dns_wordlist = ""
    if args.dir_wordlist == 'none':
        args.dir_wordlist = ""
    
    # Get scan profile configuration
    profile = SCAN_PROFILES.get(args.profile, SCAN_PROFILES["balanced"])
    logger.info(f"Starting REX SCAN with profile: {args.profile.upper()}")
    logger.info(f"Profile: {profile['description']}")

    # Parse targets (single target, CIDR, file, or multi-target)
    targets = []
    if args.targets:
        if not HAS_TARGET_PARSER:
            logger.error("Multi-target support not available")
            sys.exit(1)
        try:
            targets = parse_and_validate_targets(args.targets, max_targets=args.max_targets)
            logger.info(f"Parsed {len(targets)} targets from {args.targets}")
        except Exception as e:
            logger.error(f"Failed to parse targets: {e}")
            sys.exit(1)
    elif args.target:
        # Single target, CIDR, IP range, or comma-separated
        if HAS_TARGET_PARSER and ('/' in args.target or '-' in args.target or ',' in args.target):
            try:
                targets = parse_and_validate_targets(args.target, max_targets=args.max_targets)
                logger.info(f"Parsed {len(targets)} targets from range")
            except Exception as e:
                logger.warning(f"Failed to parse as range, treating as single target: {e}")
                targets = [args.target]
        else:
            targets = [args.target]
    else:
        # Interactive mode
        if not args.non_interactive:
            try:
                target = input("Target IP or hostname: ").strip()
                targets = [target]
            except KeyboardInterrupt:
                print("\nCancelled")
                sys.exit(1)
        else:
            print("No target provided. Use --target or run interactively.")
            sys.exit(1)
    
    if not targets:
        print("No valid targets found. Exiting.")
        sys.exit(1)

    # consent check
    if not args.consent:
        if args.non_interactive or args.yes:
            print("Missing --consent. For automation you must pass --consent to confirm authorization.")
            sys.exit(2)
        else:
            ans = input(f"Do you have authorization to scan {len(targets)} target(s)? (yes/no): ").strip().lower()
            if ans not in ("y", "yes"):
                print("Consent not given. Exiting.")
                sys.exit(2)

    # preflight
    missing = preflight_checks()
    if missing:
        logger.warning("The following required tools are missing: %s", ", ".join(missing))
        logger.warning("Install them with: bash install_tools.sh")
        sys.exit(3)

    # Initialize rate limiter if enabled
    rate_limiter = None
    if args.rate_limit and HAS_RATE_LIMITER:
        rate_limiter = RateLimiter(rate=args.rate_limit)
        logger.info(f"Rate limiting enabled: {args.rate_limit} requests/sec")
    
    # Initialize wordlist manager for auto wordlists
    wordlist_manager = None
    if HAS_WORDLIST_MANAGER and (args.dns_wordlist == 'auto' or args.dir_wordlist == 'auto'):
        wordlist_manager = WordlistManager()
        if args.dns_wordlist == 'auto':
            args.dns_wordlist = wordlist_manager.get_default_dns_wordlist()
            logger.info(f"Using auto DNS wordlist: {args.dns_wordlist}")
        if args.dir_wordlist == 'auto':
            args.dir_wordlist = wordlist_manager.get_default_dir_wordlist()
            logger.info(f"Using auto directory wordlist: {args.dir_wordlist}")
    
    # Update config with CLI arguments
    config.TIMEOUTS['global'] = args.timeout
    config.TIMEOUTS['http'] = args.http_timeout
    config.TIMEOUTS['https'] = args.http_timeout
    config.TIMEOUTS['ssh'] = args.ssh_timeout
    config.TIMEOUTS['smb'] = args.smb_timeout
    config.DNS['use_doh'] = args.dns_over_https
    if args.dns_server:
        config.DNS['custom_server'] = args.dns_server
    config.SCREENSHOTS['enabled'] = args.screenshots
    config.ERROR_RECOVERY['continue_on_error'] = args.continue_on_error
    
    # Enable credential testing
    creds_enabled = not args.no_creds

    logger.info("="*60)
    logger.info(f"Starting scan of {len(targets)} target(s)")
    logger.info("="*60)
    
    # Scan all targets
    all_results = []
    progress_bar = None
    if HAS_TQDM and not args.quiet:
        progress_bar = tqdm(total=len(targets), desc="Scanning targets", unit="target")
    
    for target_idx, target in enumerate(targets):
        try:
            logger.info(f"\n{'='*60}")
            logger.info(f"Target {target_idx + 1}/{len(targets)}: {target}")
            logger.info(f"{'='*60}")
            
            # Scan single target
            result = scan_single_target(
                target=target,
                args=args,
                profile=profile,
                creds_enabled=creds_enabled,
                rate_limiter=rate_limiter,
                logger=logger
            )
            all_results.append(result)
            
            if progress_bar:
                progress_bar.update(1)
                
        except Exception as e:
            logger.error(f"Failed to scan {target}: {e}")
            if not args.continue_on_error:
                if progress_bar:
                    progress_bar.close()
                raise
            else:
                logger.warning(f"Continuing to next target due to --continue-on-error")
                continue
    
    if progress_bar:
        progress_bar.close()
    
    logger.info("="*60)
    logger.info("All scans complete!")
    logger.info("="*60)


def scan_single_target(target, args, profile, creds_enabled, rate_limiter, logger):
    """Scan a single target and return results."""

    # Create organized output structure: <target>_<timestamp>/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    
    if args.output:
        scan_folder = Path(args.output)
    else:
        desktop = Path.home() / "Desktop"
        scan_folder = desktop / f"{safe_target}_{timestamp}"
    
    # Create directory structure
    scan_folder.mkdir(parents=True, exist_ok=True)
    reports_dir = scan_folder / "REX_REPORTS"
    individual_dir = scan_folder / "INDIVIDUAL"
    reports_dir.mkdir(exist_ok=True)
    individual_dir.mkdir(exist_ok=True)
    
    # Set global state for signal handler
    global _scan_state
    _scan_state["output_base"] = scan_folder
    _scan_state["partial_data"] = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "profile": args.profile,
        "nmap": {},
        "exploits": [],
        "credentials": [],
        "dns_enumeration": {},
        "directory_enumeration": {},
        "smb_enumeration": {},
        "ssh_enumeration": {},
        "vulnerabilities": [],
        "advanced_web": {},
        "screenshots": []
    }
    
    # Create screenshots directory if enabled
    screenshots_dir = None
    if args.screenshots and HAS_SCREENSHOT:
        screenshots_dir = individual_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)
    
    # Create charts directory if enabled
    charts_dir = None
    if args.charts and HAS_CHART_GEN:
        charts_dir = reports_dir / "charts"
        charts_dir.mkdir(exist_ok=True)
    
    # Initialize scan state for resume capability
    scan_state = None
    if HAS_SCAN_STATE:
        scan_state = ScanState(scan_folder, target)
        scan_state.save_state(force=True)
    
    logger.info(f"Scan folder: {scan_folder}")
    logger.info(f"Reports will be saved to: {reports_dir}")
    logger.info(f"Individual tool outputs: {individual_dir}")

    # Determine nmap timing (profile override or manual)
    nmap_timing = args.nmap_timing if args.nmap_timing else profile["nmap_timing"]
    
    logger.info("="*60)
    logger.info("Preflight complete. Starting nmap scan...")
    logger.info("="*60)

    # Run nmap
    xml_path = individual_dir / "nmap.xml"
    txt_path = individual_dir / "nmap.txt"
    logger.info(f"Running nmap against {target} (profile: {args.profile})")
    try:
        run_nmap(
            target=target,
            ports=args.ports,
            timing=nmap_timing,
            output_xml=str(xml_path),
            verbose=not args.quiet,
            sudo_password=args.sudo_password,
            nmap_flags=args.nmap_flags
        )
        if scan_state:
            scan_state.mark_phase_complete('nmap')
    except Exception as e:
        logger.error("Nmap run failed: %s", e)
        if not args.continue_on_error:
            return None
        parsed = {"hosts": []}

    # Parse nmap results
    try:
        parsed = parse_nmap_xml(str(xml_path))
        _scan_state["partial_data"]["nmap"] = parsed
    except Exception as e:
        logger.error("Failed to parse nmap XML: %s", e)
        if not args.continue_on_error:
            return None
        parsed = {"hosts": []}

    # Save parsed JSON summary to disk
    try:
        import json
        json_path = individual_dir / "nmap_parsed.json"
        with open(json_path, "w") as fh:
            json.dump(parsed, fh, indent=2)
        logger.info(f"Parsed nmap data saved: {json_path}")
    except Exception:
        logger.warning("Failed to write parsed JSON summary")
    
    # Check for services discovered
    services_found = False
    for h in parsed.get("hosts", []):
        for p in h.get("ports", []):
            svc = p.get("service")
            if svc and svc.get("name") and p.get("state") == "open":
                services_found = True
                break
        if services_found:
            break

    # Check for optional tools and prompt user
    skip_exploitdb = False
    
    if services_found and not check_tool("searchsploit"):
        logger.warning("`searchsploit` is not installed. Exploit lookups will be skipped.")
        if not args.non_interactive and not args.yes:
            resp = input("Install searchsploit now? (yes/no/skip): ").strip().lower()
            if resp in ("y", "yes"):
                print("Run: brew install exploitdb  # or see https://www.exploit-db.com/")
                sys.exit(10)
            elif resp == "skip":
                skip_exploitdb = True
            else:
                logger.info("Continuing without exploit lookups...")
                skip_exploitdb = True
        else:
            skip_exploitdb = True
    
    if args.dns_wordlist and not check_tool("dig"):
        logger.warning("`dig` not found. DNS enumeration may be limited.")
    
    if args.dir_wordlist and not check_tool("gobuster"):
        logger.warning("`gobuster` not installed. Will use Python fallback for directory enumeration.")

    # Run per-service enumeration and credential checks
    try:
        from .service_dispatcher import dispatch_services
        from .dns_enum import enumerate_dns
        from .dir_enum import enumerate_directories
        from .vuln_correlator import correlate_vulnerabilities

        logger.info("Running per-service enumeration and credential checks (creds_enabled=%s)", creds_enabled)
        dispatch_results = dispatch_services(
            parsed, 
            str(xml_path), 
            creds_enabled=creds_enabled,
            run_exploitdb=not skip_exploitdb,
            run_smb=not args.no_smb,
            run_ssh=not args.no_ssh,
            rate_limiter=rate_limiter,
            timeout=config.TIMEOUTS,
            continue_on_error=args.continue_on_error
        )
        
        if scan_state:
            scan_state.mark_phase_complete('service_enum')
        
        # Save exploit results to INDIVIDUAL folder
        exploits_path = individual_dir / "searchsploit.txt"
        with open(exploits_path, "w") as fh:
            for line in dispatch_results.get("exploits", []):
                fh.write(line + "\n")
        logger.info(f"Exploit lookup saved: {exploits_path}")
        
        # Save credentials to INDIVIDUAL folder
        creds_path = individual_dir / "credentials.json"
        with open(creds_path, "w") as fh:
            json.dump(dispatch_results.get("creds", []), fh, indent=2)
        logger.info(f"Credential check results saved: {creds_path}")
        
        # Save SMB enumeration results if any
        if dispatch_results.get("smb_enumeration"):
            smb_path = individual_dir / "smb_enum.json"
            with open(smb_path, "w") as fh:
                json.dump(dispatch_results["smb_enumeration"], fh, indent=2)
            logger.info(f"SMB enumeration saved: {smb_path}")
        
        # Save SSH enumeration results if any
        if dispatch_results.get("ssh_enumeration"):
            ssh_path = individual_dir / "ssh_enum.json"
            with open(ssh_path, "w") as fh:
                json.dump(dispatch_results["ssh_enumeration"], fh, indent=2)
            logger.info(f"SSH enumeration saved: {ssh_path}")
        
        # Update scan state
        _scan_state["partial_data"]["exploits"] = dispatch_results.get("exploits", [])
        _scan_state["partial_data"]["credentials"] = dispatch_results.get("creds", [])
        _scan_state["partial_data"]["smb_enumeration"] = dispatch_results.get("smb_enumeration", {})
        _scan_state["partial_data"]["ssh_enumeration"] = dispatch_results.get("ssh_enumeration", {})
        
        # Vulnerability correlation if not disabled
        vuln_results = {}
        if not args.no_vulns:
            logger.info("Correlating service versions with vulnerability databases...")
            vuln_results = correlate_vulnerabilities(parsed)
            
            # Save vulnerability results
            vuln_path = individual_dir / "vulnerabilities.json"
            with open(vuln_path, "w") as fh:
                json.dump(vuln_results, fh, indent=2)
            logger.info(f"Vulnerability correlation saved: {vuln_path}")
            
            # Show summary
            for summary_line in vuln_results.get("summary", []):
                logger.info(f"  {summary_line}")
            
            _scan_state["partial_data"]["vulnerabilities"] = vuln_results
        
        # DNS enumeration if wordlist provided
        dns_results = {}
        if args.dns_wordlist:
            import uuid
            import platform
            
            logger.info("Starting DNS enumeration...")
            for h in parsed.get("hosts", []):
                # Get IP from addresses array (nmap format)
                ip = h.get("ip")
                if not ip and h.get("addresses"):
                    for addr in h.get("addresses", []):
                        if addr.get("type") == "ipv4":
                            ip = addr.get("addr")
                            break
                
                if not ip:
                    continue
                
                hostnames = h.get("hostnames", [])
                target_domain = hostnames[0] if hostnames else None
                temp_domain_added = False
                temp_domain = None
                
                # If no hostname, create temporary domain and add to /etc/hosts
                if not target_domain or target_domain.replace('.', '').isdigit():
                    # Generate unique temporary domain
                    scan_uid = str(uuid.uuid4())[:8]
                    temp_domain = f"scan{scan_uid}.rex"
                    
                    # Determine hosts file path based on OS
                    system = platform.system()
                    if system in ("Linux", "Darwin"):  # Linux or macOS
                        hosts_file = "/etc/hosts"
                    elif system == "Windows":
                        hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
                    else:
                        logger.warning(f"Unsupported OS for /etc/hosts manipulation: {system}")
                        continue
                    
                    # Add temporary entry to hosts file
                    try:
                        logger.info(f"Adding temporary DNS entry: {ip} -> {temp_domain}")
                        hosts_entry = f"{ip}\t{temp_domain}\n"
                        
                        # Read current hosts file
                        with open(hosts_file, 'r') as f:
                            original_hosts = f.read()
                        
                        # Append our entry
                        with open(hosts_file, 'a') as f:
                            f.write(f"# REX SCAN TEMP ENTRY - AUTO REMOVE\n")
                            f.write(hosts_entry)
                        
                        target_domain = temp_domain
                        temp_domain_added = True
                        logger.info(f"Temporary hosts entry added successfully")
                        
                    except PermissionError:
                        logger.error(f"Permission denied: Cannot modify {hosts_file}. Run with sudo/admin privileges.")
                        logger.info(f"Skipping DNS enumeration for {ip}")
                        continue
                    except Exception as e:
                        logger.error(f"Failed to add hosts entry: {e}")
                        continue
                
                # Perform DNS enumeration
                if target_domain:
                    try:
                        logger.info(f"Enumerating DNS for domain: {target_domain}")
                        dns_results[target_domain] = enumerate_dns(
                            target=target_domain,
                            wordlist_path=args.dns_wordlist,
                            dns_server=args.dns_server if args.dns_server else None,
                            use_doh=args.dns_over_https
                        )
                    except Exception as e:
                        logger.error(f"DNS enumeration failed for {target_domain}: {e}")
                    finally:
                        # Clean up temporary hosts entry
                        if temp_domain_added and temp_domain:
                            try:
                                logger.info(f"Removing temporary hosts entry for {temp_domain}")
                                with open(hosts_file, 'r') as f:
                                    lines = f.readlines()
                                
                                # Remove our temporary entry and comment
                                with open(hosts_file, 'w') as f:
                                    skip_next = False
                                    for line in lines:
                                        if "REX SCAN TEMP ENTRY" in line:
                                            skip_next = True
                                            continue
                                        if skip_next and temp_domain in line:
                                            skip_next = False
                                            continue
                                        f.write(line)
                                
                                logger.info("Temporary hosts entry removed")
                            except Exception as e:
                                logger.warning(f"Failed to remove temporary hosts entry: {e}")
                                logger.warning(f"Please manually remove '{temp_domain}' from {hosts_file}")
            
            # Save DNS results to INDIVIDUAL folder
            dns_path = individual_dir / "dns_enum.json"
            with open(dns_path, "w") as fh:
                json.dump(dns_results, fh, indent=2)
            logger.info(f"DNS enumeration saved: {dns_path}")
            _scan_state["partial_data"]["dns_enumeration"] = dns_results
            
            if scan_state:
                scan_state.mark_phase_complete('dns_enum')
        
        # Directory enumeration if wordlist provided
        dir_results = {}
        if args.dir_wordlist:
            logger.info("Starting directory enumeration for HTTP/HTTPS services...")
            http_services = []
            for h in parsed.get("hosts", []):
                # Get IP from addresses array (nmap format)
                ip = h.get("ip")
                if not ip and h.get("addresses"):
                    for addr in h.get("addresses", []):
                        if addr.get("type") == "ipv4":
                            ip = addr.get("addr")
                            break
                
                if not ip:
                    continue
                    
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        svc_name = p.get("service", {}).get("name", "").lower()
                        port = p.get("portid") or p.get("port")  # Try portid first, fallback to port
                        if not port:
                            continue
                        port = int(port) if isinstance(port, str) else port
                        if svc_name in ("http", "https", "http-proxy", "ssl/http") or port in (80, 443, 8080, 8000):
                            protocol = "https" if "ssl" in svc_name or svc_name == "https" or port == 443 else "http"
                            target_url = f"{protocol}://{ip}:{port}"
                            http_services.append(target_url)
            
            # Use progress bar if available
            dir_iter = tqdm(http_services, desc="Directory enum", unit="url") if HAS_TQDM and not args.quiet else http_services
            
            for target_url in dir_iter:
                try:
                    if rate_limiter:
                        rate_limiter.wait()
                    logger.info(f"Enumerating directories on {target_url}")
                    dir_results[target_url] = enumerate_directories(
                        url=target_url,
                        wordlist=args.dir_wordlist,
                        extensions=args.dir_extensions.split(",") if args.dir_extensions else []
                    )
                except Exception as e:
                    logger.error(f"Directory enumeration failed for {target_url}: {e}")
                    if not args.continue_on_error:
                        raise
            
            # Save directory results to INDIVIDUAL folder
            dir_path = individual_dir / "dir_enum.json"
            with open(dir_path, "w") as fh:
                json.dump(dir_results, fh, indent=2)
            logger.info(f"Directory enumeration saved: {dir_path}")
            _scan_state["partial_data"]["directory_enumeration"] = dir_results
            
            if scan_state:
                scan_state.mark_phase_complete('dir_enum')
        
        # Advanced web enumeration if enabled
        advanced_web_results = {}
        if args.advanced_web and HAS_ADVANCED_WEB:
            logger.info("Starting advanced web enumeration...")
            http_services = []
            for h in parsed.get("hosts", []):
                # Extract IP address
                ip = h.get("ip")
                if not ip and h.get("addresses"):
                    for addr in h.get("addresses", []):
                        if addr.get("type") == "ipv4":
                            ip = addr.get("addr")
                            break
                
                if not ip:
                    continue
                
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        svc_name = p.get("service", {}).get("name", "").lower()
                        port = p.get("portid") or p.get("port")
                        if svc_name in ("http", "https", "http-proxy", "ssl/http") or port in (80, 443, 8080, 8000, 8180):
                            protocol = "https" if "ssl" in svc_name or svc_name == "https" or port in (443, 8443) else "http"
                            target_url = f"{protocol}://{ip}:{port}"
                            http_services.append(target_url)
            
            web_iter = tqdm(http_services, desc="Advanced web enum", unit="url") if HAS_TQDM and not args.quiet else http_services
            
            for target_url in web_iter:
                try:
                    if rate_limiter:
                        rate_limiter.wait()
                    logger.info(f"Advanced web analysis of {target_url}")
                    advanced_web_results[target_url] = enumerate_web_advanced(
                        target_url,
                        timeout=config.TIMEOUTS['http']
                    )
                except Exception as e:
                    logger.error(f"Advanced web enumeration failed for {target_url}: {e}")
                    if not args.continue_on_error:
                        raise
            
            # Save advanced web results
            adv_web_path = individual_dir / "advanced_web_enum.json"
            with open(adv_web_path, "w") as fh:
                json.dump(advanced_web_results, fh, indent=2)
            logger.info(f"Advanced web enumeration saved: {adv_web_path}")
            _scan_state["partial_data"]["advanced_web"] = advanced_web_results
            
            if scan_state:
                scan_state.mark_phase_complete('advanced_web')
        
        # Screenshot capture if enabled
        screenshot_results = []
        if args.screenshots and HAS_SCREENSHOT and screenshots_dir:
            logger.info("Capturing screenshots of web services and discovered directories...")
            http_services = []
            
            # Add base URLs
            for h in parsed.get("hosts", []):
                # Get IP from addresses array (nmap format)
                ip = h.get("ip")
                if not ip and h.get("addresses"):
                    for addr in h.get("addresses", []):
                        if addr.get("type") == "ipv4":
                            ip = addr.get("addr")
                            break
                
                if not ip:
                    continue
                    
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        svc_name = p.get("service", {}).get("name", "").lower()
                        port = p.get("portid") or p.get("port")  # Try portid first, fallback to port
                        if not port:
                            continue
                        port = int(port) if isinstance(port, str) else port
                        if svc_name in ("http", "https", "http-proxy", "ssl/http") or port in (80, 443, 8080, 8000):
                            protocol = "https" if "ssl" in svc_name or svc_name == "https" or port == 443 else "http"
                            base_url = f"{protocol}://{ip}:{port}"
                            http_services.append({"url": base_url, "type": "base"})
            
            # Add discovered directories (interesting ones only)
            interesting_dirs = ["login", "admin", "dashboard", "panel", "portal", "manager", "console", 
                              "phpmyadmin", "phpinfo", "upload", "uploads", "backup", "config", "api",
                              "test", "dev", "staging", "www", "web", "index.php", "login.php"]
            
            for base_url, paths in dir_results.items():
                if paths:
                    for path_obj in paths:
                        path = path_obj.get("path", "")
                        status = path_obj.get("status", "")
                        
                        # Skip error pages and redirects to root
                        if status in ["403", "404", "500"]:
                            continue
                        
                        # Check if it's an interesting directory
                        path_lower = path.lower().strip("/")
                        is_interesting = any(interesting in path_lower for interesting in interesting_dirs)
                        
                        # Screenshot if it's a 200 OK and interesting, or a redirect (301, 302)
                        if (status == "200" and is_interesting) or status in ["301", "302"]:
                            full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                            http_services.append({"url": full_url, "type": "directory", "status": status})
            
            logger.info(f"Total URLs to screenshot: {len(http_services)} (base services + interesting directories)")
            ss_iter = tqdm(http_services, desc="Screenshots", unit="url") if HAS_TQDM and not args.quiet else http_services
            
            for service_obj in ss_iter:
                # Handle both old format (string) and new format (dict)
                if isinstance(service_obj, str):
                    target_url = service_obj
                    url_type = "base"
                else:
                    target_url = service_obj["url"]
                    url_type = service_obj.get("type", "base")
                
                try:
                    if rate_limiter:
                        rate_limiter.wait()
                    safe_name = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
                    screenshot_path = screenshots_dir / f"{safe_name}.png"
                    
                    # Add type prefix to log message
                    type_prefix = "[DIR]" if url_type == "directory" else "[WEB]"
                    logger.info(f"{type_prefix} Capturing screenshot of {target_url}")
                    
                    capture_screenshot(
                        target_url,
                        str(screenshot_path),
                        timeout=config.TIMEOUTS['screenshot']
                    )
                    screenshot_results.append({
                        "url": target_url,
                        "path": str(screenshot_path),
                        "type": url_type,
                        "success": True
                    })
                except Exception as e:
                    logger.error(f"Screenshot failed for {target_url}: {e}")
                    screenshot_results.append({
                        "url": target_url,
                        "type": url_type,
                        "error": str(e),
                        "success": False
                    })
                    if not args.continue_on_error:
                        raise
            
            _scan_state["partial_data"]["screenshots"] = screenshot_results
            
            if scan_state:
                scan_state.mark_phase_complete('screenshots')
        
        # Generate comprehensive reports
        from .report import generate_text_report, generate_json_report, generate_html_report
        
        report_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "profile": args.profile,
            "nmap": parsed,
            "exploits": dispatch_results.get("exploits", []),
            "credentials": dispatch_results.get("creds", []),
            "smb_enumeration": dispatch_results.get("smb_enumeration", {}),
            "ssh_enumeration": dispatch_results.get("ssh_enumeration", {}),
            "vulnerabilities": vuln_results,
            "dns_enumeration": dns_results,
            "directory_enumeration": dir_results,
            "advanced_web": advanced_web_results if args.advanced_web else {},
            "screenshots": screenshot_results if args.screenshots else []
        }
        
        # Update final scan state
        _scan_state["partial_data"] = report_data
        
        # Generate charts if enabled
        if args.charts and HAS_CHART_GEN and charts_dir:
            logger.info("Generating charts...")
            try:
                import base64
                chart_paths = generate_all_charts(report_data, str(charts_dir))
                logger.info(f"Charts generated: {len(chart_paths)} files")
                
                # Store chart paths and embed PNG charts as base64 for HTML report
                report_data["charts"] = chart_paths.copy()
                for chart_name, chart_path in chart_paths.items():
                    logger.info(f"  - {chart_name}: {Path(chart_path).name}")
                    # Embed PNG charts as base64 for HTML report
                    if chart_path.endswith('.png'):
                        try:
                            with open(chart_path, 'rb') as f:
                                chart_data = base64.b64encode(f.read()).decode('utf-8')
                                report_data["charts"][f"{chart_name}_base64"] = chart_data
                        except Exception as e:
                            logger.warning(f"Failed to encode chart {chart_name}: {e}")
            except Exception as e:
                logger.error(f"Chart generation failed: {e}")
                if not args.continue_on_error:
                    raise
        
        # Text report in REX_REPORTS folder
        text_report_path = reports_dir / "report.txt"
        generate_text_report(report_data, str(text_report_path))
        logger.info(f"Text report saved: {text_report_path}")
        
        # JSON report in REX_REPORTS folder
        json_report_path = reports_dir / "report.json"
        generate_json_report(report_data, str(json_report_path))
        logger.info(f"JSON report saved: {json_report_path}")
        
        # HTML report in REX_REPORTS folder
        html_report_path = reports_dir / "report.html"
        generate_html_report(report_data, str(html_report_path))
        logger.info(f"HTML report saved: {html_report_path}")
        
        # Mark scan as complete
        if scan_state:
            scan_state.mark_phase_complete('complete')
            scan_state.save_state(force=True)
        
        logger.info("="*60)
        logger.info("REX SCAN: TOOL OF TOOLS - Complete!")
        logger.info("="*60)
        logger.info(f"Scan folder: {scan_folder}")
        logger.info(f"Reports: {reports_dir}")
        logger.info(f"Individual outputs: {individual_dir}")
        if args.screenshots and screenshots_dir:
            logger.info(f"Screenshots: {screenshots_dir}")
        if args.charts and charts_dir:
            logger.info(f"Charts: {charts_dir}")
        logger.info("="*60)
        
        return report_data
        
    except Exception as e:
        logger.error("Service enumeration failed: %s", e)
        if not args.continue_on_error:
            import traceback
            logger.error(traceback.format_exc())
            raise
        return None


if __name__ == "__main__":
    main()
