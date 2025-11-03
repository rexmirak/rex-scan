"""Target parsing and validation

Supports:
- Single IPs: 192.168.1.1
- Hostnames: example.com
- CIDR ranges: 192.168.1.0/24
- IP ranges: 192.168.1.1-50
- Target files: targets.txt
"""
import ipaddress
import socket
from pathlib import Path
from typing import List, Set
import re


def parse_ip_range(range_str: str) -> List[str]:
    """
    Parse IP range like 192.168.1.1-50
    
    Args:
        range_str: IP range string
    
    Returns:
        List of IP addresses
    """
    ips = []
    
    # Match pattern like 192.168.1.1-50
    match = re.match(r'(\d+\.\d+\.\d+\.)(\d+)-(\d+)', range_str)
    if match:
        prefix = match.group(1)
        start = int(match.group(2))
        end = int(match.group(3))
        
        for i in range(start, end + 1):
            ips.append(f"{prefix}{i}")
    
    return ips


def parse_cidr(cidr: str) -> List[str]:
    """
    Parse CIDR notation like 192.168.1.0/24
    
    Args:
        cidr: CIDR string
    
    Returns:
        List of IP addresses
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def parse_target_file(filepath: str) -> List[str]:
    """
    Parse target file with one target per line
    
    Args:
        filepath: Path to target file
    
    Returns:
        List of targets
    """
    targets = []
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    targets.append(line)
    except Exception as e:
        raise ValueError(f"Failed to read target file {filepath}: {e}")
    
    return targets


def validate_ip(ip: str) -> bool:
    """Validate if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """Validate if string is a valid hostname."""
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False


def parse_targets(target_input: str) -> List[str]:
    """
    Parse various target input formats
    
    Args:
        target_input: Can be:
            - Single IP: 192.168.1.1
            - Hostname: example.com
            - CIDR: 192.168.1.0/24
            - IP range: 192.168.1.1-50
            - File: @targets.txt
            - Comma-separated: 192.168.1.1,192.168.1.2,example.com
    
    Returns:
        List of valid targets
    """
    targets = []
    
    # Check for comma-separated targets first
    if ',' in target_input:
        parts = [part.strip() for part in target_input.split(',')]
        all_targets = []
        for part in parts:
            all_targets.extend(parse_targets(part))  # Recursively parse each part
        return all_targets
    
    # File input (prefixed with @)
    if target_input.startswith('@'):
        filepath = target_input[1:]
        return parse_target_file(filepath)
    
    # CIDR notation
    if '/' in target_input:
        cidr_targets = parse_cidr(target_input)
        if cidr_targets:
            return cidr_targets
    
    # IP range
    if '-' in target_input and re.match(r'\d+\.\d+\.\d+\.\d+-\d+', target_input):
        range_targets = parse_ip_range(target_input)
        if range_targets:
            return range_targets
    
    # Single target (IP or hostname)
    return [target_input]


def deduplicate_targets(targets: List[str]) -> List[str]:
    """Remove duplicate targets while preserving order."""
    seen = set()
    unique = []
    
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
    
    return unique


def parse_and_validate_targets(target_input: str, max_targets: int = 256) -> List[str]:
    """
    Parse and validate target input
    
    Args:
        target_input: Target specification
        max_targets: Maximum number of targets allowed
    
    Returns:
        List of validated targets
    
    Raises:
        ValueError: If target input is invalid
    """
    # Parse targets
    targets = parse_targets(target_input)
    
    # Deduplicate
    targets = deduplicate_targets(targets)
    
    # Check max targets
    if len(targets) > max_targets:
        raise ValueError(f"Too many targets ({len(targets)}). Maximum allowed: {max_targets}")
    
    # Validate each target
    validated = []
    invalid = []
    
    for target in targets:
        if validate_ip(target) or validate_hostname(target):
            validated.append(target)
        else:
            invalid.append(target)
    
    if invalid and len(invalid) < 10:
        print(f"Warning: {len(invalid)} invalid targets skipped: {', '.join(invalid[:5])}")
    elif invalid:
        print(f"Warning: {len(invalid)} invalid targets skipped")
    
    if not validated:
        raise ValueError("No valid targets found")
    
    return validated
