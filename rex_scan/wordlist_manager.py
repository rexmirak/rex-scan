"""Wordlist management for REX SCAN

Downloads and manages common wordlists for enumeration.
"""
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional
import requests
from tqdm import tqdm


class WordlistManager:
    """Manages wordlist downloads and organization."""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize wordlist manager.
        
        Args:
            base_dir: Base directory for wordlists (defaults to ~/.rex_scan/wordlists)
        """
        if base_dir is None:
            self.base_dir = Path.home() / ".rex_scan" / "wordlists"
        else:
            self.base_dir = Path(base_dir)
        
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # Wordlist sources
        self.wordlists = {
            "dns": {
                "subdomains-top1million-5000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
                "subdomains-top1million-20000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
                "dns-Jhaddix.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt"
            },
            "directory": {
                "directory-list-2.3-small.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt",
                "directory-list-2.3-medium.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
                "raft-large-words.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"
            },
            "passwords": {
                "10k-most-common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
                "rockyou-top1000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-passwords-shortlist.txt"
            },
            "usernames": {
                "top-usernames-shortlist.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
                "xato-net-10-million-usernames.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt"
            }
        }
    
    def download_file(self, url: str, output_path: Path) -> bool:
        """
        Download a file with progress bar.
        
        Args:
            url: URL to download
            output_path: Path to save file
        
        Returns:
            True if successful
        """
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'wb') as f:
                with tqdm(total=total_size, unit='B', unit_scale=True, desc=output_path.name) as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            return True
        except Exception as e:
            print(f"Failed to download {url}: {e}")
            return False
    
    def download_wordlist(self, category: str, name: str) -> Optional[Path]:
        """
        Download a specific wordlist.
        
        Args:
            category: Wordlist category (dns, directory, passwords, usernames)
            name: Wordlist name
        
        Returns:
            Path to downloaded wordlist or None
        """
        if category not in self.wordlists:
            print(f"Unknown category: {category}")
            return None
        
        if name not in self.wordlists[category]:
            print(f"Unknown wordlist: {name}")
            return None
        
        url = self.wordlists[category][name]
        output_path = self.base_dir / category / name
        
        # Check if already downloaded
        if output_path.exists():
            print(f"[+] {name} already exists")
            return output_path
        
        print(f"Downloading {name}...")
        if self.download_file(url, output_path):
            print(f"[+] Downloaded {name}")
            return output_path
        
        return None
    
    def download_all(self, category: Optional[str] = None):
        """
        Download all wordlists in a category (or all categories).
        
        Args:
            category: Category to download (None for all)
        """
        categories = [category] if category else self.wordlists.keys()
        
        for cat in categories:
            print(f"\n=== Downloading {cat} wordlists ===")
            for name in self.wordlists[cat].keys():
                self.download_wordlist(cat, name)
    
    def list_available(self) -> Dict[str, List[str]]:
        """List all available wordlists."""
        available = {}
        
        for category, wordlists in self.wordlists.items():
            available[category] = []
            for name in wordlists.keys():
                path = self.base_dir / category / name
                status = "[+]" if path.exists() else "[X]"
                available[category].append(f"{status} {name}")
        
        return available
    
    def get_wordlist_path(self, category: str, name: str) -> Optional[Path]:
        """
        Get path to a wordlist, downloading if necessary.
        
        Args:
            category: Wordlist category
            name: Wordlist name
        
        Returns:
            Path to wordlist or None
        """
        path = self.base_dir / category / name
        
        if path.exists():
            return path
        
        # Try to download
        return self.download_wordlist(category, name)
    
    def get_default_dns_wordlist(self) -> Optional[Path]:
        """Get default DNS wordlist, downloading if necessary."""
        return self.get_wordlist_path("dns", "subdomains-top1million-5000.txt")
    
    def get_default_dir_wordlist(self) -> Optional[Path]:
        """Get default directory wordlist, downloading if necessary."""
        return self.get_wordlist_path("directory", "common.txt")
    
    def clone_seclists(self) -> bool:
        """Clone entire SecLists repository (large download)."""
        seclists_dir = self.base_dir / "SecLists"
        
        if seclists_dir.exists():
            print("[+] SecLists already cloned")
            return True
        
        if not shutil.which("git"):
            print("[X] git not installed - cannot clone SecLists")
            return False
        
        print("Cloning SecLists repository (this may take a while)...")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/danielmiessler/SecLists.git", str(seclists_dir)],
                check=True
            )
            print("[+] SecLists cloned successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[X] Failed to clone SecLists: {e}")
            return False


def manage_wordlists_interactive():
    """Interactive wordlist management interface."""
    manager = WordlistManager()
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║            REX SCAN - Wordlist Manager                    ║
╚═══════════════════════════════════════════════════════════╝

Choose an option:
  1. Download default wordlists (recommended)
  2. Download DNS wordlists
  3. Download directory wordlists
  4. Download password wordlists
  5. Download username wordlists
  6. Clone entire SecLists repository
  7. List available wordlists
  8. Exit
""")
    
    while True:
        choice = input("\nChoice [1-8]: ").strip()
        
        if choice == "1":
            print("\nDownloading default wordlists...")
            manager.download_wordlist("dns", "subdomains-top1million-5000.txt")
            manager.download_wordlist("directory", "common.txt")
            print("\n[+] Default wordlists ready")
        
        elif choice == "2":
            manager.download_all("dns")
        
        elif choice == "3":
            manager.download_all("directory")
        
        elif choice == "4":
            manager.download_all("passwords")
        
        elif choice == "5":
            manager.download_all("usernames")
        
        elif choice == "6":
            manager.clone_seclists()
        
        elif choice == "7":
            available = manager.list_available()
            for category, wordlists in available.items():
                print(f"\n{category.upper()}:")
                for wl in wordlists:
                    print(f"  {wl}")
        
        elif choice == "8":
            break
        
        else:
            print("Invalid choice")
