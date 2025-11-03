"""Scan state management for resume capability

Allows saving and resuming interrupted scans.
"""
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class ScanState:
    """Manages scan state for resume capability."""
    
    def __init__(self, scan_folder: Path, target: str):
        """
        Initialize scan state manager.
        
        Args:
            scan_folder: Base folder for scan outputs
            target: Target being scanned
        """
        self.scan_folder = Path(scan_folder)
        self.target = target
        self.state_file = self.scan_folder / ".scan_state.json"
        self.state: Dict[str, Any] = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "last_checkpoint": None,
            "completed_phases": [],
            "current_phase": None,
            "data": {},
            "errors": []
        }
        self.last_save = time.time()
        self.save_interval = 60  # Save every 60 seconds
    
    def load_state(self) -> bool:
        """
        Load existing state from file.
        
        Returns:
            True if state loaded successfully
        """
        if not self.state_file.exists():
            return False
        
        try:
            with open(self.state_file, 'r') as f:
                self.state = json.load(f)
            return True
        except Exception as e:
            print(f"Warning: Failed to load state: {e}")
            return False
    
    def save_state(self, force: bool = False):
        """
        Save current state to file.
        
        Args:
            force: Force save even if interval hasn't passed
        """
        now = time.time()
        
        # Check if enough time has passed since last save
        if not force and (now - self.last_save) < self.save_interval:
            return
        
        try:
            self.state["last_checkpoint"] = datetime.now().isoformat()
            
            # Ensure directory exists
            self.scan_folder.mkdir(parents=True, exist_ok=True)
            
            # Write state to temp file first
            temp_file = self.state_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(self.state, f, indent=2)
            
            # Atomic rename
            temp_file.replace(self.state_file)
            
            self.last_save = now
        except Exception as e:
            print(f"Warning: Failed to save state: {e}")
    
    def mark_phase_complete(self, phase: str):
        """Mark a scan phase as complete."""
        if phase not in self.state["completed_phases"]:
            self.state["completed_phases"].append(phase)
        self.save_state(force=True)
    
    def is_phase_complete(self, phase: str) -> bool:
        """Check if a phase has been completed."""
        return phase in self.state["completed_phases"]
    
    def set_current_phase(self, phase: str):
        """Set the current scan phase."""
        self.state["current_phase"] = phase
        self.save_state()
    
    def update_data(self, key: str, value: Any):
        """Update scan data."""
        self.state["data"][key] = value
        self.save_state()
    
    def get_data(self, key: str, default: Any = None) -> Any:
        """Get scan data."""
        return self.state["data"].get(key, default)
    
    def add_error(self, phase: str, error: str):
        """Record an error."""
        self.state["errors"].append({
            "phase": phase,
            "error": error,
            "timestamp": datetime.now().isoformat()
        })
        self.save_state()
    
    def cleanup(self):
        """Remove state file after successful completion."""
        try:
            if self.state_file.exists():
                self.state_file.unlink()
        except Exception:
            pass
    
    @classmethod
    def load(cls, scan_folder: str) -> 'ScanState':
        """
        Load scan state from folder.
        
        Args:
            scan_folder: Path to scan folder with state file
        
        Returns:
            ScanState instance with loaded state
        
        Raises:
            FileNotFoundError: If state file doesn't exist
            ValueError: If state is invalid
        """
        folder_path = Path(scan_folder)
        state_file = folder_path / ".scan_state.json"
        
        if not state_file.exists():
            raise FileNotFoundError(f"No state file found in {scan_folder}")
        
        try:
            with open(state_file, 'r') as f:
                state_data = json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load state: {e}")
        
        # Create instance
        instance = cls(folder_path, state_data.get("target", "unknown"))
        instance.state = state_data
        
        return instance
    
    def get_resume_info(self) -> Dict[str, Any]:
        """Get information for resume prompt."""
        return {
            "target": self.state.get("target"),
            "start_time": self.state.get("start_time"),
            "last_checkpoint": self.state.get("last_checkpoint"),
            "completed_phases": self.state.get("completed_phases", []),
            "current_phase": self.state.get("current_phase"),
            "errors": len(self.state.get("errors", []))
        }


def find_resumable_scans(base_path: Path = None) -> list:
    """
    Find all resumable scans.
    
    Args:
        base_path: Base path to search (defaults to Desktop)
    
    Returns:
        List of (scan_folder, state_info) tuples
    """
    if base_path is None:
        base_path = Path.home() / "Desktop"
    
    resumable = []
    
    # Find all .scan_state.json files
    for state_file in base_path.rglob(".scan_state.json"):
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
            
            resumable.append((
                state_file.parent,
                {
                    "target": state.get("target"),
                    "start_time": state.get("start_time"),
                    "last_checkpoint": state.get("last_checkpoint"),
                    "completed_phases": state.get("completed_phases", [])
                }
            ))
        except Exception:
            continue
    
    return resumable
