"""Track all commands and raw outputs for transparency and debugging."""
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CommandExecution:
    """Represents a single command execution."""
    tool: str
    command: str
    timestamp: str
    duration: float
    exit_code: int
    stdout: str
    stderr: str
    success: bool
    context: str = ""  # e.g., "DNS Enumeration for example.com"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool": self.tool,
            "command": self.command,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration, 2),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "success": self.success,
            "context": self.context
        }


class CommandTracker:
    """Global command tracker for all external tool executions."""
    
    def __init__(self):
        self.commands: List[CommandExecution] = []
        self._enabled = True
    
    def enable(self):
        """Enable command tracking."""
        self._enabled = True
    
    def disable(self):
        """Disable command tracking."""
        self._enabled = False
    
    def track(self, tool: str, command: str, stdout: str, stderr: str, 
              exit_code: int, duration: float, context: str = "") -> None:
        """Track a command execution."""
        if not self._enabled:
            return
        
        execution = CommandExecution(
            tool=tool,
            command=command,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration=duration,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            success=(exit_code == 0),
            context=context
        )
        self.commands.append(execution)
    
    def get_all(self) -> List[Dict]:
        """Get all tracked commands."""
        return [cmd.to_dict() for cmd in self.commands]
    
    def get_by_tool(self, tool: str) -> List[Dict]:
        """Get commands filtered by tool."""
        return [cmd.to_dict() for cmd in self.commands if cmd.tool.lower() == tool.lower()]
    
    def get_failed(self) -> List[Dict]:
        """Get only failed commands."""
        return [cmd.to_dict() for cmd in self.commands if not cmd.success]
    
    def clear(self):
        """Clear all tracked commands."""
        self.commands.clear()
    
    def summary(self) -> Dict:
        """Get summary statistics."""
        total = len(self.commands)
        successful = sum(1 for cmd in self.commands if cmd.success)
        failed = total - successful
        
        tools_used = {}
        for cmd in self.commands:
            tools_used[cmd.tool] = tools_used.get(cmd.tool, 0) + 1
        
        total_duration = sum(cmd.duration for cmd in self.commands)
        
        return {
            "total_commands": total,
            "successful": successful,
            "failed": failed,
            "tools_used": tools_used,
            "total_duration_seconds": round(total_duration, 2)
        }


# Global tracker instance
_tracker = CommandTracker()


def get_tracker() -> CommandTracker:
    """Get the global command tracker instance."""
    return _tracker
