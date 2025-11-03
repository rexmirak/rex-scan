"""Rate limiting for network operations

Prevents overwhelming targets and avoids triggering IDS/IPS systems.
"""
import time
import threading
from collections import deque
from typing import Callable, Any


class RateLimiter:
    """Token bucket rate limiter for controlling request rates."""
    
    def __init__(self, rate: float, delay: float = 0.0):
        """
        Initialize rate limiter.
        
        Args:
            rate: Maximum requests per second
            delay: Additional delay between requests (seconds)
        """
        self.rate = rate
        self.delay = delay
        self.min_interval = 1.0 / rate if rate > 0 else 0
        self.last_call = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limit."""
        with self.lock:
            now = time.time()
            time_since_last = now - self.last_call
            
            # Calculate required wait time
            wait_time = max(0, self.min_interval - time_since_last)
            
            # Add additional delay if specified
            wait_time += self.delay
            
            if wait_time > 0:
                time.sleep(wait_time)
            
            self.last_call = time.time()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator to rate-limit a function."""
        def wrapper(*args, **kwargs):
            self.wait()
            return func(*args, **kwargs)
        return wrapper


class AdaptiveRateLimiter(RateLimiter):
    """Rate limiter that adapts based on response times and errors."""
    
    def __init__(self, initial_rate: float, min_rate: float = 0.5, max_rate: float = 50):
        """
        Initialize adaptive rate limiter.
        
        Args:
            initial_rate: Starting requests per second
            min_rate: Minimum requests per second
            max_rate: Maximum requests per second
        """
        super().__init__(initial_rate)
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.error_count = 0
        self.success_count = 0
        self.window_size = 10
        self.response_times = deque(maxlen=self.window_size)
    
    def record_success(self, response_time: float):
        """Record successful request."""
        self.success_count += 1
        self.response_times.append(response_time)
        
        # Increase rate if consistently fast responses
        if len(self.response_times) == self.window_size:
            avg_time = sum(self.response_times) / self.window_size
            if avg_time < 0.5 and self.rate < self.max_rate:
                self.rate = min(self.rate * 1.1, self.max_rate)
                self.min_interval = 1.0 / self.rate
    
    def record_error(self):
        """Record failed request and slow down."""
        self.error_count += 1
        
        # Decrease rate on errors
        if self.error_count > 2:
            self.rate = max(self.rate * 0.8, self.min_rate)
            self.min_interval = 1.0 / self.rate
            self.error_count = 0  # Reset counter


class RequestThrottler:
    """Simple request throttler with configurable delay."""
    
    def __init__(self, delay: float = 0.0):
        """
        Initialize throttler.
        
        Args:
            delay: Delay between requests in seconds
        """
        self.delay = delay
        self.lock = threading.Lock()
    
    def throttle(self):
        """Apply throttling delay."""
        if self.delay > 0:
            with self.lock:
                time.sleep(self.delay)
