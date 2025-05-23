#!/usr/bin/env python3
"""
Demonstration script for the rate limiting system.

This script shows how the rate limiter works with different services
and demonstrates the backoff/retry functionality.
"""

import time
import logging
from src.utils.rate_limiter import get_rate_limiter, RateLimitConfig
from src.utils.backoff import with_api_backoff, RateLimitError

# Configure logging to see rate limiting in action
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def demo_basic_rate_limiting():
    """Demonstrate basic rate limiting functionality."""
    print("\n" + "="*60)
    print("DEMO: Basic Rate Limiting")
    print("="*60)
    
    limiter = get_rate_limiter()
    
    # Show current configuration for BGP.HE.NET
    config = limiter.get_rate_limit_config("bgp_he_net")
    print(f"BGP.HE.NET config: {config.requests_per_minute}/min, {config.requests_per_hour}/hour")
    
    # Show current usage
    usage = limiter.get_current_usage("bgp_he_net")
    print(f"Current usage: {usage}")
    
    # Demonstrate acquiring permits
    print("\nMaking 3 API calls with rate limiting...")
    for i in range(3):
        with limiter.acquire("bgp_he_net", f"demo_call_{i+1}"):
            print(f"  ✅ API call {i+1} allowed")
            time.sleep(0.5)  # Simulate API call duration
    
    # Show updated usage
    usage = limiter.get_current_usage("bgp_he_net")
    print(f"Updated usage: {usage}")

def demo_rate_limit_hit():
    """Demonstrate what happens when rate limit is hit."""
    print("\n" + "="*60)
    print("DEMO: Rate Limit Hit Simulation")
    print("="*60)
    
    limiter = get_rate_limiter()
    
    # Create a very restrictive config for demo
    demo_config = RateLimitConfig(
        service="demo_service",
        requests_per_minute=2,
        requests_per_hour=10,
        burst_limit=1
    )
    limiter.set_rate_limit_config("demo_service", demo_config)
    
    print("Created demo service with 2 requests/minute, 1 burst limit")
    
    # Make requests that will hit the limit
    print("\nMaking rapid requests to hit rate limit...")
    for i in range(5):
        try:
            start_time = time.time()
            with limiter.acquire("demo_service", f"demo_call_{i+1}"):
                print(f"  ✅ API call {i+1} allowed (waited {time.time() - start_time:.2f}s)")
        except Exception as e:
            print(f"  ❌ API call {i+1} failed: {e}")

def demo_backoff_decorator():
    """Demonstrate the backoff decorator functionality."""
    print("\n" + "="*60)
    print("DEMO: Exponential Backoff Decorator")
    print("="*60)
    
    @with_api_backoff
    def simulate_api_call(call_number: int, should_fail: bool = False):
        """Simulate an API call that might fail."""
        print(f"    Attempting API call #{call_number}")
        
        if should_fail and call_number <= 2:  # Fail first 2 attempts
            raise RateLimitError(
                message=f"Simulated rate limit hit on call {call_number}",
                retry_after=1.0
            )
        
        return f"Success on call {call_number}"
    
    # Test successful call
    print("Testing successful API call:")
    try:
        result = simulate_api_call(1, should_fail=False)
        print(f"  ✅ {result}")
    except Exception as e:
        print(f"  ❌ Failed: {e}")
    
    # Test call that fails initially but succeeds after retry
    print("\nTesting API call with retries (will fail first 2 attempts):")
    try:
        result = simulate_api_call(1, should_fail=True)
        print(f"  ✅ {result}")
    except Exception as e:
        print(f"  ❌ Failed after retries: {e}")

def demo_metrics():
    """Demonstrate rate limiting metrics."""
    print("\n" + "="*60)
    print("DEMO: Rate Limiting Metrics")
    print("="*60)
    
    limiter = get_rate_limiter()
    
    # Get metrics for all services
    all_metrics = limiter.get_metrics()
    
    print("Rate limiting metrics for all services:")
    for service, metrics in all_metrics.items():
        if metrics.get('total_requests', 0) > 0:
            print(f"\n{service}:")
            print(f"  Total requests: {metrics.get('total_requests', 0)}")
            print(f"  Successful requests: {metrics.get('successful_requests', 0)}")
            print(f"  Blocked requests: {metrics.get('blocked_requests', 0)}")
            print(f"  Average wait time: {metrics.get('average_wait_time', 0):.2f}s")
            current_usage = metrics.get('current_usage', {})
            print(f"  Current minute usage: {current_usage.get('requests_last_minute', 0)}/{current_usage.get('limit_per_minute', 0)}")

def main():
    """Run all demonstrations."""
    print("Rate Limiting System Demonstration")
    print("This demo shows the advanced rate limiting system in action.")
    
    try:
        demo_basic_rate_limiting()
        demo_rate_limit_hit()
        demo_backoff_decorator()
        demo_metrics()
        
        print("\n" + "="*60)
        print("✅ Rate limiting demonstration completed successfully!")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        logger.exception("Demo failed")

if __name__ == "__main__":
    main() 