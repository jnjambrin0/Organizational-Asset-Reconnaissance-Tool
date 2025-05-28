#!/usr/bin/env python3
"""
Performance testing script for the optimized Streamlit application.

This script tests the improved performance features including:
- Streaming progress updates
- Optimized pagination
- Intelligent caching
- Large dataset handling
"""

import sys
import time
import logging
import random
from datetime import datetime
from typing import Set

# Add src to path for imports
sys.path.insert(0, 'src')

from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, Subdomain, CloudService
from src import db_manager
from src.utils.logging_config import setup_logging

# Setup logging
setup_logging(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_large_test_dataset(scale: str = "medium") -> ReconnaissanceResult:
    """
    Create a test dataset of various sizes to test performance.
    
    Args:
        scale: "small", "medium", "large", or "massive"
    """
    # Scale definitions
    scales = {
        "small": {"asns": 5, "domains": 10, "subdomains_per_domain": 20, "ip_ranges": 50, "cloud": 15},
        "medium": {"asns": 25, "domains": 50, "subdomains_per_domain": 100, "ip_ranges": 200, "cloud": 75},
        "large": {"asns": 100, "domains": 200, "subdomains_per_domain": 500, "ip_ranges": 1000, "cloud": 300},
        "massive": {"asns": 500, "domains": 1000, "subdomains_per_domain": 2000, "ip_ranges": 5000, "cloud": 1500}
    }
    
    config = scales.get(scale, scales["medium"])
    
    logger.info(f"Creating {scale} test dataset: {config}")
    
    # Create result object
    result = ReconnaissanceResult(target_organization=f"Test Organization {scale.title()}")
    
    start_time = time.time()
    
    # Generate ASNs
    logger.info(f"Generating {config['asns']} ASNs...")
    for i in range(config['asns']):
        asn = ASN(
            number=64512 + i,  # Use private ASN range
            name=f"Test ASN {i+1}",
            description=f"Test Autonomous System Number {i+1} for performance testing",
            country=random.choice(["US", "GB", "DE", "FR", "JP", "CA", "AU"]),
            data_source="Performance Test"
        )
        result.add_asn(asn)
    
    # Generate IP Ranges
    logger.info(f"Generating {config['ip_ranges']} IP ranges...")
    for i in range(config['ip_ranges']):
        # Generate IPv4 ranges
        if i % 4 != 3:  # 75% IPv4
            base_ip = f"192.{168 + (i // 256)}.{i % 256}"
            prefix = random.choice([24, 25, 26, 27, 28])
            cidr = f"{base_ip}.0/{prefix}"
            version = 4
        else:  # 25% IPv6
            cidr = f"2001:db8:{i:04x}::{prefix}/64"
            version = 6
            
        ip_range = IPRange(
            cidr=cidr,
            version=version,
            asn=random.choice(list(result.asns)) if result.asns else None,
            country=random.choice(["US", "GB", "DE", "FR", "JP"]),
            data_source="Performance Test"
        )
        result.add_ip_range(ip_range)
    
    # Generate Domains with Subdomains
    logger.info(f"Generating {config['domains']} domains with {config['subdomains_per_domain']} subdomains each...")
    
    tlds = [".com", ".net", ".org", ".io", ".co", ".tech", ".ai"]
    subdomain_prefixes = [
        "www", "mail", "ftp", "blog", "shop", "api", "cdn", "static", "admin", "dev",
        "test", "staging", "prod", "app", "mobile", "web", "secure", "portal", 
        "support", "help", "docs", "wiki", "forum", "chat", "vpn", "remote"
    ]
    
    for i in range(config['domains']):
        domain_name = f"testdomain{i+1}{random.choice(tlds)}"
        
        domain = Domain(
            name=domain_name,
            registrar=random.choice(["GoDaddy", "Namecheap", "Cloudflare", "Google Domains"]),
            creation_date=datetime.now(),
            data_source="Performance Test"
        )
        
        # Generate subdomains
        num_subdomains = min(config['subdomains_per_domain'], len(subdomain_prefixes) * 10)
        for j in range(num_subdomains):
            if j < len(subdomain_prefixes):
                subdomain_name = f"{subdomain_prefixes[j]}.{domain_name}"
            else:
                subdomain_name = f"sub{j}.{domain_name}"
            
            # Generate some resolved IPs
            resolved_ips = set()
            if random.random() > 0.3:  # 70% chance of having resolved IPs
                for _ in range(random.randint(1, 3)):
                    ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    resolved_ips.add(ip)
            
            subdomain = Subdomain(
                fqdn=subdomain_name,
                status=random.choice(["Active", "Inactive", "Unknown"]),
                resolved_ips=resolved_ips,
                data_source="Performance Test",
                last_checked=datetime.now()
            )
            domain.subdomains.add(subdomain)
        
        result.add_domain(domain)
    
    # Generate Cloud Services
    logger.info(f"Generating {config['cloud']} cloud services...")
    providers = ["AWS", "Azure", "GCP", "Cloudflare", "DigitalOcean", "Heroku"]
    resource_types = ["Domain", "IP", "Service", "Database", "Storage", "CDN"]
    
    for i in range(config['cloud']):
        provider = random.choice(providers)
        resource_type = random.choice(resource_types)
        
        if provider == "AWS":
            identifier = f"s3.amazonaws.com" if resource_type == "Storage" else f"ec2-{i}.compute.amazonaws.com"
        elif provider == "Azure":
            identifier = f"test{i}.azurewebsites.net"
        elif provider == "GCP":
            identifier = f"test{i}.appspot.com"
        else:
            identifier = f"test{i}.{provider.lower()}.com"
        
        cloud_service = CloudService(
            provider=provider,
            identifier=identifier,
            resource_type=resource_type,
            data_source="Performance Test"
        )
        result.add_cloud_service(cloud_service)
    
    # Add some warnings for testing
    result.add_warning("Test warning: Some API endpoints were rate limited during testing")
    result.add_warning("Test warning: DNS resolution timeout for 3 subdomains")
    if scale in ["large", "massive"]:
        result.add_warning("Performance test warning: Large dataset may cause display delays")
        result.add_warning("Critical test error: Simulated API failure during massive scan")
    
    creation_time = time.time() - start_time
    logger.info(f"Dataset creation completed in {creation_time:.2f} seconds")
    logger.info(f"Total assets created: {len(result.asns) + len(result.ip_ranges) + len(result.domains) + sum(len(d.subdomains) for d in result.domains) + len(result.cloud_services)}")
    
    return result

def save_test_dataset(result: ReconnaissanceResult):
    """Save the test dataset to the database for testing."""
    logger.info("Saving test dataset to database...")
    start_time = time.time()
    
    # Initialize database
    db_manager.init_db()
    
    # Save the result
    success = db_manager.save_scan_result(result)
    
    save_time = time.time() - start_time
    
    if success:
        logger.info(f"Test dataset saved successfully in {save_time:.2f} seconds")
        return True
    else:
        logger.error("Failed to save test dataset")
        return False

def main():
    """Main testing function."""
    print("🧪 Performance Testing for Optimized Streamlit App")
    print("=" * 60)
    
    # Test different dataset sizes
    scales = ["small", "medium", "large"]
    
    if len(sys.argv) > 1:
        scale = sys.argv[1]
        if scale not in ["small", "medium", "large", "massive"]:
            print(f"Invalid scale: {scale}. Using 'medium'")
            scale = "medium"
    else:
        scale = "medium"
    
    print(f"Creating {scale} dataset for performance testing...")
    
    # Create test dataset
    test_result = create_large_test_dataset(scale)
    
    # Calculate metrics
    total_assets = (
        len(test_result.asns) + 
        len(test_result.ip_ranges) + 
        len(test_result.domains) + 
        sum(len(d.subdomains) for d in test_result.domains) + 
        len(test_result.cloud_services)
    )
    
    print(f"\n📊 Dataset Statistics:")
    print(f"   ASNs: {len(test_result.asns):,}")
    print(f"   IP Ranges: {len(test_result.ip_ranges):,}")
    print(f"   Domains: {len(test_result.domains):,}")
    print(f"   Subdomains: {sum(len(d.subdomains) for d in test_result.domains):,}")
    print(f"   Cloud Services: {len(test_result.cloud_services):,}")
    print(f"   Total Assets: {total_assets:,}")
    print(f"   Warnings: {len(test_result.warnings)}")
    
    # Save to database for testing
    print(f"\n💾 Saving {scale} dataset to database...")
    if save_test_dataset(test_result):
        print("✅ Dataset saved successfully!")
        print("\n🚀 You can now test the optimized Streamlit app with this dataset.")
        print("   1. Go to http://localhost:8501")
        print(f"   2. Look for '{test_result.target_organization}' in the scan history")
        print("   3. Load the results to test pagination and performance optimizations")
        print("\n💡 Performance features to test:")
        print("   • Streaming progress updates")
        print("   • Intelligent pagination with search/sort")
        print("   • Optimized large dataset display")
        print("   • Virtual scrolling for large tables")
        print("   • Intelligent caching and lazy loading")
    else:
        print("❌ Failed to save dataset")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 