"""
Centralized configuration management for the Organizational Asset Reconnaissance Tool.

This module provides configuration classes for managing API keys, reconnaissance settings,
and overall application configuration with support for environment variables and .env files.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path
import json

logger = logging.getLogger(__name__)

@dataclass
class APIConfig:
    """Configuration for external API keys and credentials."""
    
    # Search and Intelligence APIs
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    
    # OSINT and Threat Intelligence APIs
    alienvault_otx_api_key: Optional[str] = None
    urlvoid_api_key: Optional[str] = None
    hybrid_analysis_api_key: Optional[str] = None
    
    # Notification APIs
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    
    # Email configuration
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    
    def has_shodan_api(self) -> bool:
        """Check if Shodan API key is available."""
        return bool(self.shodan_api_key)
    
    def has_virustotal_api(self) -> bool:
        """Check if VirusTotal API key is available."""
        return bool(self.virustotal_api_key)
    
    def has_censys_api(self) -> bool:
        """Check if Censys API credentials are available."""
        return bool(self.censys_api_id and self.censys_api_secret)
    
    def has_securitytrails_api(self) -> bool:
        """Check if SecurityTrails API key is available."""
        return bool(self.securitytrails_api_key)
    
    def has_notification_apis(self) -> bool:
        """Check if any notification API is configured."""
        return any([
            self.slack_webhook_url,
            self.discord_webhook_url,
            (self.telegram_bot_token and self.telegram_chat_id)
        ])
    
    def has_email_config(self) -> bool:
        """Check if email configuration is complete."""
        return all([
            self.smtp_server,
            self.smtp_username,
            self.smtp_password
        ])
    
    def get_available_apis(self) -> List[str]:
        """Get list of available/configured APIs."""
        available = []
        if self.has_shodan_api():
            available.append("Shodan")
        if self.has_virustotal_api():
            available.append("VirusTotal")
        if self.has_censys_api():
            available.append("Censys")
        if self.has_securitytrails_api():
            available.append("SecurityTrails")
        if self.alienvault_otx_api_key:
            available.append("AlienVault OTX")
        return available

@dataclass 
class ReconConfig:
    """Configuration for reconnaissance behavior and limits."""
    
    # General settings
    max_workers: int = 10
    timeout_seconds: int = 30
    rate_limit_delay: float = 1.0
    max_retries: int = 3
    
    # Discovery limits
    max_subdomains_per_domain: int = 1000
    max_ip_ranges_per_asn: int = 500
    max_asns_per_org: int = 50
    
    # Rate limiting settings per source
    rate_limits: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "bgp_he_net": {"requests_per_minute": 30, "requests_per_hour": 1000},
        "crt_sh": {"requests_per_minute": 60, "requests_per_hour": 2000},
        "dnsdumpster": {"requests_per_minute": 10, "requests_per_hour": 100},
        "shodan": {"requests_per_minute": 10, "requests_per_hour": 100},
        "virustotal": {"requests_per_minute": 4, "requests_per_hour": 500},
        "censys": {"requests_per_minute": 10, "requests_per_hour": 1000},
        "securitytrails": {"requests_per_minute": 10, "requests_per_hour": 1000}
    })
    
    # Cache settings
    cache_enabled: bool = True
    cache_ttl_hours: Dict[str, int] = field(default_factory=lambda: {
        "asn_queries": 24,
        "ip_ranges": 24, 
        "dns_resolution": 6,
        "crt_sh_queries": 12,
        "whois_queries": 48,
        "threat_intel": 2
    })
    
    # Discovery modules to enable/disable
    enable_subdomain_discovery: bool = True
    enable_cloud_detection: bool = True
    enable_threat_intelligence: bool = True
    enable_asset_validation: bool = True
    
    # Validation settings
    validate_domains: bool = True
    validate_ip_ranges: bool = True
    dns_timeout: float = 5.0
    http_timeout: float = 10.0
    
    # Export settings
    default_export_format: str = "json"  # json, csv, txt, html
    include_metadata: bool = True
    compress_exports: bool = False
    
    def get_rate_limit(self, source: str, period: str = "minute") -> int:
        """Get rate limit for a specific source and time period."""
        if source not in self.rate_limits:
            return 60 if period == "minute" else 1000
        
        period_key = f"requests_per_{period}"
        return self.rate_limits[source].get(period_key, 60 if period == "minute" else 1000)
    
    def get_cache_ttl(self, query_type: str) -> int:
        """Get cache TTL in hours for a specific query type."""
        return self.cache_ttl_hours.get(query_type, 6)

@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    
    # SQLite settings (default)
    sqlite_path: str = "recon_results.db"
    sqlite_timeout: float = 30.0
    
    # PostgreSQL settings (optional)
    postgres_enabled: bool = False
    postgres_host: Optional[str] = None
    postgres_port: int = 5432
    postgres_database: Optional[str] = None
    postgres_username: Optional[str] = None
    postgres_password: Optional[str] = None
    postgres_ssl_mode: str = "prefer"
    
    # Connection pooling
    connection_pool_size: int = 5
    connection_pool_max_overflow: int = 10
    
    def get_postgres_url(self) -> Optional[str]:
        """Get PostgreSQL connection URL if configured."""
        if not self.postgres_enabled or not all([
            self.postgres_host, self.postgres_database, 
            self.postgres_username, self.postgres_password
        ]):
            return None
        
        return (f"postgresql://{self.postgres_username}:{self.postgres_password}"
                f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_database}"
                f"?sslmode={self.postgres_ssl_mode}")

class Settings:
    """Main settings class that loads and manages all configuration."""
    
    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize settings from environment variables and optional .env file.
        
        Args:
            env_file: Path to .env file to load (optional)
        """
        self.api = APIConfig()
        self.recon = ReconConfig()
        self.database = DatabaseConfig()
        
        # Load from .env file if specified
        if env_file:
            self._load_env_file(env_file)
        
        # Load from environment variables
        self._load_from_env()
        
        # Validate configuration
        self._validate_config()
    
    def _load_env_file(self, env_file: str):
        """Load configuration from .env file."""
        env_path = Path(env_file)
        if not env_path.exists():
            logger.warning(f"Environment file {env_file} not found")
            return
        
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        os.environ[key] = value
            logger.info(f"Loaded environment variables from {env_file}")
        except Exception as e:
            logger.error(f"Error loading .env file {env_file}: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables and encrypted storage."""
        
        # Import here to avoid circular import
        from .secrets import get_api_key_manager
        api_key_manager = get_api_key_manager()
        
        # Load API configuration with fallback to encrypted storage
        self.api.shodan_api_key = api_key_manager.get_api_key("shodan", "SHODAN_API_KEY")
        self.api.virustotal_api_key = api_key_manager.get_api_key("virustotal", "VIRUSTOTAL_API_KEY")
        self.api.censys_api_id = api_key_manager.get_api_key("censys_id", "CENSYS_API_ID")
        self.api.censys_api_secret = api_key_manager.get_api_key("censys_secret", "CENSYS_API_SECRET")
        self.api.securitytrails_api_key = api_key_manager.get_api_key("securitytrails", "SECURITYTRAILS_API_KEY")
        self.api.alienvault_otx_api_key = api_key_manager.get_api_key("alienvault_otx", "ALIENVAULT_OTX_API_KEY")
        
        # Notification APIs (not encrypted for now, but could be extended)
        self.api.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        self.api.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        self.api.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.api.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        
        # Email configuration
        self.api.smtp_server = os.getenv("SMTP_SERVER")
        self.api.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.api.smtp_username = os.getenv("SMTP_USERNAME")
        self.api.smtp_password = os.getenv("SMTP_PASSWORD")
        self.api.smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
        
        # Load reconnaissance configuration
        self.recon.max_workers = int(os.getenv("RECON_MAX_WORKERS", "10"))
        self.recon.timeout_seconds = int(os.getenv("RECON_TIMEOUT_SECONDS", "30"))
        self.recon.rate_limit_delay = float(os.getenv("RECON_RATE_LIMIT_DELAY", "1.0"))
        self.recon.max_retries = int(os.getenv("RECON_MAX_RETRIES", "3"))
        
        # Discovery limits
        self.recon.max_subdomains_per_domain = int(os.getenv("MAX_SUBDOMAINS_PER_DOMAIN", "1000"))
        self.recon.max_ip_ranges_per_asn = int(os.getenv("MAX_IP_RANGES_PER_ASN", "500"))
        self.recon.max_asns_per_org = int(os.getenv("MAX_ASNS_PER_ORG", "50"))
        
        # Feature flags
        self.recon.enable_subdomain_discovery = os.getenv("ENABLE_SUBDOMAIN_DISCOVERY", "true").lower() == "true"
        self.recon.enable_cloud_detection = os.getenv("ENABLE_CLOUD_DETECTION", "true").lower() == "true"
        self.recon.enable_threat_intelligence = os.getenv("ENABLE_THREAT_INTELLIGENCE", "true").lower() == "true"
        self.recon.enable_asset_validation = os.getenv("ENABLE_ASSET_VALIDATION", "true").lower() == "true"
        
        # Cache settings
        self.recon.cache_enabled = os.getenv("CACHE_ENABLED", "true").lower() == "true"
        
        # Database configuration
        self.database.sqlite_path = os.getenv("SQLITE_PATH", "recon_results.db")
        self.database.postgres_enabled = os.getenv("POSTGRES_ENABLED", "false").lower() == "true"
        self.database.postgres_host = os.getenv("POSTGRES_HOST")
        self.database.postgres_port = int(os.getenv("POSTGRES_PORT", "5432"))
        self.database.postgres_database = os.getenv("POSTGRES_DATABASE")
        self.database.postgres_username = os.getenv("POSTGRES_USERNAME")
        self.database.postgres_password = os.getenv("POSTGRES_PASSWORD")
    
    def _validate_config(self):
        """Validate configuration and log warnings for missing components."""
        warnings = []
        
        # Check for premium APIs
        if not self.api.has_shodan_api():
            warnings.append("Shodan API key not configured - advanced IP/service discovery disabled")
        
        if not self.api.has_virustotal_api():
            warnings.append("VirusTotal API key not configured - malware/reputation analysis disabled")
        
        if not self.api.has_censys_api():
            warnings.append("Censys API credentials not configured - certificate/service discovery limited")
        
        # Check notification setup
        if not self.api.has_notification_apis() and not self.api.has_email_config():
            warnings.append("No notification methods configured - alerts will only be logged")
        
        # Log warnings
        for warning in warnings:
            logger.warning(f"Configuration: {warning}")
        
        # Log available APIs
        available_apis = self.api.get_available_apis()
        if available_apis:
            logger.info(f"Available premium APIs: {', '.join(available_apis)}")
        else:
            logger.info("No premium APIs configured - using public sources only")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary (excluding sensitive data)."""
        return {
            "api": {
                "available_apis": self.api.get_available_apis(),
                "has_notification_apis": self.api.has_notification_apis(),
                "has_email_config": self.api.has_email_config()
            },
            "recon": {
                "max_workers": self.recon.max_workers,
                "timeout_seconds": self.recon.timeout_seconds,
                "max_subdomains_per_domain": self.recon.max_subdomains_per_domain,
                "cache_enabled": self.recon.cache_enabled,
                "enabled_features": {
                    "subdomain_discovery": self.recon.enable_subdomain_discovery,
                    "cloud_detection": self.recon.enable_cloud_detection,
                    "threat_intelligence": self.recon.enable_threat_intelligence,
                    "asset_validation": self.recon.enable_asset_validation
                }
            },
            "database": {
                "type": "postgresql" if self.database.postgres_enabled else "sqlite",
                "path": self.database.sqlite_path if not self.database.postgres_enabled else None
            }
        }
    
    def save_to_file(self, file_path: str):
        """Save non-sensitive configuration to JSON file."""
        config_dict = self.to_dict()
        try:
            with open(file_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
            logger.info(f"Configuration saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving configuration to {file_path}: {e}")

# Global settings instance
_settings: Optional[Settings] = None

def get_settings(env_file: Optional[str] = None, reload: bool = False) -> Settings:
    """
    Get global settings instance (singleton pattern).
    
    Args:
        env_file: Path to .env file to load
        reload: Force reload of settings
        
    Returns:
        Settings instance
    """
    global _settings
    
    if _settings is None or reload:
        _settings = Settings(env_file=env_file)
    
    return _settings

def load_settings_from_file(config_file: str) -> Optional[Settings]:
    """
    Load settings from a JSON configuration file.
    
    Args:
        config_file: Path to JSON configuration file
        
    Returns:
        Settings instance or None if loading failed
    """
    try:
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        # This would need more complex logic to properly restore from JSON
        # For now, just log that it's not fully implemented
        logger.warning("Loading from JSON config file not fully implemented yet")
        return None
        
    except Exception as e:
        logger.error(f"Error loading configuration from {config_file}: {e}")
        return None 