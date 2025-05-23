"""
Automatic API key rotation management.

This module provides functionality for automatic rotation of API keys
when supported by the service provider.
"""

import logging
import datetime
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from .secrets import get_api_key_manager, get_secrets_manager

logger = logging.getLogger(__name__)

@dataclass
class KeyRotationConfig:
    """Configuration for API key rotation."""
    service: str
    rotation_interval_days: int
    warning_days_before_expiry: int = 7
    auto_rotate: bool = False
    supports_rotation: bool = False
    last_rotation: Optional[datetime.datetime] = None
    next_rotation: Optional[datetime.datetime] = None

class KeyRotationManager:
    """Manages automatic rotation of API keys."""
    
    def __init__(self):
        self.api_manager = get_api_key_manager()
        self.secrets_manager = get_secrets_manager()
        
        # Default rotation configurations for different services
        self.rotation_configs = {
            "shodan": KeyRotationConfig(
                service="shodan",
                rotation_interval_days=90,
                supports_rotation=False,  # Shodan doesn't support automatic rotation
                auto_rotate=False
            ),
            "virustotal": KeyRotationConfig(
                service="virustotal",
                rotation_interval_days=365,
                supports_rotation=False,  # VirusTotal doesn't support automatic rotation
                auto_rotate=False
            ),
            "securitytrails": KeyRotationConfig(
                service="securitytrails", 
                rotation_interval_days=180,
                supports_rotation=False,  # SecurityTrails doesn't support automatic rotation
                auto_rotate=False
            ),
            "censys": KeyRotationConfig(
                service="censys",
                rotation_interval_days=365,
                supports_rotation=False,  # Censys doesn't support automatic rotation
                auto_rotate=False
            ),
            "alienvault_otx": KeyRotationConfig(
                service="alienvault_otx",
                rotation_interval_days=365,
                supports_rotation=False,  # AlienVault OTX doesn't support automatic rotation
                auto_rotate=False
            )
        }
    
    def check_key_expiry(self, service: str) -> Tuple[bool, int]:
        """
        Check if an API key is approaching expiry.
        
        Args:
            service: Service name
            
        Returns:
            Tuple of (needs_attention, days_until_expiry)
        """
        config = self.rotation_configs.get(service)
        if not config or not config.last_rotation:
            return False, -1
        
        # Calculate days since last rotation
        days_since_rotation = (datetime.datetime.now() - config.last_rotation).days
        days_until_expiry = config.rotation_interval_days - days_since_rotation
        
        # Check if within warning period
        needs_attention = days_until_expiry <= config.warning_days_before_expiry
        
        return needs_attention, days_until_expiry
    
    def get_rotation_status(self) -> Dict[str, Dict]:
        """
        Get rotation status for all configured services.
        
        Returns:
            Dictionary of service -> status information
        """
        status = {}
        
        for service, config in self.rotation_configs.items():
            # Check if API key is configured
            api_key = self.api_manager.get_api_key(service, f"{service.upper()}_API_KEY")
            
            if not api_key:
                status[service] = {
                    "configured": False,
                    "supports_rotation": config.supports_rotation,
                    "status": "not_configured"
                }
                continue
            
            needs_attention, days_until_expiry = self.check_key_expiry(service)
            
            status[service] = {
                "configured": True,
                "supports_rotation": config.supports_rotation,
                "auto_rotate": config.auto_rotate,
                "last_rotation": config.last_rotation.isoformat() if config.last_rotation else None,
                "next_rotation": config.next_rotation.isoformat() if config.next_rotation else None,
                "days_until_expiry": days_until_expiry if days_until_expiry > 0 else None,
                "needs_attention": needs_attention,
                "status": self._get_status_text(config, needs_attention, days_until_expiry)
            }
        
        return status
    
    def _get_status_text(self, config: KeyRotationConfig, needs_attention: bool, days_until_expiry: int) -> str:
        """Get human-readable status text."""
        if not config.supports_rotation:
            return "manual_rotation_required"
        
        if needs_attention:
            if days_until_expiry <= 0:
                return "expired"
            else:
                return "expiring_soon"
        
        return "valid"
    
    def set_rotation_config(self, service: str, rotation_interval_days: int, auto_rotate: bool = False):
        """
        Update rotation configuration for a service.
        
        Args:
            service: Service name
            rotation_interval_days: Days between rotations
            auto_rotate: Enable automatic rotation (if supported)
        """
        if service in self.rotation_configs:
            config = self.rotation_configs[service]
            config.rotation_interval_days = rotation_interval_days
            config.auto_rotate = auto_rotate and config.supports_rotation
            
            # Update next rotation date if last rotation is known
            if config.last_rotation:
                config.next_rotation = config.last_rotation + datetime.timedelta(days=rotation_interval_days)
            
            logger.info(f"Updated rotation config for {service}: {rotation_interval_days} days, auto_rotate={auto_rotate}")
    
    def mark_key_rotated(self, service: str):
        """
        Mark an API key as manually rotated.
        
        Args:
            service: Service name
        """
        if service in self.rotation_configs:
            config = self.rotation_configs[service]
            config.last_rotation = datetime.datetime.now()
            config.next_rotation = config.last_rotation + datetime.timedelta(days=config.rotation_interval_days)
            
            # Save rotation timestamp to secrets
            rotation_key = f"{service}_last_rotation"
            self.secrets_manager.update_secret(rotation_key, config.last_rotation.isoformat())
            
            logger.info(f"Marked {service} API key as rotated")
    
    def load_rotation_history(self):
        """Load rotation history from encrypted storage."""
        for service in self.rotation_configs:
            rotation_key = f"{service}_last_rotation"
            last_rotation_str = self.secrets_manager.get_secret(rotation_key)
            
            if last_rotation_str:
                try:
                    last_rotation = datetime.datetime.fromisoformat(last_rotation_str)
                    config = self.rotation_configs[service]
                    config.last_rotation = last_rotation
                    config.next_rotation = last_rotation + datetime.timedelta(days=config.rotation_interval_days)
                except ValueError:
                    logger.warning(f"Invalid rotation date format for {service}: {last_rotation_str}")
    
    def get_keys_needing_attention(self) -> List[Dict]:
        """
        Get list of API keys that need attention (expiring or expired).
        
        Returns:
            List of dictionaries with key information
        """
        keys_needing_attention = []
        status = self.get_rotation_status()
        
        for service, info in status.items():
            if info.get("configured") and info.get("needs_attention"):
                keys_needing_attention.append({
                    "service": service,
                    "status": info["status"],
                    "days_until_expiry": info.get("days_until_expiry"),
                    "supports_auto_rotation": info["supports_rotation"]
                })
        
        return keys_needing_attention
    
    def rotate_key_if_supported(self, service: str) -> bool:
        """
        Attempt to rotate an API key automatically if supported.
        
        Args:
            service: Service name
            
        Returns:
            True if rotation was successful, False otherwise
        """
        config = self.rotation_configs.get(service)
        if not config or not config.supports_rotation:
            logger.warning(f"Automatic rotation not supported for {service}")
            return False
        
        # TODO: Implement actual API key rotation for services that support it
        # This would require service-specific API calls to generate new keys
        logger.info(f"Automatic rotation for {service} is not implemented yet")
        return False
    
    def generate_rotation_report(self) -> Dict:
        """
        Generate a comprehensive rotation report.
        
        Returns:
            Dictionary with rotation status and recommendations
        """
        status = self.get_rotation_status()
        keys_needing_attention = self.get_keys_needing_attention()
        
        # Calculate summary statistics
        total_keys = len([s for s in status.values() if s["configured"]])
        keys_with_rotation_support = len([s for s in status.values() if s["configured"] and s["supports_rotation"]])
        keys_expiring_soon = len([k for k in keys_needing_attention if k["status"] == "expiring_soon"])
        keys_expired = len([k for k in keys_needing_attention if k["status"] == "expired"])
        
        return {
            "summary": {
                "total_configured_keys": total_keys,
                "keys_with_rotation_support": keys_with_rotation_support,
                "keys_expiring_soon": keys_expiring_soon,
                "keys_expired": keys_expired,
                "keys_needing_manual_rotation": len(keys_needing_attention)
            },
            "detailed_status": status,
            "keys_needing_attention": keys_needing_attention,
            "recommendations": self._generate_recommendations(status, keys_needing_attention)
        }
    
    def _generate_recommendations(self, status: Dict, keys_needing_attention: List[Dict]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if keys_needing_attention:
            expired_keys = [k for k in keys_needing_attention if k["status"] == "expired"]
            if expired_keys:
                recommendations.append(f"🚨 {len(expired_keys)} API key(s) have expired and need immediate replacement")
            
            expiring_keys = [k for k in keys_needing_attention if k["status"] == "expiring_soon"]
            if expiring_keys:
                recommendations.append(f"⚠️ {len(expiring_keys)} API key(s) are expiring soon and should be rotated")
        
        # Check for services without rotation tracking
        untracked_services = [s for s, info in status.items() if info["configured"] and not info.get("last_rotation")]
        if untracked_services:
            recommendations.append(f"📅 {len(untracked_services)} service(s) don't have rotation tracking. Consider marking rotation dates.")
        
        if not recommendations:
            recommendations.append("✅ All API keys are in good standing")
        
        return recommendations

# Global instance
_rotation_manager: Optional[KeyRotationManager] = None

def get_rotation_manager() -> KeyRotationManager:
    """Get global key rotation manager instance."""
    global _rotation_manager
    if _rotation_manager is None:
        _rotation_manager = KeyRotationManager()
        _rotation_manager.load_rotation_history()
    return _rotation_manager 