"""
Secure secrets management for API keys and sensitive configuration.

This module provides encryption/decryption capabilities for storing API keys
and other sensitive data securely.
"""

import os
import base64
import json
import logging
from typing import Dict, Optional, Any
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

class SecretsManager:
    """Manages encrypted storage of API keys and sensitive configuration."""
    
    def __init__(self, secrets_file: str = "secrets.enc", password: Optional[str] = None):
        """
        Initialize the secrets manager.
        
        Args:
            secrets_file: Path to the encrypted secrets file
            password: Master password for encryption (if None, uses environment variable)
        """
        self.secrets_file = Path(secrets_file)
        self.password = password or os.getenv("SECRETS_PASSWORD")
        self._fernet = None
        
        if not self.password:
            logger.warning("No secrets password provided. Encrypted storage disabled.")
    
    def _get_cipher(self) -> Optional[Fernet]:
        """Get or create the encryption cipher."""
        if not self.password:
            return None
            
        if self._fernet is None:
            # Derive key from password
            salt = b'org_recon_salt'  # In production, use a random salt stored separately
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
            self._fernet = Fernet(key)
        
        return self._fernet
    
    def save_secrets(self, secrets: Dict[str, Any]) -> bool:
        """
        Save secrets to encrypted file.
        
        Args:
            secrets: Dictionary of secrets to encrypt and save
            
        Returns:
            True if successful, False otherwise
        """
        cipher = self._get_cipher()
        if not cipher:
            logger.error("Cannot save secrets: no encryption password provided")
            return False
        
        try:
            # Convert to JSON and encrypt
            secrets_json = json.dumps(secrets, indent=2)
            encrypted_data = cipher.encrypt(secrets_json.encode())
            
            # Save to file
            with open(self.secrets_file, 'wb') as f:
                f.write(encrypted_data)
            
            logger.info(f"Secrets saved to {self.secrets_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving secrets: {e}")
            return False
    
    def load_secrets(self) -> Dict[str, Any]:
        """
        Load and decrypt secrets from file.
        
        Returns:
            Dictionary of decrypted secrets, empty dict if error
        """
        cipher = self._get_cipher()
        if not cipher:
            logger.warning("Cannot load secrets: no encryption password provided")
            return {}
        
        if not self.secrets_file.exists():
            logger.info(f"Secrets file {self.secrets_file} not found")
            return {}
        
        try:
            # Read and decrypt
            with open(self.secrets_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = cipher.decrypt(encrypted_data)
            secrets = json.loads(decrypted_data.decode())
            
            logger.info(f"Secrets loaded from {self.secrets_file}")
            return secrets
            
        except Exception as e:
            logger.error(f"Error loading secrets: {e}")
            return {}
    
    def update_secret(self, key: str, value: str) -> bool:
        """
        Update a single secret value.
        
        Args:
            key: Secret key name
            value: Secret value
            
        Returns:
            True if successful, False otherwise
        """
        secrets = self.load_secrets()
        secrets[key] = value
        return self.save_secrets(secrets)
    
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a single secret value.
        
        Args:
            key: Secret key name
            default: Default value if key not found
            
        Returns:
            Secret value or default
        """
        secrets = self.load_secrets()
        return secrets.get(key, default)
    
    def delete_secret(self, key: str) -> bool:
        """
        Delete a secret.
        
        Args:
            key: Secret key name
            
        Returns:
            True if successful, False otherwise
        """
        secrets = self.load_secrets()
        if key in secrets:
            del secrets[key]
            return self.save_secrets(secrets)
        return True
    
    def list_secret_keys(self) -> list:
        """
        List all secret keys (without values).
        
        Returns:
            List of secret key names
        """
        secrets = self.load_secrets()
        return list(secrets.keys())
    
    def secrets_file_exists(self) -> bool:
        """Check if the secrets file exists."""
        return self.secrets_file.exists()
    
    def delete_secrets_file(self) -> bool:
        """
        Delete the secrets file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.secrets_file.exists():
                self.secrets_file.unlink()
                logger.info(f"Secrets file {self.secrets_file} deleted")
            return True
        except Exception as e:
            logger.error(f"Error deleting secrets file: {e}")
            return False

class APIKeyManager:
    """High-level manager for API keys with fallback to environment variables."""
    
    def __init__(self, secrets_manager: Optional[SecretsManager] = None):
        """
        Initialize API key manager.
        
        Args:
            secrets_manager: SecretsManager instance (optional)
        """
        self.secrets_manager = secrets_manager or SecretsManager()
    
    def get_api_key(self, service: str, env_var: str) -> Optional[str]:
        """
        Get API key with fallback chain: encrypted storage -> environment variable.
        
        Args:
            service: Service name (e.g., 'shodan', 'virustotal')
            env_var: Environment variable name
            
        Returns:
            API key or None if not found
        """
        # Try encrypted storage first
        if self.secrets_manager.secrets_file_exists():
            encrypted_key = self.secrets_manager.get_secret(f"{service}_api_key")
            if encrypted_key:
                return encrypted_key
        
        # Fallback to environment variable
        return os.getenv(env_var)
    
    def set_api_key(self, service: str, api_key: str) -> bool:
        """
        Store API key in encrypted storage.
        
        Args:
            service: Service name
            api_key: API key value
            
        Returns:
            True if successful, False otherwise
        """
        return self.secrets_manager.update_secret(f"{service}_api_key", api_key)
    
    def get_all_api_keys(self) -> Dict[str, str]:
        """
        Get all configured API keys.
        
        Returns:
            Dictionary of service -> API key
        """
        api_keys = {}
        
        # Define known services and their env vars
        services = {
            'shodan': 'SHODAN_API_KEY',
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'securitytrails': 'SECURITYTRAILS_API_KEY',
            'censys_id': 'CENSYS_API_ID',
            'censys_secret': 'CENSYS_API_SECRET',
            'alienvault_otx': 'ALIENVAULT_OTX_API_KEY'
        }
        
        for service, env_var in services.items():
            api_key = self.get_api_key(service, env_var)
            if api_key:
                api_keys[service] = api_key
        
        return api_keys
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """
        Validate API keys (basic format validation).
        
        Returns:
            Dictionary of service -> is_valid
        """
        api_keys = self.get_all_api_keys()
        validation_results = {}
        
        for service, api_key in api_keys.items():
            # Basic validation - check if not empty and reasonable length
            is_valid = bool(api_key and len(api_key) > 10)
            validation_results[service] = is_valid
        
        return validation_results

# Global instance
_secrets_manager: Optional[SecretsManager] = None
_api_key_manager: Optional[APIKeyManager] = None

def get_secrets_manager(password: Optional[str] = None) -> SecretsManager:
    """Get global secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager(password=password)
    return _secrets_manager

def get_api_key_manager() -> APIKeyManager:
    """Get global API key manager instance."""
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager(get_secrets_manager())
    return _api_key_manager 