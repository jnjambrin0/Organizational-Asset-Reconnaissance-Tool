"""
Organizational Asset Reconnaissance Tool - Configuration Module
Author: jnjambrino 

DEPRECATED: This file is deprecated. Use src.config.settings instead.
Keeping for backward compatibility during transition.
"""

import logging
from src.config.settings import get_settings

logger = logging.getLogger(__name__)

# Issue deprecation warning
logger.warning(
    "src.config is deprecated. Please use 'from src.config.settings import get_settings' instead. "
    "This module will be removed in a future version."
)

# Get settings instance
settings = get_settings()

# Legacy compatibility - expose old constants
TIMEOUT_SECONDS = settings.recon.timeout_seconds

# Expose new settings for easy migration
api_config = settings.api
recon_config = settings.recon
database_config = settings.database

# Legacy API key access (deprecated)
SHODAN_API_KEY = settings.api.shodan_api_key
VIRUSTOTAL_API_KEY = settings.api.virustotal_api_key

# Example: Load from environment variables
# import os
# SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
 
# Placeholder for now
TIMEOUT_SECONDS = 30 