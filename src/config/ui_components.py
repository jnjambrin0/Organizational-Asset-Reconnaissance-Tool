"""
UI components for configuring API keys and settings through Streamlit interface.
"""

import streamlit as st
import logging
from typing import Dict, Any, Optional
from .settings import get_settings
from .secrets import get_api_key_manager, get_secrets_manager

logger = logging.getLogger(__name__)

def render_api_configuration():
    """Render the API configuration interface."""
    st.header("🔑 API Configuration")
    
    # Get current settings and API manager
    settings = get_settings()
    api_manager = get_api_key_manager()
    
    # Check if secrets encryption is available
    secrets_manager = get_secrets_manager()
    encryption_available = bool(secrets_manager.password)
    
    if not encryption_available:
        st.warning(
            "⚠️ Secrets encryption is disabled. Set the `SECRETS_PASSWORD` environment variable "
            "to enable secure API key storage."
        )
    
    # API Keys Configuration
    st.subheader("Premium API Keys")
    
    with st.expander("🔍 Search & Discovery APIs", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            # Shodan API
            st.markdown("**Shodan API**")
            current_shodan = "Configured ✅" if settings.api.has_shodan_api() else "Not configured ❌"
            st.caption(f"Status: {current_shodan}")
            
            shodan_key = st.text_input(
                "Shodan API Key",
                type="password",
                placeholder="Enter your Shodan API key",
                help="Get your API key from https://account.shodan.io/",
                key="shodan_api_key"
            )
            
            if st.button("Save Shodan Key", key="save_shodan"):
                if shodan_key:
                    if encryption_available:
                        if api_manager.set_api_key("shodan", shodan_key):
                            st.success("Shodan API key saved securely!")
                            st.rerun()
                        else:
                            st.error("Failed to save Shodan API key")
                    else:
                        st.info("Set SHODAN_API_KEY environment variable to use this key")
                else:
                    st.error("Please enter a valid API key")
        
        with col2:
            # VirusTotal API
            st.markdown("**VirusTotal API**")
            current_vt = "Configured ✅" if settings.api.has_virustotal_api() else "Not configured ❌"
            st.caption(f"Status: {current_vt}")
            
            vt_key = st.text_input(
                "VirusTotal API Key",
                type="password", 
                placeholder="Enter your VirusTotal API key",
                help="Get your API key from https://www.virustotal.com/gui/my-apikey",
                key="virustotal_api_key"
            )
            
            if st.button("Save VirusTotal Key", key="save_vt"):
                if vt_key:
                    if encryption_available:
                        if api_manager.set_api_key("virustotal", vt_key):
                            st.success("VirusTotal API key saved securely!")
                            st.rerun()
                        else:
                            st.error("Failed to save VirusTotal API key")
                    else:
                        st.info("Set VIRUSTOTAL_API_KEY environment variable to use this key")
                else:
                    st.error("Please enter a valid API key")
    
    with st.expander("🔐 Certificate & Service APIs"):
        col1, col2 = st.columns(2)
        
        with col1:
            # Censys API
            st.markdown("**Censys API**")
            current_censys = "Configured ✅" if settings.api.has_censys_api() else "Not configured ❌"
            st.caption(f"Status: {current_censys}")
            
            censys_id = st.text_input(
                "Censys API ID",
                placeholder="Enter your Censys API ID",
                help="Get your credentials from https://censys.io/account",
                key="censys_api_id"
            )
            
            censys_secret = st.text_input(
                "Censys API Secret",
                type="password",
                placeholder="Enter your Censys API Secret", 
                key="censys_api_secret"
            )
            
            if st.button("Save Censys Credentials", key="save_censys"):
                if censys_id and censys_secret:
                    if encryption_available:
                        success = (
                            api_manager.set_api_key("censys_id", censys_id) and
                            api_manager.set_api_key("censys_secret", censys_secret)
                        )
                        if success:
                            st.success("Censys API credentials saved securely!")
                            st.rerun()
                        else:
                            st.error("Failed to save Censys API credentials")
                    else:
                        st.info("Set CENSYS_API_ID and CENSYS_API_SECRET environment variables")
                else:
                    st.error("Please enter both API ID and Secret")
        
        with col2:
            # SecurityTrails API
            st.markdown("**SecurityTrails API**")
            current_st = "Configured ✅" if settings.api.has_securitytrails_api() else "Not configured ❌"
            st.caption(f"Status: {current_st}")
            
            st_key = st.text_input(
                "SecurityTrails API Key",
                type="password",
                placeholder="Enter your SecurityTrails API key",
                help="Get your API key from https://securitytrails.com/corp/apidocs",
                key="securitytrails_api_key"
            )
            
            if st.button("Save SecurityTrails Key", key="save_st"):
                if st_key:
                    if encryption_available:
                        if api_manager.set_api_key("securitytrails", st_key):
                            st.success("SecurityTrails API key saved securely!")
                            st.rerun()
                        else:
                            st.error("Failed to save SecurityTrails API key")
                    else:
                        st.info("Set SECURITYTRAILS_API_KEY environment variable to use this key")
                else:
                    st.error("Please enter a valid API key")

def render_notification_configuration():
    """Render the notification configuration interface."""
    st.header("📢 Notification Configuration")
    
    settings = get_settings()
    
    with st.expander("📱 Messaging Platforms", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Slack Integration**")
            slack_status = "Configured ✅" if settings.api.slack_webhook_url else "Not configured ❌"
            st.caption(f"Status: {slack_status}")
            
            slack_webhook = st.text_input(
                "Slack Webhook URL",
                type="password",
                placeholder="https://hooks.slack.com/services/...",
                help="Create a webhook in your Slack workspace",
                key="slack_webhook"
            )
            
            if st.button("Test Slack Notification", key="test_slack"):
                if slack_webhook:
                    # TODO: Implement actual test
                    st.info("Slack notification test not implemented yet")
                else:
                    st.error("Please enter a webhook URL first")
        
        with col2:
            st.markdown("**Discord Integration**")
            discord_status = "Configured ✅" if settings.api.discord_webhook_url else "Not configured ❌"
            st.caption(f"Status: {discord_status}")
            
            discord_webhook = st.text_input(
                "Discord Webhook URL",
                type="password",
                placeholder="https://discord.com/api/webhooks/...",
                help="Create a webhook in your Discord server",
                key="discord_webhook"
            )
    
    with st.expander("📧 Email Configuration"):
        col1, col2 = st.columns(2)
        
        with col1:
            smtp_server = st.text_input(
                "SMTP Server",
                value=settings.api.smtp_server or "",
                placeholder="smtp.gmail.com",
                key="smtp_server"
            )
            
            smtp_port = st.number_input(
                "SMTP Port",
                value=settings.api.smtp_port,
                min_value=1,
                max_value=65535,
                key="smtp_port"
            )
            
            smtp_username = st.text_input(
                "SMTP Username",
                value=settings.api.smtp_username or "",
                placeholder="your-email@gmail.com",
                key="smtp_username"
            )
        
        with col2:
            smtp_password = st.text_input(
                "SMTP Password",
                type="password",
                placeholder="Your email password or app password",
                key="smtp_password"
            )
            
            smtp_use_tls = st.checkbox(
                "Use TLS",
                value=settings.api.smtp_use_tls,
                key="smtp_use_tls"
            )
            
            email_status = "Configured ✅" if settings.api.has_email_config() else "Not configured ❌"
            st.caption(f"Status: {email_status}")
        
        if st.button("Test Email Configuration", key="test_email"):
            if smtp_server and smtp_username and smtp_password:
                # TODO: Implement actual email test
                st.info("Email configuration test not implemented yet")
            else:
                st.error("Please fill in all email configuration fields")

def render_reconnaissance_configuration():
    """Render the reconnaissance settings interface."""
    st.header("⚙️ Reconnaissance Configuration")
    
    settings = get_settings()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Performance Settings")
        
        max_workers = st.slider(
            "Max Concurrent Workers",
            min_value=1,
            max_value=50,
            value=settings.recon.max_workers,
            help="Number of concurrent threads for discovery operations",
            key="max_workers"
        )
        
        timeout_seconds = st.slider(
            "Request Timeout (seconds)",
            min_value=5,
            max_value=120,
            value=settings.recon.timeout_seconds,
            help="Timeout for individual HTTP requests",
            key="timeout_seconds"
        )
        
        rate_limit_delay = st.slider(
            "Rate Limit Delay (seconds)",
            min_value=0.1,
            max_value=10.0,
            value=settings.recon.rate_limit_delay,
            step=0.1,
            help="Delay between requests to avoid rate limiting",
            key="rate_limit_delay"
        )
    
    with col2:
        st.subheader("Discovery Limits")
        
        max_subdomains = st.number_input(
            "Max Subdomains per Domain",
            min_value=10,
            max_value=10000,
            value=settings.recon.max_subdomains_per_domain,
            help="Maximum number of subdomains to discover per domain",
            key="max_subdomains"
        )
        
        max_ip_ranges = st.number_input(
            "Max IP Ranges per ASN",
            min_value=10,
            max_value=5000,
            value=settings.recon.max_ip_ranges_per_asn,
            help="Maximum number of IP ranges to discover per ASN",
            key="max_ip_ranges"
        )
        
        max_asns = st.number_input(
            "Max ASNs per Organization",
            min_value=1,
            max_value=500,
            value=settings.recon.max_asns_per_org,
            help="Maximum number of ASNs to discover per organization",
            key="max_asns"
        )
    
    st.subheader("Feature Toggles")
    
    col1, col2 = st.columns(2)
    
    with col1:
        enable_subdomain_discovery = st.checkbox(
            "Enable Subdomain Discovery",
            value=settings.recon.enable_subdomain_discovery,
            help="Enable discovery of subdomains using various sources",
            key="enable_subdomain_discovery"
        )
        
        enable_cloud_detection = st.checkbox(
            "Enable Cloud Detection",
            value=settings.recon.enable_cloud_detection,
            help="Enable detection of cloud service providers",
            key="enable_cloud_detection"
        )
    
    with col2:
        enable_threat_intelligence = st.checkbox(
            "Enable Threat Intelligence",
            value=settings.recon.enable_threat_intelligence,
            help="Enable threat intelligence checks for discovered assets",
            key="enable_threat_intelligence"
        )
        
        enable_asset_validation = st.checkbox(
            "Enable Asset Validation",
            value=settings.recon.enable_asset_validation,
            help="Enable validation of discovered assets (DNS, HTTP checks)",
            key="enable_asset_validation"
        )
    
    # Save configuration button
    if st.button("💾 Save Configuration", key="save_config", type="primary"):
        # TODO: Implement saving configuration changes
        st.success("Configuration saved! (Note: Implementation pending)")
        st.info("Currently, configuration changes require restarting the application to take effect.")

def render_configuration_page():
    """Render the complete configuration page."""
    st.title("⚙️ System Configuration")
    
    st.markdown("""
    Configure API keys, notification settings, and reconnaissance parameters.
    Changes will take effect after restarting the application.
    """)
    
    # Create tabs for different configuration sections
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔑 API Keys", 
        "📢 Notifications", 
        "⚙️ Reconnaissance", 
        "📊 Status"
    ])
    
    with tab1:
        render_api_configuration()
    
    with tab2:
        render_notification_configuration()
    
    with tab3:
        render_reconnaissance_configuration()
    
    with tab4:
        render_configuration_status()

def render_configuration_status():
    """Render the configuration status overview."""
    st.header("📊 Configuration Status")
    
    settings = get_settings()
    api_manager = get_api_key_manager()
    
    # API Status
    st.subheader("API Configuration Status")
    
    api_status = [
        ("Shodan", settings.api.has_shodan_api()),
        ("VirusTotal", settings.api.has_virustotal_api()),
        ("Censys", settings.api.has_censys_api()),
        ("SecurityTrails", settings.api.has_securitytrails_api()),
        ("AlienVault OTX", bool(settings.api.alienvault_otx_api_key))
    ]
    
    for api_name, is_configured in api_status:
        status_icon = "✅" if is_configured else "❌"
        status_text = "Configured" if is_configured else "Not configured"
        st.write(f"{status_icon} **{api_name}**: {status_text}")
    
    # Notification Status
    st.subheader("Notification Configuration Status")
    
    notification_status = [
        ("Slack", bool(settings.api.slack_webhook_url)),
        ("Discord", bool(settings.api.discord_webhook_url)),
        ("Email", settings.api.has_email_config()),
        ("Telegram", bool(settings.api.telegram_bot_token and settings.api.telegram_chat_id))
    ]
    
    for notif_name, is_configured in notification_status:
        status_icon = "✅" if is_configured else "❌"
        status_text = "Configured" if is_configured else "Not configured"
        st.write(f"{status_icon} **{notif_name}**: {status_text}")
    
    # Feature Status
    st.subheader("Feature Status")
    
    features = [
        ("Subdomain Discovery", settings.recon.enable_subdomain_discovery),
        ("Cloud Detection", settings.recon.enable_cloud_detection),
        ("Threat Intelligence", settings.recon.enable_threat_intelligence),
        ("Asset Validation", settings.recon.enable_asset_validation),
        ("Cache", settings.recon.cache_enabled)
    ]
    
    for feature_name, is_enabled in features:
        status_icon = "✅" if is_enabled else "❌"
        status_text = "Enabled" if is_enabled else "Disabled"
        st.write(f"{status_icon} **{feature_name}**: {status_text}")
    
    # System Information
    st.subheader("System Information")
    
    st.json({
        "Max Workers": settings.recon.max_workers,
        "Request Timeout": f"{settings.recon.timeout_seconds}s",
        "Rate Limit Delay": f"{settings.recon.rate_limit_delay}s",
        "Max Subdomains per Domain": settings.recon.max_subdomains_per_domain,
        "Max IP Ranges per ASN": settings.recon.max_ip_ranges_per_asn,
        "Max ASNs per Organization": settings.recon.max_asns_per_org,
        "Database Type": "PostgreSQL" if settings.database.postgres_enabled else "SQLite",
        "Database Path": settings.database.sqlite_path if not settings.database.postgres_enabled else "N/A"
    }) 