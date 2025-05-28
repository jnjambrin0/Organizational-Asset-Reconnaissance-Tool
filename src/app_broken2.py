import streamlit as st

# Set page config at the very beginning
st.set_page_config(
    layout="wide", 
    page_title="ReconForge - Enterprise Asset Discovery", 
    page_icon="🚀",
    initial_sidebar_state="expanded"
)

import logging
import io
import os
import time
import json
from datetime import datetime, timedelta
from typing import Set, List, Dict, Any, Optional, Tuple
import pandas as pd
import ipaddress

from src import db_manager
from src.utils.logging_config import StringLogHandler, setup_logging as configure_logging
from src.utils.logging_config import create_progress_logger, get_logger
from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, CloudService, Subdomain
from src.orchestration.intelligent_discovery_orchestrator import IntelligentDiscoveryOrchestrator
from src.visualization.network_graph import generate_network_graph

# --- Logger ---
logger = get_logger(__name__)

# --- Constants ---
DEFAULT_PAGINATION_SIZE = 50
DEFAULT_MAX_WORKERS = 10
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Enhanced icons with more modern look
ICONS = {
    "app": "🚀", "forge": "⚡", "enterprise": "🏢", "discovery": "🔬",
    "db": "💾", "load": "📂", "scan": "🎯", "summary": "📊", 
    "asn": "🌐", "ip": "💻", "domain": "🌍", "subdomain": "🔗", 
    "cloud": "☁️", "graph": "🕸️", "logs": "📋", "success": "✅", 
    "warning": "⚠️", "error": "❌", "info": "ℹ️", "pending": "⏳", 
    "running": "⌛", "completed": "✓", "security": "🛡️",
    "intelligence": "🧠", "analytics": "📈", "shield": "🔰",
    "radar": "📡", "target": "🎯", "search": "🔍"
}

# Modern Professional Color Palette
COLORS = {
    # Primary Brand Colors
    "primary": "#1E40AF",           # Deep Blue
    "primary_light": "#3B82F6",     # Blue-500
    "primary_dark": "#1E3A8A",      # Blue-800
    "primary_gradient": "linear-gradient(135deg, #1E40AF 0%, #3B82F6 50%, #60A5FA 100%)",
    
    # Secondary Colors
    "secondary": "#0F172A",         # Slate-900
    "secondary_light": "#334155",   # Slate-700
    "accent": "#059669",            # Emerald-600
    "accent_secondary": "#DC2626",  # Red-600
    "accent_warning": "#D97706",    # Amber-600
    "accent_info": "#0284C7",       # Sky-600
    
    # Background & Surfaces
    "background": "#F8FAFC",        # Slate-50
    "background_dark": "#0F172A",   # Slate-900
    "surface": "#FFFFFF",           # White
    "surface_secondary": "#F1F5F9", # Slate-100
    "surface_elevated": "#F8FAFC",  # Slate-50
    "surface_dark": "#1E293B",      # Slate-800
    
    # Text Colors
    "text": "#0F172A",              # Slate-900
    "text_secondary": "#475569",    # Slate-600
    "text_muted": "#64748B",        # Slate-500
    "text_light": "#94A3B8",        # Slate-400
    "text_inverse": "#F8FAFC",      # Slate-50
    
    # Semantic Colors
    "success": "#059669",           # Emerald-600
    "success_bg": "#ECFDF5",        # Emerald-50
    "warning": "#D97706",           # Amber-600
    "warning_bg": "#FFFBEB",        # Amber-50
    "error": "#DC2626",             # Red-600
    "error_bg": "#FEF2F2",          # Red-50
    "info": "#0284C7",              # Sky-600
    "info_bg": "#F0F9FF",           # Sky-50
    
    # Borders & Shadows
    "border": "#E2E8F0",            # Slate-200
    "border_light": "#F1F5F9",      # Slate-100
    "shadow": "rgba(15, 23, 42, 0.1)",
    "shadow_lg": "rgba(15, 23, 42, 0.15)",
    
    # Sidebar & Navigation
    "sidebar_bg": "#0F172A",        # Slate-900
    "sidebar_surface": "#1E293B",   # Slate-800
    "sidebar_text": "#F8FAFC",     # Slate-50
    "sidebar_text_muted": "#94A3B8" # Slate-400
}

def apply_professional_css():
    """Apply professional, modern CSS styling"""
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    .main {
        background: #F8FAFC;
        color: #0F172A;
        padding: 0;
        margin: 0;
    }
    
    /* Hide Streamlit Default Elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {visibility: hidden;}
    
    /* Enhanced Header Design */
    .professional-header {
        background: linear-gradient(135deg, #1E40AF 0%, #3B82F6 50%, #60A5FA 100%);
        position: relative;
        margin: -1rem -1rem 2rem -1rem;
        padding: 2.5rem 2rem 3rem 2rem;
        border-radius: 0 0 32px 32px;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        overflow: hidden;
    }
    
    .header-content {
        position: relative;
        z-index: 2;
        text-align: center;
    }
    
    .header-title {
        font-size: 3rem;
        font-weight: 800;
        color: white;
        margin: 0 0 0.5rem 0;
        text-shadow: 0 4px 8px rgba(0,0,0,0.2);
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 1rem;
        letter-spacing: -0.025em;
    }
    
    .header-subtitle {
        font-size: 1.25rem;
        color: rgba(255,255,255,0.9);
        margin: 0 0 1.5rem 0;
        font-weight: 400;
        letter-spacing: 0.025em;
    }
    
    .header-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.75rem;
        background: rgba(255,255,255,0.15);
        color: white;
        padding: 0.75rem 1.5rem;
        border-radius: 50px;
        font-size: 0.95rem;
        font-weight: 600;
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255,255,255,0.2);
        transition: all 0.25s ease-in-out;
    }
    
    /* Professional Cards */
    .professional-card {
        background: #FFFFFF;
        border-radius: 16px;
        padding: 2rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        border: 1px solid #F1F5F9;
        margin: 1.5rem 0;
        transition: all 0.25s ease-in-out;
        position: relative;
        overflow: hidden;
    }
    
    .professional-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(135deg, #1E40AF 0%, #3B82F6 100%);
    }
    
    .card-header {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1.5rem;
    }
    
    .card-icon {
        font-size: 2rem;
        opacity: 0.8;
    }
    
    .card-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #0F172A;
        margin: 0;
        line-height: 1.2;
    }
    
    .card-subtitle {
        font-size: 0.95rem;
        color: #64748B;
        margin: 0.25rem 0 0 0;
    }
    
    .card-content {
        padding: 0;
        color: #475569;
        line-height: 1.6;
    }
    
    /* Enhanced Metrics */
    .metric-card {
        background: #FFFFFF;
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
        border: 1px solid #F1F5F9;
        transition: all 0.25s ease-in-out;
        position: relative;
        overflow: hidden;
    }
    
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(135deg, #1E40AF 0%, #3B82F6 100%);
    }
    
    .metric-icon {
        font-size: 2rem;
        margin-bottom: 0.5rem;
        opacity: 0.8;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #1E40AF;
        margin: 0;
        line-height: 1;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: #64748B;
        margin: 0.5rem 0 0 0;
        font-weight: 500;
    }
    
    /* Status Badges */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.25rem 0.75rem;
        border-radius: 50px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .status-success {
        background: #ECFDF5;
        color: #059669;
        border: 1px solid #059669;
    }
    
    .status-warning {
        background: #FFFBEB;
        color: #D97706;
        border: 1px solid #D97706;
    }
    
    .status-error {
        background: #FEF2F2;
        color: #DC2626;
        border: 1px solid #DC2626;
    }
    
    .status-info {
        background: #F0F9FF;
        color: #0284C7;
        border: 1px solid #0284C7;
    }
    
    /* Enhanced Button Styling */
    .stButton > button {
        background: linear-gradient(135deg, #1E40AF 0%, #3B82F6 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        transition: all 0.25s ease-in-out !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
        padding: 0.75rem 1.5rem !important;
        font-size: 0.95rem !important;
    }
    
    /* Enhanced Input Styling */
    .stTextInput > div > div > input {
        background: #FFFFFF !important;
        border: 2px solid #E2E8F0 !important;
        border-radius: 12px !important;
        color: #0F172A !important;
        padding: 0.75rem 1rem !important;
        font-size: 0.95rem !important;
        font-weight: 500 !important;
        transition: all 0.15s ease-in-out !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #1E40AF !important;
        box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.1) !important;
        outline: none !important;
    }
    
    .stTextInput > div > div > input::placeholder {
        color: #94A3B8 !important;
        opacity: 0.8 !important;
        font-style: italic !important;
    }
    
    /* Animation Classes */
    .fade-in {
        animation: fadeIn 0.6s ease-in-out;
    }
    
    .fade-in-up {
        animation: fadeInUp 0.6s ease-in-out;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    @keyframes fadeInUp {
        from { 
            opacity: 0;
            transform: translateY(20px);
        }
        to { 
            opacity: 1;
            transform: translateY(0);
        }
    }
    </style>
    """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">{ICONS['domain']}</div>
            <div class="metric-value">{len(result.domains)}</div>
            <div class="metric-label">Domains Discovered</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">{ICONS['ip']}</div>
            <div class="metric-value">{len(result.ip_ranges)}</div>
            <div class="metric-label">IP Ranges</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">{ICONS['cloud']}</div>
            <div class="metric-value">{len(result.cloud_services)}</div>
            <div class="metric-label">Cloud Services</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)

# --- Add missing method to ReconnaissanceResult (if not defined in the class itself) ---
def ensure_to_json_method():
    """Monkey patch the ReconnaissanceResult class with to_json method if it doesn't exist"""
    if not hasattr(ReconnaissanceResult, 'to_json'):
        logger.debug("Patching ReconnaissanceResult with to_json method.")
        def to_json(self) -> str:
            """Convert the result to a JSON-formatted string"""
            try:
                # Use current DATE_FORMAT from constants
                current_time_str = datetime.now().strftime(DATE_FORMAT)
                data = {
                    "target_organization": self.target_organization,
                    "scan_time": current_time_str,
                    "asns": [
                        {
                            "number": asn.number,
                            "name": asn.name or "Unknown", 
                            "description": asn.description,
                            "country": asn.country,
                            "data_source": asn.data_source
                        } for asn in self.asns
                    ],
                    "ip_ranges": [
                        {
                            "cidr": ipr.cidr,
                            "version": ipr.version,
                            "asn_number": ipr.asn.number if ipr.asn else None,
                            "country": ipr.country,
                            "data_source": ipr.data_source
                        } for ipr in self.ip_ranges
                    ],
                    "domains": [
                        {
                            "name": dom.name,
                            "registrar": dom.registrar,
                            "creation_date": dom.creation_date.strftime(DATE_FORMAT) if dom.creation_date else None,
                            "data_source": dom.data_source,
                            "subdomains": [
                                {
                                    "fqdn": sub.fqdn,
                                    "status": sub.status,
                                    "resolved_ips": sorted(list(sub.resolved_ips)) if sub.resolved_ips else [],
                                    "data_source": sub.data_source,
                                    "last_checked": sub.last_checked.strftime(DATE_FORMAT) if sub.last_checked else None
                                } for sub in dom.subdomains
                            ]
                        } for dom in self.domains
                    ],
                    "cloud_services": [
                        {
                            "provider": svc.provider,
                            "identifier": svc.identifier,
                            "resource_type": svc.resource_type,
                            "region": svc.region,
                            "status": svc.status,
                            "data_source": svc.data_source
                        } for svc in self.cloud_services
                    ],
                    "warnings": list(self.warnings)
                }
                return json.dumps(data, indent=2, default=str)
            except Exception as e:
                logger.error(f"Error serializing result to JSON: {e}")
                return json.dumps({"error": "Failed to serialize result"})
                
        setattr(ReconnaissanceResult, 'to_json', to_json)
    else:
         logger.debug("ReconnaissanceResult already has to_json method.")

# --- Enhanced Data Preparation Functions ---
@st.cache_data(ttl=3600, max_entries=10)
def get_asn_df(asns: Set[ASN]) -> pd.DataFrame:
    """Convert ASNs to DataFrame with intelligent caching."""
    if not asns:
        return pd.DataFrame()
    
    asn_list = sorted(list(asns), key=lambda x: x.number)
    
    data = []
    for asn in asn_list:
        data.append({
            'ASN': f"AS{asn.number}",
            'Number': asn.number,
            'Name': asn.name or asn.description or "N/A",
            'Description': asn.description or "N/A", 
            'Country': asn.country or "Unknown",
            'Data Source': asn.data_source
        })
    
    return pd.DataFrame(data)

@st.cache_data(ttl=3600, max_entries=10)
def get_ip_range_df(ip_ranges: Set[IPRange]) -> pd.DataFrame:
    """Convert IP ranges to DataFrame with performance optimizations."""
    if not ip_ranges:
        return pd.DataFrame()
    
    def sort_key(ipr):
        try:
            network = ipaddress.ip_network(ipr.cidr, strict=False)
            return (network.version, network.network_address, network.prefixlen)
        except:
            return (0, 0, 0)
    
    sorted_ranges = sorted(list(ip_ranges), key=sort_key)
    
    data = []
    for ipr in sorted_ranges:
        size_str = _format_ip_range_size(ipr.cidr)
        
        data.append({
            'CIDR': ipr.cidr,
            'Version': f"IPv{ipr.version}",
            'Size': size_str,
            'ASN': f"AS{ipr.asn.number}" if ipr.asn else "Unknown",
            'Country': ipr.country or "Unknown",
            'Data Source': ipr.data_source
        })
    
    return pd.DataFrame(data)

def _format_ip_range_size(cidr: str) -> str:
    """Format IP range size with caching for performance."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        num_addresses = network.num_addresses
        
        if num_addresses >= 1_000_000:
            return f"{num_addresses:,} ({num_addresses/1_000_000:.1f}M)"
        elif num_addresses >= 1_000:
            return f"{num_addresses:,} ({num_addresses/1_000:.1f}K)"
        else:
            return f"{num_addresses:,}"
    except:
        return "Invalid"

@st.cache_data(ttl=3600, max_entries=10)
def get_domain_df(domains: Set[Domain]) -> pd.DataFrame:
    """Convert domains to DataFrame with optimized subdomain counting."""
    if not domains:
        return pd.DataFrame()
    
    sorted_domains = sorted(list(domains), key=lambda d: d.name)
    
    data = []
    for domain in sorted_domains:
        total_subdomains = len(domain.subdomains)
        active_subdomains = sum(1 for sub in domain.subdomains if sub.status == "Active")
        
        data.append({
            'Domain': domain.name,
            'Registrar': domain.registrar or "Unknown",
            'Creation Date': domain.creation_date.strftime('%Y-%m-%d') if domain.creation_date else "Unknown",
            'Subdomains': f"{total_subdomains} ({active_subdomains} active)",
            'Data Source': domain.data_source
        })
    
    return pd.DataFrame(data)

@st.cache_data(ttl=3600, max_entries=20)
def get_subdomain_df(domains: Set[Domain]) -> pd.DataFrame:
    """Convert subdomains to DataFrame with enhanced status formatting."""
    if not domains:
        return pd.DataFrame()
    
    data = []
    for domain in domains:
        sorted_subdomains = sorted(list(domain.subdomains), key=lambda s: s.fqdn)
        for subdomain in sorted_subdomains:
            data.append({
                'FQDN': subdomain.fqdn,
                'Status': _format_status(subdomain.status),
                'Resolved IPs': _format_ip_list(subdomain.resolved_ips),
                'Parent Domain': domain.name,
                'Data Source': subdomain.data_source,
                'Last Checked': subdomain.last_checked.strftime('%Y-%m-%d %H:%M') if subdomain.last_checked else "Never"
            })
    
    return pd.DataFrame(data)

def _format_status(status: str) -> str:
    """Format status with colored indicators."""
    status_map = {
        "Active": "🟢 Active",
        "Inactive": "🔴 Inactive", 
        "Unknown": "⚪ Unknown",
        "Pending": "🟡 Pending"
    }
    return status_map.get(status, f"⚪ {status}")

def _format_ip_list(ips: Optional[List[str]]) -> str:
    """Format IP list for display."""
    if not ips:
        return "None"
    elif len(ips) <= 3:
        return ", ".join(ips)
    else:
        return f"{', '.join(ips[:3])}, +{len(ips)-3} more"

@st.cache_data(ttl=600)
def get_cloud_service_df(services: Set[CloudService]) -> pd.DataFrame:
    """Convert cloud services to DataFrame with provider icons."""
    if not services:
        return pd.DataFrame()
    
    def get_provider_icon(provider: str) -> str:
        """Get emoji icon for cloud provider."""
        icons = {
            'AWS': '🟠',
            'Azure': '🔵', 
            'GCP': '🟡',
            'Cloudflare': '🟠',
            'DigitalOcean': '🔵',
            'Linode': '🟢',
            'OVH': '🔵',
            'Vultr': '🔴'
        }
        return icons.get(provider, '☁️')
    
    sorted_services = sorted(list(services), key=lambda s: (s.provider, s.identifier))
    
    data = []
    for service in sorted_services:
        provider_display = f"{get_provider_icon(service.provider)} {service.provider}"
        
        data.append({
            'Provider': provider_display,
            'Identifier': service.identifier,
            'Type': service.resource_type or "Unknown",
            'Region': service.region or "Unknown", 
            'Status': _format_status(service.status),
            'Data Source': service.data_source
        })
    
    return pd.DataFrame(data)

def render_modern_card(title: str, content: Any = None, icon: str = "📊"):
    """Render a modern card component."""
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{icon}</div>
            <h3 class="card-title">{title}</h3>
        </div>
        {f'<div class="card-content">{content}</div>' if content else ''}
    </div>
    """, unsafe_allow_html=True)

def display_enhanced_dataframe(df: pd.DataFrame, title: str, icon: str = "📊", page_size: int = DEFAULT_PAGINATION_SIZE):
    """Display DataFrame with modern styling and pagination."""
    if df.empty:
        render_modern_card(title, f"<p style='color: {COLORS['text_muted']}; text-align: center; padding: 2rem;'>No data available</p>", icon)
        return
    
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{icon}</div>
            <h3 class="card-title">{title}</h3>
            <div style="margin-left: auto; background: {COLORS['surface_secondary']}; 
                        padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.875rem;">
                {len(df)} total records
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Add search functionality
    search_term = st.text_input(f"🔍 Search {title.lower()}", key=f"search_{title.lower().replace(' ', '_')}")
    
    # Filter dataframe based on search
    filtered_df = df
    if search_term:
        # Search across all string columns
        mask = df.astype(str).apply(lambda x: x.str.contains(search_term, case=False, na=False)).any(axis=1)
        filtered_df = df[mask]
        
        if len(filtered_df) < len(df):
            st.caption(f"Showing {len(filtered_df)} of {len(df)} records matching '{search_term}'")
    
    # Pagination
    total_rows = len(filtered_df)
    if total_rows > page_size:
        total_pages = (total_rows - 1) // page_size + 1
        page = st.selectbox(f"Page", range(1, total_pages + 1), key=f"page_{title.lower().replace(' ', '_')}")
        
        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_rows)
        displayed_df = filtered_df.iloc[start_idx:end_idx]
        
        st.caption(f"Showing rows {start_idx + 1}-{end_idx} of {total_rows}")
    else:
        displayed_df = filtered_df
    
    # Display the dataframe
    st.dataframe(displayed_df, use_container_width=True, hide_index=True)
    
    # Download button
    csv = displayed_df.to_csv(index=False)
    st.download_button(
        label=f"📥 Download {title} CSV",
        data=csv,
        file_name=f"{title.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        key=f"download_{title.lower().replace(' ', '_')}"
    )

def display_empty_state(message: str, icon: str = "🔍"):
    """Display modern empty state."""
    st.markdown(f"""
    <div class="modern-card fade-in-up" style="text-align: center; padding: 3rem;">
        <div style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;">{icon}</div>
        <h3 style="color: {COLORS['text_muted']}; margin-bottom: 0.5rem;">No Data Available</h3>
        <p style="color: {COLORS['text_light']};">{message}</p>
    </div>
    """, unsafe_allow_html=True)

def display_asn_details(asns: Set[ASN]):
    """Display ASN details with enhanced modern styling."""
    if not asns:
        display_empty_state("No autonomous systems found", ICONS["asn"])
        return
    
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['asn']}</div>
            <h3 class="card-title">Autonomous Systems (ASNs)</h3>
            <div style="margin-left: auto;">
                <span class="status-indicator status-success">{len(asns)} discovered</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick stats
    countries = {asn.country for asn in asns if asn.country}
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total ASNs", len(asns))
    with col2:
        st.metric("Countries", len(countries))
    with col3:
        largest_asn = max(asns, key=lambda x: x.number)
        st.metric("Largest ASN", f"AS{largest_asn.number}")
    
    # Display data
    df = get_asn_df(asns)
    display_enhanced_dataframe(df, "ASN Details", ICONS["asn"])

def display_ip_range_details(ip_ranges: Set[IPRange]):
    """Display IP range details with enhanced visualization."""
    if not ip_ranges:
        display_empty_state("No IP ranges found", ICONS["ip"])
        return
    
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['ip']}</div>
            <h3 class="card-title">IP Address Ranges</h3>
            <div style="margin-left: auto;">
                <span class="status-indicator status-success">{len(ip_ranges)} ranges</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Calculate statistics
    ipv4_ranges = [r for r in ip_ranges if r.version == 4]
    ipv6_ranges = [r for r in ip_ranges if r.version == 6]
    
    total_addresses = 0
    for r in ip_ranges:
        try:
            network = ipaddress.ip_network(r.cidr, strict=False)
            total_addresses += network.num_addresses
        except:
            continue
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Ranges", len(ip_ranges))
    with col2:
        st.metric("IPv4 Ranges", len(ipv4_ranges))
    with col3:
        st.metric("IPv6 Ranges", len(ipv6_ranges))
    with col4:
        if total_addresses >= 1_000_000:
            st.metric("Total IPs", f"{total_addresses/1_000_000:.1f}M")
        elif total_addresses >= 1_000:
            st.metric("Total IPs", f"{total_addresses/1_000:.1f}K")
        else:
            st.metric("Total IPs", f"{total_addresses:,}")
    
    # Display data
    df = get_ip_range_df(ip_ranges)
    display_enhanced_dataframe(df, "IP Range Details", ICONS["ip"])

def display_domain_details(domains: Set[Domain]):
    """Display domain details with enhanced subdomain analysis."""
    if not domains:
        display_empty_state("No domains found", ICONS["domain"])
        return
    
    total_subdomains = sum(len(d.subdomains) for d in domains)
    active_subdomains = sum(len([s for s in d.subdomains if s.status == "Active"]) for d in domains)
    
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['domain']}</div>
            <h3 class="card-title">Domain Analysis</h3>
            <div style="margin-left: auto;">
                <span class="status-indicator status-success">{len(domains)} domains</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Domain statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Root Domains", len(domains))
    with col2:
        st.metric("Total Subdomains", total_subdomains)
    with col3:
        st.metric("Active Subdomains", active_subdomains)
    with col4:
        avg_subdomains = total_subdomains / len(domains) if domains else 0
        st.metric("Avg per Domain", f"{avg_subdomains:.1f}")
    
    # Tabs for different views
    tab1, tab2 = st.tabs([f"{ICONS['domain']} Root Domains", f"{ICONS['subdomain']} All Subdomains"])
    
    with tab1:
        df = get_domain_df(domains)
        display_enhanced_dataframe(df, "Root Domain Details", ICONS["domain"])
    
    with tab2:
        if total_subdomains > 0:
            df = get_subdomain_df(domains)
            display_enhanced_dataframe(df, "Subdomain Details", ICONS["subdomain"])
        else:
            display_empty_state("No subdomains discovered", ICONS["subdomain"])

def display_cloud_services(services: Set[CloudService]):
    """Display cloud services with provider breakdown."""
    if not services:
        display_empty_state("No cloud services detected", ICONS["cloud"])
        return
    
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['cloud']}</div>
            <h3 class="card-title">Cloud Infrastructure</h3>
            <div style="margin-left: auto;">
                <span class="status-indicator status-success">{len(services)} services</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Provider breakdown
    provider_counts = {}
    for service in services:
        provider_counts[service.provider] = provider_counts.get(service.provider, 0) + 1
    
    st.markdown("### 📊 Provider Distribution")
    
    cols = st.columns(min(len(provider_counts), 4))
    for i, (provider, count) in enumerate(provider_counts.items()):
        with cols[i % 4]:
            st.metric(provider, count)
    
    # Display data
    df = get_cloud_service_df(services)
    display_enhanced_dataframe(df, "Cloud Service Details", ICONS["cloud"])

# --- Enhanced Pagination Helper ---
def display_paginated_dataframe(df: pd.DataFrame, page_size=DEFAULT_PAGINATION_SIZE, key_prefix="page"):
    """
    Displays a large DataFrame with virtual pagination and intelligent caching for better performance.
    
    Args:
        df: DataFrame to display
        page_size: Number of rows per page
        key_prefix: Unique prefix for Streamlit widget keys
    """
    if df.empty:
        st.info("No data to display")
        return
    
    total_rows = len(df)
    total_pages = (total_rows + page_size - 1) // page_size
    
    # Initialize session state for this dataframe if not exists
    pagination_key = f"{key_prefix}_current_page"
    if pagination_key not in st.session_state:
        st.session_state[pagination_key] = 1
    
    # Performance optimization: Show quick stats first
    col_stats, col_pagination = st.columns([2, 1])
    
    with col_stats:
        st.markdown(f"""
        <div style="padding: 10px; background-color: #f8f9fa; border-radius: 5px; margin-bottom: 10px;">
            <strong>📊 Dataset Overview:</strong> {total_rows:,} total records | {total_pages:,} pages | {page_size} per page
        </div>
        """, unsafe_allow_html=True)
    
    with col_pagination:
        # Quick navigation buttons
        col_nav1, col_nav2, col_nav3 = st.columns(3)
        with col_nav1:
            if st.button("⏪ First", key=f"{key_prefix}_first", disabled=(st.session_state[pagination_key] == 1)):
                st.session_state[pagination_key] = 1
                st.rerun()
        with col_nav2:
            if st.button("⏩ Last", key=f"{key_prefix}_last", disabled=(st.session_state[pagination_key] == total_pages)):
                st.session_state[pagination_key] = total_pages
                st.rerun()
        with col_nav3:
            # Jump to page input
            target_page = st.number_input(
                "Page", 
                min_value=1, 
                max_value=total_pages, 
                value=st.session_state[pagination_key],
                key=f"{key_prefix}_jump"
            )
            if target_page != st.session_state[pagination_key]:
                st.session_state[pagination_key] = target_page
                st.rerun()
    
    # Search and filter functionality
    search_container = st.container()
    with search_container:
        col_search, col_filter = st.columns([3, 1])
        
        with col_search:
            search_term = st.text_input(
                "🔍 Search in data",
                placeholder="Search across all columns...",
                key=f"{key_prefix}_search"
            )
        
        with col_filter:
            # Quick filter for numeric columns
            numeric_columns = df.select_dtypes(include=['number']).columns.tolist()
            if numeric_columns:
                sort_column = st.selectbox(
                    "Sort by",
                    options=["Default"] + numeric_columns,
                    key=f"{key_prefix}_sort"
                )
            else:
                sort_column = "Default"
    
    # Apply search filter if provided
    filtered_df = df.copy()
    if search_term:
        # Create a boolean mask for searching across all string columns
        search_mask = pd.Series([False] * len(df))
        for column in df.columns:
            if df[column].dtype == 'object':  # String columns
                search_mask |= df[column].astype(str).str.contains(search_term, case=False, na=False)
        filtered_df = df[search_mask]
        
        # Update pagination for filtered results
        filtered_total = len(filtered_df)
        if filtered_total != total_rows:
            st.info(f"🔍 Found {filtered_total:,} records matching '{search_term}'")
            total_pages = (filtered_total + page_size - 1) // page_size
            if st.session_state[pagination_key] > total_pages:
                st.session_state[pagination_key] = 1
    
    # Apply sorting if selected
    if sort_column != "Default" and sort_column in filtered_df.columns:
        filtered_df = filtered_df.sort_values(by=sort_column, ascending=False)
    
    # Calculate current page bounds
    current_page = st.session_state[pagination_key]
    start_idx = (current_page - 1) * page_size
    end_idx = min(start_idx + page_size, len(filtered_df))
    
    # Virtual pagination: only slice the data we need
    page_data = filtered_df.iloc[start_idx:end_idx].copy()
    
    # Display the current page data with better styling
    st.markdown(f"""
    <div style="margin: 10px 0; padding: 8px; background-color: #e3f2fd; border-radius: 4px; border-left: 4px solid #2196f3;">
        <strong>📄 Page {current_page} of {total_pages}</strong> | 
        Showing rows {start_idx + 1:,} - {end_idx:,} of {len(filtered_df):,}
    </div>
    """, unsafe_allow_html=True)
    
    # Display the data table with enhanced formatting
    try:
        # Use Streamlit's native dataframe with better configuration
        st.dataframe(
            page_data,
            use_container_width=True,
            hide_index=True,
            height=min(400, len(page_data) * 35 + 50)  # Dynamic height based on content
        )
    except Exception as e:
        st.error(f"Error displaying data: {e}")
        st.write(page_data)  # Fallback to simple display
    
    # Enhanced pagination controls at bottom
    if total_pages > 1:
        st.markdown("### Navigation")
        
        # Create pagination button layout
        pagination_cols = st.columns([1, 1, 2, 1, 1])
        
        with pagination_cols[0]:
            if st.button("◀ Previous", key=f"{key_prefix}_prev", disabled=(current_page == 1)):
                st.session_state[pagination_key] = max(1, current_page - 1)
                st.rerun()
        
        with pagination_cols[1]:
            if st.button("Next ▶", key=f"{key_prefix}_next", disabled=(current_page == total_pages)):
                st.session_state[pagination_key] = min(total_pages, current_page + 1)
                st.rerun()
        
        with pagination_cols[2]:
            # Page size selector
            new_page_size = st.selectbox(
                "Items per page",
                options=[25, 50, 100, 200, 500],
                index=[25, 50, 100, 200, 500].index(page_size) if page_size in [25, 50, 100, 200, 500] else 1,
                key=f"{key_prefix}_page_size"
            )
            if new_page_size != page_size:
                # Recalculate page position based on current start index
                new_current_page = (start_idx // new_page_size) + 1
                st.session_state[pagination_key] = new_current_page
                # Note: We can't change page_size here as it's a parameter, 
                # but we can store it in session state for next render
                st.session_state[f"{key_prefix}_preferred_page_size"] = new_page_size
                st.rerun()
        
        with pagination_cols[3]:
            # Show page info
            st.markdown(f"<div style='text-align: center; padding: 8px;'><small>Page {current_page}/{total_pages}</small></div>", unsafe_allow_html=True)
        
        with pagination_cols[4]:
            # Export current page option
            if st.button("📥 Export Page", key=f"{key_prefix}_export"):
                csv_data = page_data.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"page_{current_page}_data.csv",
                    mime="text/csv",
                    key=f"{key_prefix}_download"
                )

def display_summary(result: ReconnaissanceResult):
    """Display an enhanced executive summary with modern styling."""
    if not result:
        display_empty_state("No reconnaissance data available", ICONS["summary"])
        return
    
    # Calculate comprehensive metrics
    total_asns = len(result.asns)
    total_ip_ranges = len(result.ip_ranges)
    total_domains = len(result.domains)
    total_subdomains = sum(len(d.subdomains) for d in result.domains)
    total_cloud_services = len(result.cloud_services)
    active_subdomains = sum(len([s for s in d.subdomains if s.status == "Active"]) for d in result.domains)
    
    # Header card
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['summary']}</div>
            <h3 class="card-title">Executive Summary - {result.target_organization}</h3>
        </div>
        <div style="padding: 1rem 0;">
            <p style="color: {COLORS['text_muted']}; font-size: 1.1rem;">
                Comprehensive digital asset discovery and analysis results
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced metrics dashboard
    render_metrics_dashboard(result)
    
    # Key findings cards
    st.markdown("### 🔍 Key Findings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Security insights
        st.markdown(f"""
        <div class="modern-card">
            <div class="card-header">
                <div class="card-icon">{ICONS['security']}</div>
                <h4 class="card-title">Security Insights</h4>
            </div>
            <div style="padding: 1rem 0;">
        """, unsafe_allow_html=True)
        
        # Attack surface analysis
        if total_subdomains > 100:
            st.markdown(f"""
            <div class="status-indicator status-warning">
                ⚠️ Large attack surface: {total_subdomains} subdomains
            </div>
            """, unsafe_allow_html=True)
        elif total_subdomains > 50:
            st.markdown(f"""
            <div class="status-indicator status-info">
                ℹ️ Moderate attack surface: {total_subdomains} subdomains
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="status-indicator status-success">
                ✅ Controlled attack surface: {total_subdomains} subdomains
            </div>
            """, unsafe_allow_html=True)
        
        # Cloud exposure analysis
        if total_cloud_services > 10:
            st.markdown(f"""
            <div class="status-indicator status-info">
                ☁️ Significant cloud presence: {total_cloud_services} services
            </div>
            """, unsafe_allow_html=True)
        elif total_cloud_services > 0:
            st.markdown(f"""
            <div class="status-indicator status-success">
                ☁️ Limited cloud exposure: {total_cloud_services} services
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("</div></div>", unsafe_allow_html=True)
    
    with col2:
        # Infrastructure overview
        st.markdown(f"""
        <div class="modern-card">
            <div class="card-header">
                <div class="card-icon">{ICONS['analytics']}</div>
                <h4 class="card-title">Infrastructure Overview</h4>
            </div>
            <div style="padding: 1rem 0;">
        """, unsafe_allow_html=True)
        
        # Network diversity
        countries = {asn.country for asn in result.asns if asn.country}
        if len(countries) > 5:
            st.markdown(f"""
            <div class="status-indicator status-info">
                🌍 Global presence: {len(countries)} countries
            </div>
            """, unsafe_allow_html=True)
        elif len(countries) > 1:
            st.markdown(f"""
            <div class="status-indicator status-success">
                🌍 Multi-region: {len(countries)} countries
            </div>
            """, unsafe_allow_html=True)
        
        # ASN diversity
        if total_asns > 20:
            st.markdown(f"""
            <div class="status-indicator status-warning">
                🌐 Highly distributed: {total_asns} ASNs
            </div>
            """, unsafe_allow_html=True)
        elif total_asns > 5:
            st.markdown(f"""
            <div class="status-indicator status-info">
                🌐 Well distributed: {total_asns} ASNs
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("</div></div>", unsafe_allow_html=True)
    
    # Recommendations section
    if result.warnings:
        st.markdown("### ⚠️ Attention Required")
        
        st.markdown(f"""
        <div class="modern-card">
            <div class="card-header">
                <div class="card-icon">⚠️</div>
                <h4 class="card-title">Scan Warnings</h4>
                <div style="margin-left: auto;">
                    <span class="status-indicator status-warning">{len(result.warnings)} warnings</span>
                </div>
            </div>
            <div style="padding: 1rem 0;">
        """, unsafe_allow_html=True)
        
        for i, warning in enumerate(result.warnings[:5]):
            st.markdown(f"""
            <div style="padding: 0.5rem; margin: 0.5rem 0; border-left: 3px solid {COLORS['warning']}; 
                        background: rgba(217, 119, 6, 0.1); border-radius: 4px;">
                <small>{warning}</small>
            </div>
            """, unsafe_allow_html=True)
        
        if len(result.warnings) > 5:
            st.markdown(f"<p><em>... and {len(result.warnings) - 5} more warnings</em></p>", unsafe_allow_html=True)
        
        st.markdown("</div></div>", unsafe_allow_html=True)

def display_process_logs(log_stream: io.StringIO):
    """Display process logs with modern styling and enhanced filtering."""
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['logs']}</div>
            <h3 class="card-title">Process Logs & Analysis</h3>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    log_content = log_stream.getvalue()
    
    if not log_content.strip():
        display_empty_state("No logs available yet", "📝")
        return
    
    # Enhanced filter options
    col1, col2 = st.columns(2)
    
    with col1:
        filter_options = ["All Logs", "Info Only", "Warnings & Errors Only", "Debug Only"]
        selected_filter = st.selectbox("Filter Level:", filter_options)
    
    with col2:
        search_term = st.text_input("🔍 Search logs", placeholder="Enter search term...")
    
    # Process logs based on filters
    filtered_logs = []
    for line in log_content.split('\n'):
        if search_term and search_term.lower() not in line.lower():
            continue
            
        if selected_filter == "All Logs":
            filtered_logs.append(line)
        elif selected_filter == "Info Only" and "INFO" in line:
            filtered_logs.append(line)
        elif selected_filter == "Warnings & Errors Only" and ("WARNING" in line or "ERROR" in line):
            filtered_logs.append(line)
        elif selected_filter == "Debug Only" and "DEBUG" in line:
            filtered_logs.append(line)
    
    filtered_content = '\n'.join(filtered_logs)
    
    col_logs, col_stats = st.columns([3, 1])
    
    with col_logs:
        st.text_area(
            "Log Output", 
            value=filtered_content,
            height=500, 
            key="log_area",
            help="Process logs with ANSI codes stripped for display"
        )
    
    with col_stats:
        # Download button
        st.download_button(
            "📥 Download Logs",
            data=log_content, 
            file_name=f"recon_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            key="download_logs",
            use_container_width=True
        )
        
        st.markdown("---")
        
        # Enhanced log statistics
        st.markdown("**Log Statistics:**")
        log_stats = {
            "Total Lines": log_content.count('\n') + (1 if log_content else 0),
            "INFO": sum(1 for line in log_content.split('\n') if " INFO " in line),
            "WARNING": sum(1 for line in log_content.split('\n') if " WARNING " in line),
            "ERROR": sum(1 for line in log_content.split('\n') if " ERROR " in line),
            "DEBUG": sum(1 for line in log_content.split('\n') if " DEBUG " in line)
        }
        
        for level, count in log_stats.items():
            if level in ["WARNING", "ERROR"] and count > 0:
                color = COLORS['warning'] if level == "WARNING" else COLORS['error']
                st.markdown(f"""
                <div class="status-indicator status-{'warning' if level == 'WARNING' else 'error'}">
                    {level}: {count}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.metric(level, count)

def render_welcome_screen():
    """Render the modern welcome screen."""
    st.markdown(f"""
    <div class="modern-card fade-in-up" style="text-align: center; padding: 3rem;">
        <div style="font-size: 4rem; margin-bottom: 1.5rem;">{ICONS['forge']}</div>
        <h2 style="color: {COLORS['text']}; margin-bottom: 1rem;">Welcome to ReconForge</h2>
        <p style="font-size: 1.2rem; color: {COLORS['text_muted']}; max-width: 600px; margin: 0 auto 2rem auto;">
            Advanced Enterprise Asset Discovery & Intelligence Platform
        </p>
        <div style="background: {COLORS['surface_secondary']}; padding: 2rem; border-radius: 12px; margin: 2rem 0;">
            <h3 style="color: {COLORS['text']}; margin-bottom: 1rem;">🚀 Getting Started</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; text-align: left;">
                <div>
                    <strong>1. Target Setup</strong><br>
                    <small style="color: {COLORS['text_muted']};">Enter organization name and known domains</small>
                </div>
                <div>
                    <strong>2. Intelligence Gathering</strong><br>
                    <small style="color: {COLORS['text_muted']};">Automated discovery across multiple sources</small>
                </div>
                <div>
                    <strong>3. Analysis & Insights</strong><br>
                    <small style="color: {COLORS['text_muted']};">Comprehensive security assessment</small>
                </div>
                <div>
                    <strong>4. Reporting</strong><br>
                    <small style="color: {COLORS['text_muted']};">Export and share findings</small>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_mission_form():
    """Render the modern mission configuration form."""
    st.markdown(f"""
    <div class="modern-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['target']}</div>
            <h3 class="card-title">Mission Configuration</h3>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("mission_form", border=False):
        # Organization input
        target_org_input = st.text_input(
            "**Target Organization**", 
            value=st.session_state.target_org,
            placeholder="e.g., Acme Corporation",
            help="Enter the exact legal name for optimal results"
        )
        
        # Domains input
        base_domains_input = st.text_input(
            "**Known Domains (Optional)**", 
            value=", ".join(st.session_state.base_domains),
            placeholder="e.g., acme.com, acmecorp.net",
            help="Comma-separated list of verified domains"
        )
        
        # Advanced options
        with st.expander("⚙️ Advanced Mission Parameters"):
            col1, col2 = st.columns(2)
            
            with col1:
                workers = st.slider(
                    "Concurrent Threads", 
                    min_value=5, 
                    max_value=50,
                    value=st.session_state.max_workers,
                    help="Higher values improve speed but may trigger rate limits"
                )
            
            with col2:
                st.write("")  # Spacer
                include_subdomains = st.checkbox(
                    "Deep Subdomain Analysis", 
                    value=st.session_state.include_subdomains,
                    help="Comprehensive subdomain discovery and validation"
                )
        
        # Enhanced submit button
        submitted = st.form_submit_button(
            f'{ICONS["scan"]} Initialize Reconnaissance Mission', 
            type="primary", 
            use_container_width=True
        )
        
        return submitted, target_org_input, base_domains_input, workers, include_subdomains

# --- Main App ---
def main():
    # Initialize the database first
    db_manager.init_db()
    
    # Apply professional styling
    apply_professional_css()
    
    # Ensure the to_json method exists in ReconnaissanceResult
    ensure_to_json_method()
    
    # --- Session State Initialization ---
    if 'recon_result' not in st.session_state:
        st.session_state.recon_result = None
    if 'log_stream' not in st.session_state:
        st.session_state.log_stream = io.StringIO()
    if 'log_handler' not in st.session_state:
        st.session_state.log_handler = StringLogHandler(st.session_state.log_stream)
    if 'scan_running' not in st.session_state:
        st.session_state.scan_running = False
    if 'run_scan' not in st.session_state:
        st.session_state.run_scan = False
    if 'load_scan_id' not in st.session_state: 
        st.session_state.load_scan_id = None
    if 'target_org' not in st.session_state:
        st.session_state.target_org = ""
    if 'base_domains' not in st.session_state:
        st.session_state.base_domains = set()
    if 'max_workers' not in st.session_state:
        st.session_state.max_workers = DEFAULT_MAX_WORKERS
    if 'include_subdomains' not in st.session_state:
        st.session_state.include_subdomains = True
    if 'current_view' not in st.session_state:
        st.session_state.current_view = "home"
    if 'ask_load_or_scan' not in st.session_state:
        st.session_state.ask_load_or_scan = False
    if 'existing_scan_id' not in st.session_state:
        st.session_state.existing_scan_id = None
    if 'expand_history' not in st.session_state:
        st.session_state.expand_history = False

    # Render modern header
    render_modern_header()
    
    # Render modern sidebar
    render_modern_sidebar()

    # Navigation callbacks
    def go_home():
        st.session_state.current_view = "home"
        st.session_state.recon_result = None
        st.session_state.run_scan = False
        st.session_state.ask_load_or_scan = False
        st.session_state.expand_history = False
    
    def go_new_scan():
        st.session_state.current_view = "new_scan"
        st.session_state.recon_result = None
        st.session_state.run_scan = False
        st.session_state.ask_load_or_scan = False
        st.session_state.expand_history = False
        st.session_state.target_org = ""
        st.session_state.base_domains = set()
    
    def go_history():
        st.session_state.current_view = "history"
        st.session_state.expand_history = True

    # --- Main Content Based on Current View ---
    if st.session_state.current_view == "new_scan":
        # Mission configuration form
        submitted, target_org_input, base_domains_input, workers, include_subdomains = render_mission_form()
        
        if submitted:
            if not target_org_input:
                st.error("⛔ Target Organization is required for mission initialization.")
            else:
                # Update session state
                st.session_state.target_org = target_org_input
                base_domains_set = set()
                if base_domains_input:
                    base_domains_set = {d.strip().lower() for d in base_domains_input.split(',') if d.strip()}
                st.session_state.base_domains = base_domains_set
                st.session_state.max_workers = workers
                st.session_state.include_subdomains = include_subdomains
                
                # Check for existing recent scan
                logger.info(f"Checking for existing recent scans for: {target_org_input}")
                existing_id = db_manager.check_existing_scan(target_org_input)
                if existing_id:
                    st.session_state.ask_load_or_scan = True
                    st.session_state.existing_scan_id = existing_id
                    st.session_state.run_scan = False
                    st.session_state.load_scan_id = None
                else:
                    st.session_state.ask_load_or_scan = False
                    st.session_state.run_scan = True
                    st.session_state.load_scan_id = None
                st.rerun()
    
    elif st.session_state.current_view == "history":
        # Intel Archive view
        st.markdown(f"""
        <div class="modern-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['db']}</div>
                <h3 class="card-title">Intelligence Archive</h3>
            </div>
            <div style="padding: 1rem 0;">
                <p style="color: {COLORS['text_muted']};">
                    Access your historical reconnaissance data and compare findings over time.
                </p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.session_state.expand_history = True
    
    elif st.session_state.current_view == "analytics":
        # Analytics dashboard (placeholder for future implementation)
        st.markdown(f"""
        <div class="modern-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['analytics']}</div>
                <h3 class="card-title">Analytics Dashboard</h3>
            </div>
            <div style="padding: 3rem; text-align: center;">
                <div style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;">{ICONS['analytics']}</div>
                <h3 style="color: {COLORS['text_muted']};">Advanced Analytics</h3>
                <p style="color: {COLORS['text_light']};">
                    Comprehensive trend analysis and risk assessment coming soon.
                </p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    else:  # "home" - Command Center
        # Show welcome screen or mission form based on context
        if not st.session_state.recon_result and not st.session_state.scan_running:
            render_welcome_screen()
        
        # Mission configuration form (always available on home)
        submitted, target_org_input, base_domains_input, workers, include_subdomains = render_mission_form()
        
        if submitted:
            if not target_org_input:
                st.error("⛔ Target Organization is required for mission initialization.")
            else:
                # Update session state
                st.session_state.target_org = target_org_input
                base_domains_set = set()
                if base_domains_input:
                    base_domains_set = {d.strip().lower() for d in base_domains_input.split(',') if d.strip()}
                st.session_state.base_domains = base_domains_set
                st.session_state.max_workers = workers
                st.session_state.include_subdomains = include_subdomains
                
                # Check for existing recent scan
                logger.info(f"Checking for existing recent scans for: {target_org_input}")
                existing_id = db_manager.check_existing_scan(target_org_input)
                if existing_id:
                    st.session_state.ask_load_or_scan = True
                    st.session_state.existing_scan_id = existing_id
                    st.session_state.run_scan = False
                    st.session_state.load_scan_id = None
                else:
                    st.session_state.ask_load_or_scan = False
                    st.session_state.run_scan = True
                    st.session_state.load_scan_id = None
                st.rerun()

    # --- Load vs Scan Decision ---
    if st.session_state.get("ask_load_or_scan", False):
        st.markdown(f"""
        <div class="modern-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['db']}</div>
                <h3 class="card-title">Existing Intelligence Found</h3>
            </div>
            <div style="padding: 1rem 0;">
                <p style="color: {COLORS['text_muted']};">
                    Found recent reconnaissance data for "{st.session_state.target_org}". 
                    Choose to load previous results or conduct a new mission.
                </p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f'{ICONS["load"]} Load Previous Intelligence', type="primary", use_container_width=True):
                st.session_state.load_scan_id = st.session_state.existing_scan_id
                st.session_state.run_scan = False
                st.session_state.ask_load_or_scan = False
                st.session_state.recon_result = None
                st.rerun()
        with col2:
            if st.button(f'{ICONS["scan"]} Execute New Mission', use_container_width=True):
                st.session_state.load_scan_id = None
                st.session_state.run_scan = True
                st.session_state.ask_load_or_scan = False
                st.session_state.recon_result = None
                st.rerun()
        st.stop()
        
    # --- Load Scan Execution --- 
    if st.session_state.get("load_scan_id", None) is not None:
        scan_id_to_load = st.session_state.load_scan_id
        logger.info(f"Loading results for scan ID: {scan_id_to_load}")
        
        with st.spinner("Loading intelligence from archive..."):
            loaded_result = db_manager.get_result_by_scan_id(scan_id_to_load)
        
        if loaded_result:
            st.session_state.recon_result = loaded_result
            st.session_state.log_stream.seek(0)
            st.session_state.log_stream.truncate(0)
            st.session_state.log_stream.write(f"--- Loaded intelligence from archive for target: {loaded_result.target_organization} ---\n")
            if loaded_result.warnings:
                st.session_state.log_stream.write(f"\n--- Warnings from loaded scan ---\n")
                for w in loaded_result.warnings:
                    st.session_state.log_stream.write(f"- {w}\n")
            
            st.success(f"✅ Successfully loaded intelligence for '{loaded_result.target_organization}'.")
        else:
            st.error(f"❌ Failed to load intelligence for scan ID {scan_id_to_load}. Please try a new mission.")
        
        # Reset flags
        st.session_state.load_scan_id = None
        st.session_state.run_scan = False
        st.session_state.scan_running = False
        st.rerun()
        
    # --- New Scan Execution --- 
    if st.session_state.get("run_scan", False):
        target_org = st.session_state.target_org 
        base_domains_set = st.session_state.base_domains
        max_workers = st.session_state.max_workers
        include_subdomains = st.session_state.include_subdomains 

        st.session_state.scan_running = True
        
        # Initialize cancellation flag
        if 'cancel_scan' not in st.session_state:
            st.session_state.cancel_scan = False
        
        scan_start_time = time.time()
        
        # Modern mission header
        st.markdown(f"""
        <div class="modern-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['running']}</div>
                <h3 class="card-title">Active Reconnaissance Mission</h3>
                <div style="margin-left: auto;">
                    <span class="status-indicator status-info">🎯 In Progress</span>
                </div>
            </div>
            <div style="padding: 1rem 0;">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <div>
                        <strong>Target:</strong><br>
                        <span style="color: {COLORS['text_muted']};">{target_org}</span>
                    </div>
                    <div>
                        <strong>Domains:</strong><br>
                        <span style="color: {COLORS['text_muted']};">{', '.join(base_domains_set) if base_domains_set else 'Discovery mode'}</span>
                    </div>
                    <div>
                        <strong>Started:</strong><br>
                        <span style="color: {COLORS['text_muted']};">{datetime.now().strftime('%H:%M:%S')}</span>
                    </div>
                    <div>
                        <strong>Threads:</strong><br>
                        <span style="color: {COLORS['text_muted']};">{max_workers} concurrent</span>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Mission control
        col_cancel, col_spacer = st.columns([1, 4])
        with col_cancel:
            if st.button("🛑 Abort Mission", key="cancel_scan_btn", type="secondary"):
                st.session_state.cancel_scan = True
                st.session_state.scan_running = False
                st.session_state.run_scan = False
                st.warning("🛑 Mission aborted by operator")
                st.rerun()

        # Configure logging
        configure_logging(
            level=logging.INFO, 
            stream_handler=st.session_state.log_handler,
            use_enhanced_formatter=True,
            color_enabled=True
        ) 

        # Clear log buffer
        st.session_state.log_stream.seek(0)
        st.session_state.log_stream.truncate(0) 
        
        # Create containers for live updates
        status_container = st.empty()
        progress_container = st.empty()
        results_preview_container = st.empty()
        
        # Initialize progress tracking
        current_phase = {"name": "Initializing", "progress": 0.0}
        
        def update_progress(progress: float, message: str):
            current_phase["progress"] = progress
            current_phase["name"] = message
            
            with progress_container.container():
                st.progress(progress / 100.0, text=f"{message} ({progress:.1f}%)")
                
        def update_status(icon: str, message: str):
            with status_container.container():
                st.markdown(f"""
                <div class="status-indicator status-info">
                    {icon} {message}
                </div>
                """, unsafe_allow_html=True)
                
        def update_results_preview(result: ReconnaissanceResult):
            if not result:
                return
                
            with results_preview_container.container():
                st.markdown("### 📡 Live Intelligence Feed")
                render_metrics_dashboard(result)

        try:
            logger.info(f"Starting enhanced reconnaissance mission for target: {target_org}")
            if base_domains_set:
                logger.info(f"Known domains provided: {', '.join(base_domains_set)}")
            logger.info(f"Using {max_workers} concurrent workers")
            
            # Initialize Intelligent Discovery Orchestrator
            orchestrator = IntelligentDiscoveryOrchestrator()
            
            # Enhanced callbacks with cancellation checks
            def enhanced_progress_callback(progress: float, message: str):
                if st.session_state.get('cancel_scan', False):
                    raise InterruptedError("Mission cancelled by operator")
                update_progress(progress, message)
                
            def enhanced_status_callback(icon: str, message: str):
                if st.session_state.get('cancel_scan', False):
                    raise InterruptedError("Mission cancelled by operator")
                update_status(icon, message)
            
            def enhanced_phase_callback(phase, phase_result):
                if st.session_state.get('cancel_scan', False):
                    raise InterruptedError("Mission cancelled by operator")
                
                phase_name = phase.value.replace('_', ' ').title()
                if phase_result.success:
                    logger.info(f"✅ {phase_name} completed successfully in {phase_result.duration:.2f}s")
                    enhanced_status_callback("✅", f"{phase_name} completed: {phase_result.assets_found} assets found")
                else:
                    logger.warning(f"⚠️ {phase_name} had issues")
                    enhanced_status_callback("⚠️", f"{phase_name} completed with warnings")
            
            # Execute mission
            update_status("🚀", "Initializing reconnaissance systems...")
            
            try:
                final_result = orchestrator.run_intelligent_discovery(
                    target_organization=target_org,
                    base_domains=base_domains_set,
                    progress_callback=enhanced_progress_callback,
                    status_callback=enhanced_status_callback,
                    phase_callback=enhanced_phase_callback
                )
                
                st.session_state.recon_result = final_result
                
                # Calculate mission duration
                total_duration = time.time() - scan_start_time
                
                update_progress(100, f"Mission completed in {total_duration:.2f}s")
                
                # Get comprehensive statistics
                discovery_stats = orchestrator.get_discovery_statistics()
                
                # Log final statistics
                total_subdomains = sum(len(d.subdomains) for d in final_result.domains)
                logger.info(f"✨ Enhanced reconnaissance completed successfully in {total_duration:.2f} seconds")
                logger.info(f"📊 Final Results: {len(final_result.asns)} ASNs, {len(final_result.domains)} domains, {total_subdomains} subdomains, {len(final_result.ip_ranges)} IP ranges, {len(final_result.cloud_services)} cloud services")
                
                update_status("✅", f"Enhanced reconnaissance complete! Found {len(final_result.asns)} ASNs, {len(final_result.domains)} domains, {len(final_result.ip_ranges)} IP ranges, {len(final_result.cloud_services)} cloud services")
                
                # Display success message with enhanced statistics
                success_message = f"🎉 Enhanced reconnaissance completed successfully in {total_duration:.2f} seconds!"
                if discovery_stats.get('phase_results'):
                    successful_phases = sum(1 for phase_stats in discovery_stats['phase_results'].values() if phase_stats['success'])
                    total_phases = len(discovery_stats['phase_results'])
                    success_message += f" ({successful_phases}/{total_phases} phases successful)"
                
                st.success(success_message)
                
                # --- Save result to DB with progress --- 
                with st.spinner("💾 Saving enhanced reconnaissance results to database..."):
                    logger.info(f"Starting database save for target: '{final_result.target_organization}'")
                    save_successful = db_manager.save_scan_result(final_result)
                    
                    if save_successful:
                        logger.info("Enhanced reconnaissance results saved to database successfully.")
                        st.info("✅ Enhanced reconnaissance results saved to database.")
                    else:
                        logger.error("Database save failed. Check previous logs in db_manager for details.")
                        st.error("❌ Failed to save enhanced reconnaissance results to the database. Some data might be lost.")
                
            except InterruptedError:
                st.warning("🛑 Enhanced reconnaissance was cancelled by user")
                # Try to get partial results from orchestrator if available
                if hasattr(orchestrator, 'partial_result') and orchestrator.partial_result:
                    st.session_state.recon_result = orchestrator.partial_result
                    st.info("💾 Partial results have been preserved from enhanced discovery")
                else:
                    st.session_state.recon_result = None
                
        except Exception as e:
            logger.exception("An unhandled error occurred during the enhanced reconnaissance process")
            st.error(f"❌ An unhandled error occurred during enhanced reconnaissance: {e}")
            
            # The enhanced orchestrator should have handled most errors gracefully
            st.session_state.recon_result = None
            
        finally:
            st.session_state.scan_running = False
            st.session_state.run_scan = False
            st.session_state.cancel_scan = False
            
            # Clear streaming containers
            status_container.empty()
            progress_container.empty()
            results_preview_container.empty()
            
            # Show action buttons
            if st.session_state.recon_result:
                col1, col2 = st.columns([1, 1])
                with col1:
                    if st.button("📊 View Detailed Results", type="primary", use_container_width=True):
                        st.rerun()
                with col2:
                    if st.button("🔄 Start New Scan", use_container_width=True):
                        st.session_state.recon_result = None
                        st.rerun()
            else:
                if st.button("🔄 Try Again", use_container_width=True):
                    st.rerun()

    # --- Display Results (From session state, either newly scanned or loaded) --- 
    if st.session_state.recon_result and not st.session_state.scan_running:
        result_data = st.session_state.recon_result
        
        # Display the target header and scan time
        target_org = result_data.target_organization
        scan_time = datetime.now().strftime(DATE_FORMAT)
        
        st.markdown(f"""
        <div style="margin-bottom: 20px; padding: 20px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid var(--primary);">
            <h2 style="margin-top:0">{ICONS["app"]} Reconnaissance Results</h2>
            <p><strong>Target Organization:</strong> {target_org}</p>
            <p><strong>Scan Completed:</strong> {scan_time}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Create tabs with enhanced styling
        tab_icons = {
            "summary": f"{ICONS['summary']} Summary",
            "asns": f"{ICONS['asn']} ASNs",
            "ips": f"{ICONS['ip']} IP Ranges",
            "domains": f"{ICONS['domain']} Domains",
            "cloud": f"{ICONS['cloud']} Cloud",
            "graph": f"{ICONS['graph']} Network Graph",
            "logs": f"{ICONS['logs']} Process Logs"
        }
        
        tab_summary, tab_asns, tab_ips, tab_domains, tab_cloud, tab_graph, tab_logs = st.tabs([
            tab_icons["summary"], 
            tab_icons["asns"],
            tab_icons["ips"],
            tab_icons["domains"],
            tab_icons["cloud"],
            tab_icons["graph"],
            tab_icons["logs"]
        ])

        with tab_summary:
            display_summary(result_data)
            
        with tab_asns:
            display_asn_details(result_data.asns)
            
        with tab_ips:
            display_ip_range_details(result_data.ip_ranges)
            
        with tab_domains:
            display_domain_details(result_data.domains)
            
        with tab_cloud:
            display_cloud_services(result_data.cloud_services)
            
        with tab_graph:
            st.markdown(f"""<div class="results-header"><h3>{ICONS['graph']} Network Relationship Graph</h3></div>""", unsafe_allow_html=True)
            
            graph_html_path = generate_network_graph(result_data)
            if graph_html_path:
                try:
                    with open(graph_html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    st.components.v1.html(html_content, height=800, scrolling=True)
                    
                    # Add download button for the graph in a cleaner format
                    with open(graph_html_path, "rb") as fp:
                        st.download_button(
                            label="📥 Download Network Graph (HTML)",
                            data=fp,
                            file_name=f"network_graph_{target_org.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html",
                            key="download_graph"
                        )
                except FileNotFoundError:
                    st.error(f"Could not find generated graph file: {graph_html_path}")
                except Exception as e:
                    logger.error(f"Error displaying graph HTML: {e}")
                    st.error("Could not display the generated network graph.")
            else:
                display_empty_state("Network graph generation failed", ICONS["graph"])
                
        with tab_logs:
            display_process_logs(st.session_state.log_stream)

    # --- Display Recent Scans (from DB) or Welcome Message ---
    elif not st.session_state.scan_running and not st.session_state.recon_result:
        # Display Welcome Message
        st.markdown(f"""
        <div style="margin-bottom: 20px; padding: 30px; text-align: center; background-color: #f8f9fa; border-radius: 8px;">
            <h2 style="margin-top:0">{ICONS["app"]} Enterprise Asset Reconnaissance</h2>
            <p style="font-size: 1.1em; max-width: 800px; margin: 15px auto;">
                Discover and map digital assets belonging to your target organization.
                Configure your scan parameters in the form above and click "Start Reconnaissance".
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Add some tips/guidance for first-time users
        st.markdown("### 💡 Quick Start Tips")
        
        tips_col1, tips_col2 = st.columns(2)
        with tips_col1:
            st.markdown("""
            **Getting Started:**
            1. Enter your target organization name
            2. Optionally add known domains
            3. Click "Check Target / Start Scan"
            4. Review results in the tabbed interface
            """)
        with tips_col2:
            st.markdown("""
            **Best Practices:**
            - Use the exact legal name of the organization
            - Add known domains to improve discovery accuracy
            - Check the Process Logs tab for detailed information
            - Save important results for future reference
            """)

    # --- Previous Scans Section (moved to bottom) ---
    # Always show the previous scans section at the bottom if there's history
    if not st.session_state.scan_running:
        # Add a separator before the history section
        st.markdown("---")
        
        # Create an expandable section for previous scans
        # Use the expand_history flag to automatically expand this section when the user clicks "Past Scans"
        with st.expander(f"{ICONS['db']} View Previous Reconnaissance Results", expanded=st.session_state.get('expand_history', False)):
            # Reset the expand flag once expanded
            if st.session_state.get('expand_history', False):
                st.session_state.expand_history = False
            
            st.markdown(f"""
            <div style="margin-bottom: 15px;">
                <h3 style="margin:0;">{ICONS['load']} Load Previous Scans</h3>
                <p style="margin-top:5px; color: #666;">Access your historical reconnaissance data to review findings or compare changes over time.</p>
            </div>
            """, unsafe_allow_html=True)
            
            recent_scans = db_manager.get_scan_history()
            
            if recent_scans:
                # Add a search/filter input
                search_term = st.text_input(
                    "🔍 Filter by target organization",
                    placeholder="Enter organization name...",
                    key="scan_history_filter"
                )
                
                # Filter scans based on search term
                filtered_scans = recent_scans
                if search_term:
                    filtered_scans = [
                        scan for scan in recent_scans 
                        if search_term.lower() in scan['target_organization'].lower()
                    ]
                
                if filtered_scans:
                    # Show how many scans are displayed after filtering
                    st.caption(f"Showing {len(filtered_scans)} of {len(recent_scans)} available scans")
                    
                    # Create a grid layout for the scan cards
                    cols_per_row = 3  # Number of cards per row
                    scan_rows = [filtered_scans[i:i + cols_per_row] for i in range(0, len(filtered_scans), cols_per_row)]
                    
                    for row in scan_rows:
                        cols = st.columns(cols_per_row)
                        for idx, scan in enumerate(row):
                            with cols[idx]:
                                # Format dates
                                scan_date = scan['scan_timestamp'].strftime("%d %b %Y")
                                scan_time = scan['scan_timestamp'].strftime("%H:%M")
                                
                                # Calculate days ago
                                days_ago = (datetime.now() - scan['scan_timestamp']).days
                                time_ago = f"{days_ago} days ago" if days_ago > 0 else "Today"
                                
                                # Determine icon based on target (simple example)
                                target_name = scan['target_organization']
                                first_letter = target_name[0].lower() if target_name else 'a'
                                # Icon gradient based on first letter (just for visual variety)
                                hue = (ord(first_letter) - ord('a')) * 15 % 360 if first_letter.isalpha() else 200
                                
                                # Create a more visual card with CSS
                                st.markdown(f"""
                                <div style="padding: 15px; border-radius: 8px; border: 1px solid #ddd; margin-bottom: 15px; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                                    <div style="display: flex; align-items: center; margin-bottom: 10px;">
                                        <div style="width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, hsl({hue}, 70%, 60%), hsl({hue+40}, 70%, 50%)); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; margin-right: 10px;">
                                            {target_name[0].upper()}
                                        </div>
                                        <div>
                                            <div style="font-weight: bold; color: #333; font-size: 1.1em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 180px;">
                                                {target_name}
                                            </div>
                                            <div style="font-size: 0.85em; color: #666;">
                                                {scan_date}, {scan_time} <span style="opacity: 0.7;">({time_ago})</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)
                                
                                # Add the load button underneath the card
                                if st.button(f"{ICONS['load']} Load Results", key=f"load_{scan['scan_id']}", use_container_width=True):
                                    st.session_state.load_scan_id = scan['scan_id']
                                    st.session_state.run_scan = False
                                    st.session_state.ask_load_or_scan = False
                                    st.session_state.recon_result = None
                                    st.rerun()
                else:
                    st.info(f"No scans found matching '{search_term}'")
            else:
                display_empty_state("No previous scans found in the database.", ICONS["db"])
                st.markdown("""
                <div style="text-align: center; padding: 20px; color: #666;">
                    <p>Start a new scan to build your reconnaissance history!</p>
                </div>
                """, unsafe_allow_html=True)

    # Add a footer with author information
    st.markdown(f"""
    <div style="margin-top: 50px; padding: 10px; background-color: #f8f9fa; border-radius: 8px; text-align: center;">
        <p style="margin: 0; font-size: 0.9em; color: #666;">
            <span style="font-weight: bold;">Enterprise Asset Reconnaissance</span> by <a href="https://github.com/jnjambrino" target="_blank">jnjambrino</a>
        </p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main() 