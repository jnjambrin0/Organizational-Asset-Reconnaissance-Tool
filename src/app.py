import streamlit as st

# Set page config at the very beginning
st.set_page_config(
    layout="wide", 
    page_title="Enterprise Asset Reconnaissance", 
    page_icon="🔍",
    initial_sidebar_state="expanded"
)

import logging
import io
import os
import time
import json
from datetime import datetime
from typing import Set, List, Dict, Any, Optional, Tuple
import pandas as pd
import ipaddress

from src.utils.logging_config import StringLogHandler, setup_logging as configure_logging
from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, CloudService, Subdomain
from src.orchestration import discovery_orchestrator
from src.visualization.network_graph import generate_network_graph

# --- Logger ---
logger = logging.getLogger(__name__)

# --- Constants ---
DEFAULT_PAGINATION_SIZE = 50
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
ICONS = {
    "app": "🔍",
    "summary": "📊",
    "asn": "🌐",
    "ip": "💻",
    "domain": "🌍",
    "subdomain": "🔗",
    "cloud": "☁️",
    "graph": "🕸️",
    "logs": "⚙️",
    "success": "✅",
    "warning": "⚠️",
    "error": "❌",
    "info": "ℹ️",
    "pending": "⏳",
    "running": "⌛",
    "completed": "✓"
}

# --- Custom CSS and Page Configuration ---
def apply_custom_css():
    """Applies custom CSS for a professional UI look and feel"""
    st.markdown("""
    <style>
    /* Main theme colors */
    :root {
        --primary: #1E65F3;
        --primary-light: #4D84F5;
        --secondary: #152238;
        --accent: #3BACBF;
        --background: #F8F9FA;
        --card: #FFFFFF;
        --text: #152238;
        --text-light: #5A6B87;
        --success: #28A745;
        --warning: #FFC107;
        --danger: #DC3545;
        --info: #17A2B8;
        --sidebar-bg: #f1f3f8; /* Más claro que el anterior */
        --sidebar-text: #2c3e50;
    }
    
    /* Global styles */
    .main {
        background-color: var(--background);
        color: var(--text);
    }
    
    h1, h2, h3 {
        color: var(--secondary);
        font-weight: 600;
    }
    
    /* Card-like containers */
    .css-1r6slb0, .css-keje6w, div[data-testid="stExpander"] { 
        background-color: var(--card);
        border-radius: 8px;
        padding: 1.5rem;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        margin-bottom: 1rem;
    }

    /* Improved form container and slider description */
    .stForm > div {
        padding: 1.5rem;
    }
    
    /* Slider label improvement - Concurrent Workers */
    .stSlider label {
        font-weight: 500;
        color: var(--text);
    }
    
    .stSlider p {
        font-size: 0.9rem;
        color: var(--text-light);
        margin-top: 0.5rem;
    }
    
    /* Button styles - Improved start button */
    .stButton>button {
        background-color: var(--primary);
        color: white;
        border-radius: 6px;
        padding: 0.5rem 1rem;
        border: none;
        font-weight: 600;
        transition: all 0.3s;
    }
    
    /* Primary action button (Start Reconnaissance) */
    .stForm button[kind="primary"] {
        padding: 0.7rem 1.4rem;
        font-size: 1.1rem;
        width: 100%;
    }
    
    .stButton>button:hover {
        background-color: var(--primary-light);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    
    /* Status indicators */
    .status-card {
        padding: 1rem;
        border-radius: 6px;
        margin-bottom: 1rem;
    }
    
    .status-success {
        background-color: rgba(40, 167, 69, 0.1);
        border-left: 4px solid var(--success);
    }
    
    .status-warning {
        background-color: rgba(255, 193, 7, 0.1);
        border-left: 4px solid var(--warning);
    }
    
    .status-error {
        background-color: rgba(220, 53, 69, 0.1);
        border-left: 4px solid var(--danger);
    }
    
    .status-info {
        background-color: rgba(23, 162, 184, 0.1);
        border-left: 4px solid var(--info);
    }
    
    /* Dashboard metrics */
    .metric-card {
        background-color: var(--card);
        border-radius: 8px;
        padding: 1.2rem;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        text-align: center;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: var(--primary);
    }
    
    .metric-label {
        font-size: 0.85rem;
        color: var(--text-light);
        text-transform: uppercase;
        letter-spacing: 0.05rem;
    }
    
    /* Table styles */
    .dataframe {
        font-size: 0.9rem;
    }
    
    .dataframe th {
        background-color: var(--secondary);
        color: white;
        font-weight: 600;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border-radius: 4px 4px 0 0;
        padding: 10px 16px;
        color: var(--text-light);
    }
    
    .stTabs [aria-selected="true"] {
        background-color: var(--primary);
        color: white;
    }
    
    /* Custom header with logo-like appearance */
    .app-header {
        display: flex;
        align-items: center;
        padding: 1rem 0;
        border-bottom: 1px solid rgba(49, 51, 63, 0.1);
        margin-bottom: 2rem;
    }
    
    .app-logo {
        font-size: 1.8rem;
        font-weight: 800;
        color: var(--primary);
        margin-right: 10px;
    }
    
    .app-title {
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--secondary);
    }
    
    /* Progress bar animation */
    @keyframes pulse {
        0% { opacity: 0.6; }
        50% { opacity: 1; }
        100% { opacity: 0.6; }
    }
    
    .pulse-animation {
        animation: pulse 2s infinite ease-in-out;
    }
    
    /* Results section */
    .results-header {
        border-bottom: 2px solid var(--primary);
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
        color: var(--secondary);
    }
    
    /* Empty state styling */
    .empty-state {
        text-align: center;
        padding: 3rem;
        color: var(--text-light);
        border: 1px dashed rgba(0,0,0,0.1);
        border-radius: 8px;
    }
    
    .empty-state-icon {
        font-size: 3rem;
        margin-bottom: 1rem;
        color: var(--text-light);
    }

    /* Sidebar styling with lighter colors */
    [data-testid="stSidebar"] {
        background-color: var(--sidebar-bg);
        color: var(--sidebar-text);
    }

    [data-testid="stSidebar"] h2, 
    [data-testid="stSidebar"] h3 {
        color: var(--secondary);
        margin-bottom: 1rem;
    }

    /* Sidebar footer fix - making it stick to bottom */
    [data-testid="stSidebar"] .stMarkdown:has(> p:contains("Version")) {
        position: absolute;
        bottom: 20px;
        left: 0;
        width: 100%;
        padding: 0 1rem;
        font-size: 0.8rem;
    }

    /* Key Features improvement */
    .features-card {
        border: 1px solid rgba(0,0,0,0.1);
        border-radius: 8px;
        padding: 1.2rem;
        margin-bottom: 1rem;
        background-color: white;
        transition: all 0.3s;
    }
    
    .features-card:hover {
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        transform: translateY(-2px);
    }
    
    .features-card h4 {
        color: var(--primary);
        margin-bottom: 0.8rem;
        font-weight: 600;
    }
    
    .features-card ul {
        margin-bottom: 0;
        padding-left: 1.5rem;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Data Preparation (Cached Functions) ---
@st.cache_data(ttl=600) # Cache for 10 minutes
def get_asn_df(asns: Set[ASN]) -> pd.DataFrame:
    """Prepare ASN data for display with enhanced formatting."""
    logger.debug("Preparing ASN DataFrame...")
    asn_list = [{"ASN": f"AS{a.number}", 
                 "Name": a.name or "Unknown", 
                 "Description": a.description or "-", 
                 "Country": a.country or "-", 
                 "Source": a.data_source or "Unknown"} 
                for a in sorted(list(asns), key=lambda x: x.number)]
    return pd.DataFrame(asn_list)

@st.cache_data(ttl=600)
def get_ip_range_df(ip_ranges: Set[IPRange]) -> pd.DataFrame:
    """Prepare IP Range data for display with enhanced formatting."""
    logger.debug("Preparing IP Range DataFrame...")
    # Sort by version first, then by network address
    def sort_key(ipr):
        try:
            net = ipaddress.ip_network(ipr.cidr)
            return (net.version, net)
        except ValueError:
            return (0, ipr.cidr) # Sort invalid ones first
            
    ip_list = [{"CIDR": ipr.cidr, 
                "Version": f"IPv{ipr.version}" if ipr.version else "Unknown", 
                "Range Size": _format_ip_range_size(ipr.cidr),
                "Source": ipr.data_source or "Unknown"} 
               for ipr in sorted(list(ip_ranges), key=sort_key)]
    return pd.DataFrame(ip_list)

def _format_ip_range_size(cidr: str) -> str:
    """Format the IP range size in a human-readable format."""
    try:
        net = ipaddress.ip_network(cidr)
        size = net.num_addresses
        if size >= 1000000:
            return f"{size/1000000:.2f}M addresses"
        elif size >= 1000:
            return f"{size/1000:.2f}K addresses"
        else:
            return f"{size} addresses"
    except ValueError:
        return "Unknown"

@st.cache_data(ttl=600)
def get_domain_df(domains: Set[Domain]) -> pd.DataFrame:
    """Prepare Domain data for display with enhanced formatting."""
    logger.debug("Preparing Domain DataFrame...")
    domain_list = [{"Domain": d.name, 
                    "Registrar": d.registrar or "Unknown", 
                    "Creation Date": d.creation_date.strftime(DATE_FORMAT) if d.creation_date else "-",
                    "Subdomains": len(d.subdomains),
                    "Source": d.data_source or "Unknown"} 
                   for d in sorted(list(domains), key=lambda x: x.name)]
    return pd.DataFrame(domain_list)

@st.cache_data(ttl=600)
def get_subdomain_df(domains: Set[Domain]) -> pd.DataFrame:
    """Prepare Subdomain data for display with enhanced formatting."""
    logger.debug("Preparing Subdomain DataFrame...")
    all_subs = set()
    for domain in domains:
        all_subs.update(domain.subdomains)
        
    subdomain_list = [{"Subdomain": s.fqdn, 
                       "Status": _format_status(s.status), 
                       "IP Addresses": _format_ip_list(s.resolved_ips),
                       "Last Checked": s.last_checked.strftime(DATE_FORMAT) if s.last_checked else "-",
                       "Source": s.data_source or "Unknown"} 
                      for s in sorted(list(all_subs), key=lambda s: s.fqdn)]
    return pd.DataFrame(subdomain_list)

def _format_status(status: str) -> str:
    """Format the status with colored indicators."""
    if not status:
        return "Unknown"
    
    status = status.lower()
    if status == "active":
        return f"{ICONS['success']} Active"
    elif status == "inactive":
        return f"{ICONS['warning']} Inactive"
    else:
        return status.capitalize()

def _format_ip_list(ips: Optional[List[str]]) -> str:
    """Format a list of IPs with proper presentation."""
    if not ips:
        return "-"
    
    if len(ips) <= 3:
        return ", ".join(sorted(ips))
    else:
        return f"{', '.join(sorted(ips)[:3])} (+{len(ips)-3} more)"

@st.cache_data(ttl=600)
def get_cloud_service_df(services: Set[CloudService]) -> pd.DataFrame:
    """Prepare Cloud Service data for display with enhanced formatting."""
    logger.debug("Preparing Cloud Service DataFrame...")
    
    # Helper function to get provider icon
    def get_provider_icon(provider: str) -> str:
        provider = provider.lower() if provider else ""
        if "aws" in provider:
            return "🧡 AWS"
        elif "azure" in provider or "microsoft" in provider:
            return "💙 Azure"
        elif "google" in provider or "gcp" in provider:
            return "💚 GCP"
        elif "cloudflare" in provider:
            return "🧡 Cloudflare"
        elif "digital ocean" in provider:
            return "💙 Digital Ocean"
        elif "oracle" in provider:
            return "🔴 Oracle"
        else:
            return f"☁️ {provider.title() if provider else 'Unknown'}"
    
    cloud_list = [{"Provider": get_provider_icon(s.provider), 
                   "Service Name": s.identifier, 
                   "Type": s.resource_type or "Unknown",
                   "Region": s.region or "-",
                   "Status": _format_status(s.status),
                   "Source": s.data_source or "Unknown"} 
                  for s in sorted(list(services), key=lambda x: (x.provider, x.identifier))]
    return pd.DataFrame(cloud_list)

# --- Enhanced Pagination Helper ---
def display_paginated_dataframe(df: pd.DataFrame, page_size=DEFAULT_PAGINATION_SIZE, key_prefix="page"):
    """Enhanced pagination with better UI and controls."""
    total_rows = len(df)
    if total_rows == 0:
        display_empty_state(f"No data available")
        return
        
    total_pages = (total_rows // page_size) + (1 if total_rows % page_size > 0 else 0)
    session_key = f"{key_prefix}_current_page"
    search_key = f"{key_prefix}_search"

    # Initialize page number and search term in session state if needed
    if session_key not in st.session_state:
        st.session_state[session_key] = 1
    if search_key not in st.session_state:
        st.session_state[search_key] = ""
        
    current_page = st.session_state[session_key]
    
    # Ensure current page is within bounds
    current_page = max(1, min(current_page, total_pages))
    st.session_state[session_key] = current_page
    
    # Search and filter functionality
    col1, col2 = st.columns([2, 1])
    with col1:
        search_term = st.text_input(
            "🔍 Search", 
            value=st.session_state[search_key],
            key=f"{key_prefix}_search_input", 
            placeholder="Filter results..."
        )
        
        # Update search term in session state if changed
        if search_term != st.session_state[search_key]:
            st.session_state[search_key] = search_term
            st.session_state[session_key] = 1  # Reset to first page on new search
            current_page = 1
    
    # Filter dataframe if search term is provided
    filtered_df = df
    if search_term:
        mask = pd.Series(False, index=df.index)
        for col in df.columns:
            # Convert column to string and check for case-insensitive contains
            mask |= df[col].astype(str).str.contains(search_term, case=False, na=False)
        filtered_df = df[mask]
        
        # Recalculate total pages based on filtered data
        total_rows = len(filtered_df)
        total_pages = (total_rows // page_size) + (1 if total_rows % page_size > 0 else 0)
        
        # Ensure current page is still valid with new total
        current_page = max(1, min(current_page, total_pages))
        st.session_state[session_key] = current_page
    
    # Display information about filtered results
    with col2:
        if search_term:
            st.info(f"Found {total_rows} matching results")
    
    # Show no results message if filtered df is empty
    if total_rows == 0:
        display_empty_state(f"No results found for '{search_term}'")
        return
        
    # Display DataFrame slice
    start_idx = (current_page - 1) * page_size
    end_idx = start_idx + page_size
    
    # Add styling to the dataframe
    st.dataframe(
        filtered_df.iloc[start_idx:end_idx], 
        use_container_width=True,
        height=None if total_rows < 10 else 400
    )

    # Pagination controls in a nicer layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        prev_disabled = (current_page <= 1)
        if st.button("⬅️ Previous", key=f"{key_prefix}_prev", disabled=prev_disabled):
            st.session_state[session_key] -= 1
            st.rerun()
            
    with col2:
        pagination_text = f"Page {current_page} of {total_pages} | Showing {start_idx+1}-{min(end_idx, total_rows)} of {total_rows} records"
        
        # Create a centered, styled pagination indicator
        st.markdown(f"""
        <div style="text-align: center; padding: 8px; border-radius: 4px; background-color: #f0f2f6;">
            {pagination_text}
        </div>
        """, unsafe_allow_html=True)

    with col3:
        next_disabled = (current_page >= total_pages)
        if st.button("Next ➡️", key=f"{key_prefix}_next", disabled=next_disabled):
            st.session_state[session_key] += 1
            st.rerun()
            
    # Quick page jump for larger datasets
    if total_pages > 5:
        st.write("")
        jump_col1, jump_col2 = st.columns([3, 1])
        with jump_col1:
            jump_page = st.slider("Jump to page:", 1, total_pages, current_page, key=f"{key_prefix}_jump")
        with jump_col2:
            if st.button("Go", key=f"{key_prefix}_jump_btn"):
                st.session_state[session_key] = jump_page
                st.rerun()

def display_empty_state(message: str, icon: str = "🔍"):
    """Display a well-styled empty state message."""
    st.markdown(f"""
    <div class="empty-state">
        <div class="empty-state-icon">{icon}</div>
        <p>{message}</p>
    </div>
    """, unsafe_allow_html=True)

# --- Enhanced Display Functions ---
def display_asn_details(asns: Set[ASN]):
    st.markdown(f"""<div class="results-header"><h3>{ICONS['asn']} Autonomous System Numbers (ASNs)</h3></div>""", unsafe_allow_html=True)
    
    if asns:
        asn_df = get_asn_df(asns)
        # ASNs are typically few enough to show all at once
        st.dataframe(asn_df, use_container_width=True)
        
        # Add download button
        csv = asn_df.to_csv(index=False)
        st.download_button(
            "📥 Download ASN Data as CSV",
            data=csv,
            file_name=f"asn_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="download_asn"
        )
    else:
        display_empty_state("No ASNs found yet", ICONS["asn"])

def display_ip_range_details(ip_ranges: Set[IPRange]):
    st.markdown(f"""<div class="results-header"><h3>{ICONS['ip']} IP Ranges</h3></div>""", unsafe_allow_html=True)
    
    if ip_ranges:
        ip_df = get_ip_range_df(ip_ranges)
        
        # Add metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            ipv4_count = sum(1 for ip in ip_ranges if ip.version == 4)
            st.metric("IPv4 Ranges", ipv4_count)
        with col2:
            ipv6_count = sum(1 for ip in ip_ranges if ip.version == 6)
            st.metric("IPv6 Ranges", ipv6_count)
        with col3:
            try:
                total_addresses = sum(ipaddress.ip_network(ip.cidr).num_addresses for ip in ip_ranges 
                                    if ip.version == 4 and ipaddress.ip_network(ip.cidr).num_addresses < 2**32)
                formatted_total = f"{total_addresses:,}"
            except:
                formatted_total = "N/A"
            st.metric("Total IPv4 Addresses", formatted_total)
            
        display_paginated_dataframe(ip_df, page_size=50, key_prefix="ip_range")
        
        # Add download button
        csv = ip_df.to_csv(index=False)
        st.download_button(
            "📥 Download IP Range Data as CSV",
            data=csv,
            file_name=f"ip_ranges_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="download_ip"
        )
    else:
        display_empty_state("No IP Ranges found yet", ICONS["ip"])

def display_domain_details(domains: Set[Domain]):
    st.markdown(f"""<div class="results-header"><h3>{ICONS['domain']} Domains & Subdomains</h3></div>""", unsafe_allow_html=True)
    
    if domains:
        domain_df = get_domain_df(domains)
        
        # Add domain metrics
        total_domains = len(domains)
        all_subdomains = sum(len(d.subdomains) for d in domains)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Primary Domains", total_domains)
        with col2:
            st.metric("Subdomains", all_subdomains)
        with col3:
            avg_subdomains = all_subdomains / total_domains if total_domains > 0 else 0
            st.metric("Avg. Subdomains per Domain", f"{avg_subdomains:.1f}")
        
        # Display domains table
        st.subheader("Primary Domains")
        st.dataframe(domain_df, use_container_width=True)
        
        # Add download button for domains
        csv_domains = domain_df.to_csv(index=False)
        st.download_button(
            "📥 Download Domains Data as CSV",
            data=csv_domains,
            file_name=f"domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="download_domains"
        )
        
        # Display subdomains
        subdomain_df = get_subdomain_df(domains)
        if not subdomain_df.empty:
            st.subheader(f"Discovered Subdomains ({len(subdomain_df)} total)")
            display_paginated_dataframe(subdomain_df, page_size=50, key_prefix="subdomain")
            
            # Add download button for subdomains
            csv_subdomains = subdomain_df.to_csv(index=False)
            st.download_button(
                "📥 Download Subdomains Data as CSV",
                data=csv_subdomains,
                file_name=f"subdomains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key="download_subdomains"
            )
        else:
            st.info(f"{ICONS['info']} No subdomains have been discovered yet.")
    else:
        display_empty_state("No Domains or Subdomains found yet", ICONS["domain"])

def display_cloud_services(services: Set[CloudService]):
    st.markdown(f"""<div class="results-header"><h3>{ICONS['cloud']} Cloud Services</h3></div>""", unsafe_allow_html=True)
    
    if services:
        cloud_df = get_cloud_service_df(services)
        
        # Add cloud service metrics
        providers = {s.provider for s in services if s.provider}
        resource_types = {s.resource_type for s in services if s.resource_type}
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Cloud Services", len(services))
        with col2:
            st.metric("Cloud Providers", len(providers))
        with col3:
            st.metric("Service Types", len(resource_types))
            
        # Display provider breakdown if multiple providers
        if len(providers) > 1:
            st.subheader("Cloud Provider Distribution")
            provider_counts = {}
            for service in services:
                provider = service.provider or "Unknown"
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
                
            provider_df = pd.DataFrame({
                "Provider": list(provider_counts.keys()),
                "Services": list(provider_counts.values())
            })
            
            col1, col2 = st.columns([1, 1])
            with col1:
                st.dataframe(provider_df, use_container_width=True)
            with col2:
                if len(provider_counts) <= 10:  # Only show chart if not too many providers
                    st.bar_chart(provider_df.set_index("Provider"))
        
        st.subheader("All Cloud Services")
        display_paginated_dataframe(cloud_df, page_size=50, key_prefix="cloud")
        
        # Add download button
        csv = cloud_df.to_csv(index=False)
        st.download_button(
            "📥 Download Cloud Services Data as CSV",
            data=csv,
            file_name=f"cloud_services_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key="download_cloud"
        )
    else:
        display_empty_state("No Cloud Services found yet", ICONS["cloud"])

def display_summary(result: ReconnaissanceResult):
    st.markdown(f"""<div class="results-header"><h3>{ICONS['summary']} Reconnaissance Summary</h3></div>""", unsafe_allow_html=True)
    
    # Target organization info
    st.markdown(f"""
    <div style="margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; border-left: 4px solid var(--primary);">
        <strong>Target:</strong> {result.target_organization}
        <br>
        <strong>Scan Time:</strong> {datetime.now().strftime(DATE_FORMAT)}
    </div>
    """, unsafe_allow_html=True)
    
    # Use cached DFs for counts where appropriate
    subdomain_count = len(get_subdomain_df(result.domains)) if result.domains else 0
    
    # Create a more visually appealing metrics display
    st.markdown("""
    <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 20px;">
    """, unsafe_allow_html=True)
    
    metrics = [
        {"icon": ICONS["asn"], "label": "ASNs", "value": len(result.asns)},
        {"icon": ICONS["ip"], "label": "IP Ranges", "value": len(result.ip_ranges)},
        {"icon": ICONS["domain"], "label": "Domains", "value": len(result.domains)},
        {"icon": ICONS["subdomain"], "label": "Subdomains", "value": subdomain_count},
        {"icon": ICONS["cloud"], "label": "Cloud Services", "value": len(result.cloud_services)}
    ]
    
    for metric in metrics:
        st.markdown(f"""
        <div style="flex: 1; min-width: 150px; background-color: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); text-align: center;">
            <div style="font-size: 2rem; color: var(--primary); margin-bottom: 5px;">{metric["icon"]} {metric["value"]}</div>
            <div style="font-size: 0.9rem; color: var(--text-light); text-transform: uppercase; letter-spacing: 0.05rem;">{metric["label"]}</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Display Warnings
    if result.warnings:
        st.markdown(f"""
        <div class="status-card status-warning">
            <h4>{ICONS["warning"]} Scan completed with {len(result.warnings)} warnings</h4>
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander("View Warnings"):
            for warning in result.warnings:
                st.markdown(f"- {warning}")
    else:
        st.markdown(f"""
        <div class="status-card status-success">
            <h4>{ICONS["success"]} Scan completed successfully without warnings</h4>
        </div>
        """, unsafe_allow_html=True)
    
    # Add export options
    st.subheader("Export Results")
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON export is always available
        json_data = result.to_json()
        if json_data:
            st.download_button(
                "💾 Export Full Results as JSON",
                data=json_data,
                file_name=f"recon_{result.target_organization.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                key="download_json"
            )

def display_process_logs(log_stream: io.StringIO):
    st.markdown(f"""<div class="results-header"><h3>{ICONS['logs']} Process Logs</h3></div>""", unsafe_allow_html=True)
    
    log_content = log_stream.getvalue()
    
    if not log_content.strip():
        display_empty_state("No logs available yet", "📝")
        return
    
    # Filter options
    filter_options = ["All Logs", "Info Only", "Warnings & Errors Only", "Debug Only"]
    selected_filter = st.selectbox("Filter Logs:", filter_options)
    
    # Process logs based on filter
    filtered_logs = []
    for line in log_content.split('\n'):
        if selected_filter == "All Logs":
            filtered_logs.append(line)
        elif selected_filter == "Info Only" and "INFO" in line:
            filtered_logs.append(line)
        elif selected_filter == "Warnings & Errors Only" and ("WARNING" in line or "ERROR" in line):
            filtered_logs.append(line)
        elif selected_filter == "Debug Only" and "DEBUG" in line:
            filtered_logs.append(line)
    
    # Join filtered logs back together
    filtered_content = '\n'.join(filtered_logs)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.text_area(
            "Log Output", 
            filtered_content, 
            height=500, 
            key="log_area"
        )
    with col2:
        st.download_button(
            "📥 Download Logs",
            data=log_content,
            file_name=f"recon_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            key="download_logs"
        )
        
        # Add log statistics
        log_stats = {
            "Total Lines": log_content.count('\n') + 1,
            "INFO": sum(1 for line in log_content.split('\n') if "INFO" in line),
            "WARNING": sum(1 for line in log_content.split('\n') if "WARNING" in line),
            "ERROR": sum(1 for line in log_content.split('\n') if "ERROR" in line),
            "DEBUG": sum(1 for line in log_content.split('\n') if "DEBUG" in line)
        }
        
        st.write("Log Statistics:")
        for key, value in log_stats.items():
            if key == "WARNING" and value > 0:
                st.warning(f"{key}: {value}")
            elif key == "ERROR" and value > 0:
                st.error(f"{key}: {value}")
            else:
                st.info(f"{key}: {value}")

# Add missing method to ReconnaissanceResult (since it's referenced in the UI but might not exist)
def ensure_to_json_method():
    """Monkey patch the ReconnaissanceResult class with to_json method if it doesn't exist"""
    if not hasattr(ReconnaissanceResult, 'to_json'):
        def to_json(self) -> str:
            """Convert the result to a JSON-formatted string"""
            try:
                # Basic serialization approach - can be enhanced as needed
                data = {
                    "target_organization": self.target_organization,
                    "scan_time": datetime.now().strftime(DATE_FORMAT),
                    "asns": [
                        {
                            "number": asn.number,
                            "name": asn.name, 
                            "description": asn.description,
                            "country": asn.country,
                            "data_source": asn.data_source
                        } for asn in self.asns
                    ],
                    "ip_ranges": [
                        {
                            "cidr": ipr.cidr,
                            "version": ipr.version,
                            "data_source": ipr.data_source
                        } for ipr in self.ip_ranges
                    ],
                    "domains": [
                        {
                            "name": dom.name,
                            "registrar": dom.registrar,
                            "data_source": dom.data_source,
                            "creation_date": dom.creation_date.strftime(DATE_FORMAT) if dom.creation_date else None,
                            "subdomains": [
                                {
                                    "fqdn": sub.fqdn,
                                    "status": sub.status,
                                    "resolved_ips": list(sub.resolved_ips) if sub.resolved_ips else [],
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
                return json.dumps(data, indent=2)
            except Exception as e:
                logger.error(f"Error serializing result to JSON: {e}")
                return json.dumps({"error": "Failed to serialize result"})
                
        # Add the method to the class
        setattr(ReconnaissanceResult, 'to_json', to_json)

# --- Main App ---
def main():
    # Apply custom CSS
    apply_custom_css()
    
    # Ensure the to_json method exists in ReconnaissanceResult
    ensure_to_json_method()
    
    # Custom header with logo-like element
    st.markdown(f"""
    <div class="app-header">
        <div class="app-logo">{ICONS["app"]}</div>
        <div class="app-title">Enterprise Asset Reconnaissance</div>
    </div>
    """, unsafe_allow_html=True)

    # --- Sidebar ---
    with st.sidebar:
        st.markdown(f"## {ICONS['app']} Control Panel")
        st.markdown("---")
        
        # Display help/about section
        with st.expander("ℹ️ About This Tool", expanded=False):
            st.markdown("""
            **Enterprise Asset Reconnaissance** is a cybersecurity tool designed to discover and map digital assets belonging to an organization.
            
            **Key capabilities:**
            - Domain & subdomain discovery
            - ASN identification
            - IP range enumeration
            - Cloud service detection
            - Network relationship visualization
            
            **How to use:**
            1. Enter organization name
            2. Optionally add base domains
            3. Click 'Start Reconnaissance'
            4. Wait for results to be displayed
            
            For the best results, provide accurate organization names and known domains.
            """)
        
        # Add branding/contact in sidebar footer
        st.markdown("---")
        st.markdown("📧 support@recon-tool.com")
        st.markdown("🌐 https://recon-tool.io")
        st.markdown(f"Version 2.0 | © {datetime.now().year}")

    # --- Input Form ---
    st.markdown("### 🎯 Target Configuration")
    
    # Create a better looking form with cards
    form_container = st.container()
    with form_container:
        with st.form("recon_form", border=False):
            # Main input fields
            target_org = st.text_input(
                "**Organization Name**", 
                placeholder="e.g., Acme Corporation",
                help="Enter the exact legal name of the target organization for best results"
            )
            
            base_domains_input = st.text_input(
                "Known Domains (Optional)", 
                placeholder="e.g., acme.com, acmecorp.net",
                help="Comma-separated list of domains known to belong to the organization"
            )
            
            # Advanced options in an expander
            with st.expander("⚙️ Advanced Scan Options"):
                col_opts1, col_opts2 = st.columns(2)
                with col_opts1:
                     workers = st.slider(
                         "Concurrent Workers", 
                         min_value=5, 
                         max_value=50,
                         value=discovery_orchestrator.DEFAULT_MAX_WORKERS,
                         help="Higher values may improve performance but can trigger rate limits"
                     )
                with col_opts2:
                     # Add some vertical space to align checkbox better with slider
                     st.write("") 
                     st.write("") 
                     include_subdomains = st.checkbox(
                         "Include Subdomains", 
                         value=True,
                         help="Discovery and scan subdomains of the target domains"
                     )
            
            # Add a 'Go' button centered and larger
            submitted = st.form_submit_button(
                f"🚀 Start Reconnaissance",
                type="primary",
                use_container_width=True
            )
                
            if submitted:
                if not target_org:
                    st.error("⛔ Organization Name is required.")
                else:
                    # Process domains input
                    base_domains_set = set()
                    if base_domains_input:
                        base_domains_set = {d.strip().lower() for d in base_domains_input.split(',') if d.strip()}
                        
                    # Set state to trigger scan
                    st.session_state.run_scan = True
                    st.session_state.target_org = target_org
                    st.session_state.base_domains = base_domains_set
                    st.session_state.max_workers = workers
                    st.session_state.include_subdomains = include_subdomains
                    st.rerun()

    # --- Recent Scans History (persistent storage) --- 
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    
    # Save scan to history when completed
    if ('recon_result' in st.session_state and 
        st.session_state.recon_result and 
        not st.session_state.scan_running and
        st.session_state.get('should_save_to_history', False)):
        
        result = st.session_state.recon_result
        scan_time = datetime.now().strftime(DATE_FORMAT)
        
        # Create a history entry
        history_entry = {
            'target': result.target_organization,
            'timestamp': scan_time,
            'summary': {
                'asns': len(result.asns),
                'ip_ranges': len(result.ip_ranges),
                'domains': len(result.domains),
                'subdomains': len(get_subdomain_df(result.domains)) if result.domains else 0,
                'cloud_services': len(result.cloud_services),
                'warnings': len(result.warnings)
            }
        }
        
        # Add to history if not already there
        if not any(entry['target'] == result.target_organization and 
                   entry['timestamp'] == scan_time for entry in st.session_state.scan_history):
            st.session_state.scan_history.insert(0, history_entry)
            # Limit history size
            if len(st.session_state.scan_history) > 10:
                st.session_state.scan_history = st.session_state.scan_history[:10]
        
        # Reset the save flag
        st.session_state.should_save_to_history = False
    
    # Display recent scans if there's no active scan and no results
    if not st.session_state.get('scan_running', False) and not st.session_state.get('recon_result', None):
        if st.session_state.scan_history:
            st.markdown("### 📜 Recent Scans")
            history_data = []
            
            for entry in st.session_state.scan_history:
                history_data.append({
                    "Target": entry['target'],
                    "Scan Time": entry['timestamp'],
                    "ASNs": entry['summary']['asns'],
                    "IP Ranges": entry['summary']['ip_ranges'],
                    "Domains": entry['summary']['domains'],
                    "Subdomains": entry['summary']['subdomains'],
                    "Warnings": entry['summary']['warnings']
                })
            
            if history_data:
                history_df = pd.DataFrame(history_data)
                st.dataframe(history_df, use_container_width=True)

    # --- Session State Initialization ---
    if 'recon_result' not in st.session_state:
        st.session_state.recon_result = None
    if 'log_stream' not in st.session_state:
        st.session_state.log_stream = io.StringIO()
    if 'scan_running' not in st.session_state:
        st.session_state.scan_running = False
    if 'run_scan' not in st.session_state:
        st.session_state.run_scan = False
    if 'should_save_to_history' not in st.session_state:
        st.session_state.should_save_to_history = False
    
    # --- Logging Handler --- 
    log_capture_handler = StringLogHandler(st.session_state.log_stream)
    if not any(isinstance(h, StringLogHandler) for h in logging.getLogger().handlers):
        logging.getLogger().addHandler(log_capture_handler)
        logger.debug("StringLogHandler added to root logger.")
    
    # --- Scan Execution (Using Phases and st.status) ---
    if st.session_state.get("run_scan", False):
        target_org = st.session_state.target_org 
        base_domains_set = st.session_state.base_domains
        max_workers = st.session_state.get("max_workers", discovery_orchestrator.DEFAULT_MAX_WORKERS)

        st.session_state.scan_running = True
        # Initialize result object here
        st.session_state.recon_result = ReconnaissanceResult(target_organization=target_org)
        # Clear logs
        st.session_state.log_stream.seek(0)
        st.session_state.log_stream.truncate(0) 
        
        # Initialize scan start time
        scan_start_time = time.time()
        
        # Display scan header
        st.markdown(f"""
        <div style="margin-bottom: 20px; padding: 20px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid var(--primary);">
            <h2 style="margin-top:0">{ICONS["app"]} Reconnaissance Scan</h2>
            <p><strong>Target Organization:</strong> {target_org}</p>
            <p><strong>Base Domains:</strong> {', '.join(base_domains_set) if base_domains_set else 'None specified'}</p>
            <p><strong>Started:</strong> {datetime.now().strftime(DATE_FORMAT)}</p>
        </div>
        """, unsafe_allow_html=True)
        
        configure_logging(level=logging.INFO, stream_handler=log_capture_handler)

        # Define phases with friendly names and icons
        phases = [
            {"name": "Domain Discovery", "icon": ICONS["domain"], "func": discovery_orchestrator.run_phase1_domains},
            {"name": "ASN Identification", "icon": ICONS["asn"], "func": discovery_orchestrator.run_phase2_asns},
            {"name": "IP Range Mapping", "icon": ICONS["ip"], "func": discovery_orchestrator.run_phase3_ip_ranges},
            {"name": "Cloud Service Detection", "icon": ICONS["cloud"], "func": discovery_orchestrator.run_phase4_cloud},
        ]
        
        with st.status("🚀 Running reconnaissance scan...", expanded=True) as overall_status:
            try:
                current_result = st.session_state.recon_result
                
                # Create progress tracker
                progress_container = st.empty()
                progress_bar = st.progress(0.0, text="Initializing scan...")
                
                # Run each phase with visual feedback
                for i, phase in enumerate(phases):
                    phase_start_time = time.time()
                    phase_name = phase["name"]
                    phase_icon = phase["icon"]
                    phase_func = phase["func"]
                    
                    # Calculate progress
                    progress_value = i / len(phases)
                    progress_bar.progress(progress_value, f"Running {phase_icon} {phase_name}...")
                    
                    # Update status with phase info
                    overall_status.write(f"{ICONS['running']} Running {phase_icon} {phase_name}")
                    logger.info(f"Starting phase: {phase_name}")
                    
                    # Execute the phase function with appropriate parameters
                    try:
                        if phase_name == "Domain Discovery":
                            phase_func(target_org, base_domains_set, current_result, max_workers)
                        elif phase_name == "ASN Identification":
                            phase_func(target_org, base_domains_set, current_result, max_workers)
                        elif phase_name == "IP Range Mapping":
                            phase_func(current_result, max_workers)
                        elif phase_name == "Cloud Service Detection":
                            phase_func(current_result, max_workers)
                    
                        # Calculate phase duration
                        phase_duration = time.time() - phase_start_time
                        overall_status.write(f"{ICONS['completed']} Completed {phase_icon} {phase_name} in {phase_duration:.2f}s")
                        
                        # If this is Domain Discovery and we found domains, show the count
                        if phase_name == "Domain Discovery" and current_result.domains:
                            domains_count = len(current_result.domains)
                            subdomains_count = len(current_result.get_all_subdomains())
                            overall_status.write(f"  └─ Found {domains_count} domains and {subdomains_count} subdomains")
                        
                        # If this is ASN Discovery and we found ASNs, show the count
                        elif phase_name == "ASN Identification" and current_result.asns:
                            asn_count = len(current_result.asns)
                            overall_status.write(f"  └─ Identified {asn_count} ASNs")
                            
                        # If this is IP Range Mapping and we found IP ranges, show the count
                        elif phase_name == "IP Range Mapping" and current_result.ip_ranges:
                            ip_range_count = len(current_result.ip_ranges)
                            overall_status.write(f"  └─ Mapped {ip_range_count} IP ranges")
                            
                        # If this is Cloud Detection and we found cloud services, show the count
                        elif phase_name == "Cloud Service Detection" and current_result.cloud_services:
                            cloud_count = len(current_result.cloud_services)
                            overall_status.write(f"  └─ Detected {cloud_count} cloud services")
                        
                    except Exception as e:
                        logger.exception(f"Error during {phase_name}")
                        overall_status.write(f"{ICONS['error']} Error in {phase_icon} {phase_name}: {str(e)}")
                        current_result.add_warning(f"Error in {phase_name}: {str(e)}")
                    
                    # Add visual separator between phases
                    if i < len(phases) - 1:
                        overall_status.write("---")
                
                # Calculate total scan duration
                total_duration = time.time() - scan_start_time
                
                # Final progress update
                progress_bar.progress(1.0, f"Scan completed in {total_duration:.2f}s")
                
                # Update overall status upon successful completion
                overall_status.update(
                    label=f"✅ Reconnaissance Complete ({total_duration:.2f}s)", 
                    state="complete", 
                    expanded=False
                )
                
                # Display success message
                st.success(f"Reconnaissance completed successfully in {total_duration:.2f} seconds!")
                
                # Mark for history saving
                st.session_state.should_save_to_history = True
                
            except Exception as e:
                logger.exception("An unhandled error occurred during the reconnaissance process")
                st.error(f"An unhandled error occurred: {e}")
                
                # Update status to error state
                overall_status.update(label="❌ Error during Reconnaissance!", state="error")
                overall_status.error(f"Error details: {str(e)}")
                st.session_state.recon_result = None # Clear results on error
                
            finally:
                st.session_state.scan_running = False
                st.session_state.run_scan = False # Reset trigger
                
                # Show a button to view results or restart
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

    # --- Display Results --- 
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

    # Show welcome message for new users with improved Key Features
    elif not st.session_state.scan_running and not st.session_state.recon_result and not st.session_state.scan_history:
        st.markdown("""
        <div style="text-align: center; padding: 3rem; background-color: #f8f9fa; border-radius: 8px; margin: 2rem 0;">
            <h2>Welcome to Enterprise Asset Reconnaissance</h2>
            <p style="font-size: 1.2rem; margin: 1rem 0;">
                Discover and map your organization's digital footprint with our advanced reconnaissance tool.
            </p>
            <p style="font-size: 1rem; color: #6c757d;">
                Enter your target organization details above to begin scanning.
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Feature highlights with improved styling
        st.markdown("### 🌟 Key Features")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="features-card">
                <h4>🌐 Asset Discovery</h4>
                <ul>
                    <li>Domain & subdomain mapping</li>
                    <li>ASN identification</li>
                    <li>IP range enumeration</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown("""
            <div class="features-card">
                <h4>☁️ Cloud Detection</h4>
                <ul>
                    <li>AWS resources</li>
                    <li>Azure services</li>
                    <li>Google Cloud Platform</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
            
        with col3:
            st.markdown("""
            <div class="features-card">
                <h4>📊 Visualization</h4>
                <ul>
                    <li>Interactive network graphs</li>
                    <li>Detailed asset tables</li>
                    <li>Exportable reports</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

        # Add an additional row of features
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="features-card">
                <h4>🔍 Comprehensive Analysis</h4>
                <ul>
                    <li>Domain ownership details</li>
                    <li>IP geolocation</li>
                    <li>Infrastructure assessment</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown("""
            <div class="features-card">
                <h4>🛡️ Security Insights</h4>
                <ul>
                    <li>Attack surface visualization</li>
                    <li>External asset inventory</li>
                    <li>Security posture assessment</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
            
        with col3:
            st.markdown("""
            <div class="features-card">
                <h4>📱 Seamless Experience</h4>
                <ul>
                    <li>Modern, intuitive interface</li>
                    <li>Progress tracking</li>
                    <li>Exportable results</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

if __name__ == "__main__":
    main() 