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
from datetime import datetime, timedelta
from typing import Set, List, Dict, Any, Optional, Tuple
import pandas as pd
import ipaddress

from src import db_manager
from src.utils.logging_config import StringLogHandler, setup_logging as configure_logging
from src.utils.logging_config import create_progress_logger, get_logger
from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, CloudService, Subdomain
from src.orchestration import discovery_orchestrator
from src.visualization.network_graph import generate_network_graph

# --- Logger ---
logger = get_logger(__name__)

# --- Constants ---
DEFAULT_PAGINATION_SIZE = 50
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
ICONS = {
    "app": "🔍", "db": "💾", "load": "🔄", "scan": "🚀",
    "summary": "📊", "asn": "🌐", "ip": "💻", "domain": "🌍",
    "subdomain": "🔗", "cloud": "☁️", "graph": "🕸️", "logs": "⚙️",
    "success": "✅", "warning": "⚠️", "error": "❌", "info": "ℹ️",
    "pending": "⏳", "running": "⌛", "completed": "✓"
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
        --sidebar-bg: #ffffff; /* Cambiado a blanco */
        --sidebar-text: #2c3e50;
    }
    
    /* Global styles */
    .main {
        background-color: var(--background);
        color: var(--text);
    }
    
    /* Ensure general labels (like for text input) are visible */
    label {
        color: var(--text); /* Ensure labels are generally dark */
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
    /* Make sure slider labels also inherit general label color if needed */
    .stSlider label {
        font-weight: 500;
        /* color: var(--text); /* Removed if covered by general label style */
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
    
    /* Download Button Specific Style */
    .stDownloadButton>button {
        background-color: var(--secondary); /* Darker background */
        color: white; /* White text for contrast */
    }
    .stDownloadButton>button:hover {
         background-color: var(--primary); /* Use primary color on hover */
         color: white;
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
    
    /* Custom Status indicators - Add specific text color */
    .status-card {
        padding: 1rem;
        border-radius: 6px;
        margin-bottom: 1rem;
        color: var(--text); /* Default dark text for status cards */
    }
    
    .status-success {
        background-color: rgba(40, 167, 69, 0.1);
        border-left: 4px solid var(--success);
        color: #155724; /* Dark green text */
    }
    
    .status-warning {
        background-color: rgba(255, 193, 7, 0.1);
        border-left: 4px solid var(--warning);
        color: #000000; /* Black text for warnings */
    }
    
    .status-error {
        background-color: rgba(220, 53, 69, 0.1);
        border-left: 4px solid var(--danger);
        color: #000000; /* Black text for errors */
    }
    
    .status-info {
        background-color: rgba(23, 162, 184, 0.1);
        border-left: 4px solid var(--info);
        color: #0c5460; /* Dark cyan text */
    }
    
    /* Status card headings */
    .status-card h4 {
         color: inherit; /* Inherit the specific color set above */
         font-weight: 600;
    }
    
    /* Fix for Streamlit built-in Alerts (st.error, st.warning, etc.) */
    div[data-testid="stAlert"] {
        color: var(--text) !important; /* Force dark text by default */
    }
    div[data-testid="stAlert"][data-alert-type="error"] {
        color: #000000 !important; /* Force black text for errors */
    }
    div[data-testid="stAlert"][data-alert-type="warning"] {
        color: #000000 !important; /* Force black text for warnings */
    }
     div[data-testid="stAlert"][data-alert-type="info"] {
        color: #0c5460 !important; /* Force dark cyan text for info */
    }
     div[data-testid="stAlert"][data-alert-type="success"] {
        color: #155724 !important; /* Force dark green text for success */
    }
    
    /* Fix for form validation error messages */
    .stForm [data-baseweb="notification"] {
        color: #000000 !important; /* Force black text */
    }

    /* General fix for all Streamlit error messages */
    .element-container div[role="alert"] {
        color: #000000 !important; /* Force black text */
    }

    /* Additional fix for any Streamlit validation messages */
    small[data-testid="stFormSubmitButton-warning"] {
        color: #000000 !important; /* Force black text */
    }

    /* General reset for any light text on light backgrounds */
    .stException, .stWarning, .stError, small[role="alert"] {
        color: #000000 !important; /* Force black text */
    }

    /* Text inside form feedback messages */
    .stForm [data-baseweb="notification"] p, 
    .stForm [role="alert"] p,
    [data-testid="stForm"] [role="alert"] {
        color: #000000 !important; /* Force black text */
    }

    /* Progress log messages that show errors */
    .stProgress p, .stProgress div {
        color: var(--text) !important; /* Ensure dark text */
    }

    /* Any remaining error element */
    [class*="error"], [class*="warning"] {
        color: #000000 !important; /* Force black text */
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
    
    /* Target st.metric label specifically using internal paragraph */
    div[data-testid="stMetric"] p {
        font-size: 0.85rem;
        color: var(--secondary) !important; /* Apply dark color to the <p> tag inside */
        text-transform: uppercase;
        letter-spacing: 0.05rem;
        margin-bottom: 0.25rem; /* Add a little space below the label */
    }
    
    /* Table styles */
    .dataframe {
        font-size: 0.9rem;
    }
    
    .dataframe th {
        background-color: var(--secondary);
        color: white;
        font-weight: 600;
        text-align: left; /* Ensure header text aligns left */
    }
    
    .dataframe td {
         background-color: var(--card); /* Explicitly white background for cells */
         color: var(--text); /* Explicitly dark text */
         border-bottom: 1px solid #eee; /* Add subtle row separator */
    }
    
    /* Input field styling */
    input[type="text"], 
    textarea, 
    .stTextInput div[data-baseweb="input"], 
    .stTextArea div[data-baseweb="input"] {
        background-color: white !important; /* Force white background */
        color: var(--text) !important; /* Force dark text */
        border: 1px solid #ccc !important; /* Add a light border */
        border-radius: 4px !important;
    }
    
    /* Ensure placeholder text is also visible */
    input[type="text"]::placeholder, 
    textarea::placeholder {
      color: var(--text-light);
      opacity: 0.7;
    }
    
    /* Download Button - Ensure Contrast */
    .stDownloadButton>button {
        background-color: var(--secondary); /* Keep dark background */
        color: white !important; /* Ensure white text */
        border: none; /* Remove border if any */
    }
    .stDownloadButton>button:hover {
         background-color: var(--primary) !important; /* Lighter on hover */
         color: white !important;
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
    
    /* Progress bar text styling - ensure visibility */
    .stProgress > div > div > div > div {
        color: var(--text) !important; /* Force dark text color */
        font-weight: 500 !important; /* Make text slightly bolder */
    }
    
    /* Progress bar container */
    .stProgress {
        background-color: white !important; /* Force white background */
    }
    
    /* Progress bar caption/label */
    .stProgress p {
        color: var(--text) !important; /* Force dark text color */
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

    /* Sidebar styling with improved design */
    [data-testid="stSidebar"] {
        background-color: var(--sidebar-bg);
        border-right: 1px solid rgba(0,0,0,0.05);
        box-shadow: 1px 0px 10px rgba(0,0,0,0.03);
    }

    /* Sidebar header with logo and title */
    .sidebar-header {
        display: flex;
        align-items: center;
        padding: 1rem 0.5rem;
        margin-bottom: 0.5rem;
    }

    .sidebar-logo {
        font-size: 1.8rem;
        margin-right: 12px;
        color: var(--primary);
    }

    .sidebar-title {
        font-size: 1.4rem;
        font-weight: 600;
        color: var(--secondary);
    }

    /* Dividers in sidebar */
    .sidebar-divider {
        height: 1px;
        background-color: rgba(0,0,0,0.05);
        margin: 1rem 0;
    }

    /* Section titles */
    .sidebar-section {
        margin-bottom: 1rem;
    }

    .sidebar-section-title {
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 0.05rem;
        color: var(--text-light);
        margin-bottom: 0.5rem;
        font-weight: 500;
        padding: 0 0.5rem;
    }

    /* Sidebar buttons styling - enhanced */
    [data-testid="stSidebar"] [data-testid="baseButton-secondary"] {
        background-color: transparent;
        color: var(--text);
        border: none;
        border-radius: 6px;
        text-align: left;
        margin-bottom: 0.5rem;
        transition: all 0.2s;
        padding: 0.6rem 0.8rem;
        font-weight: 500;
        box-shadow: none;
    }

    [data-testid="stSidebar"] [data-testid="baseButton-secondary"]:hover {
        background-color: rgba(30, 101, 243, 0.08);
        color: var(--primary);
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }

    /* Active navigation styling */
    [data-testid="stSidebar"] [data-testid="baseButton-secondary"]:active {
        background-color: rgba(30, 101, 243, 0.12);
        color: var(--primary);
        transform: scale(0.98);
    }

    /* Add left border indicator to navigation buttons */
    [data-testid="stSidebar"] .element-container:has([data-testid="baseButton-secondary"]) {
        border-left: 3px solid transparent;
        padding-left: 0.5rem;
        margin-left: 0.5rem;
    }

    [data-testid="stSidebar"] .element-container:has([data-testid="baseButton-secondary"]):hover {
        border-left-color: var(--primary-light);
    }

    /* Footer in sidebar */
    .sidebar-footer {
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        max-width: 320px; /* Ancho máximo para evitar problemas */
        padding: 1rem;
        background-color: #fafafa;
        border-top: 1px solid rgba(0,0,0,0.05);
        font-size: 0.8rem;
        text-align: center;
        z-index: 100; /* Asegurar que esté sobre otros elementos */
    }

    /* Espacio adicional para sidebar para evitar solapamientos con el footer */
    [data-testid="stSidebar"] .stApp {
        padding-bottom: 100px;
    }

    /* Asegurar que el último expansor tenga suficiente margen */
    [data-testid="stSidebar"] [data-testid="stExpander"]:last-of-type {
        margin-bottom: 100px;
    }

    .footer-company {
        font-weight: 600;
        color: var(--primary);
        margin-bottom: 0.2rem;
    }

    .footer-version {
        color: var(--text-light);
        margin-bottom: 0.2rem;
    }

    .footer-copyright {
        color: var(--text-light);
    }

    /* Expander styling in sidebar */
    [data-testid="stSidebar"] [data-testid="stExpander"] {
        border: none;
        box-shadow: none;
        background-color: transparent;
        padding: 0;
        margin-bottom: 0.5rem;
    }

    [data-testid="stSidebar"] [data-testid="stExpander"] details {
        background-color: white;
        border-radius: 4px;
        border: 1px solid rgba(0,0,0,0.05);
    }

    [data-testid="stSidebar"] [data-testid="stExpander"] summary {
        padding: 0.6rem;
        font-weight: 500;
        color: var(--text);
    }
    
    /* Ensure text inside sidebar expanders is dark */
    [data-testid="stSidebar"] [data-testid="stExpander"] p,
    [data-testid="stSidebar"] [data-testid="stExpander"] li,
    [data-testid="stSidebar"] [data-testid="stExpander"] span,
    [data-testid="stSidebar"] [data-testid="stExpander"] strong,
    [data-testid="stSidebar"] [data-testid="stExpander"] em,
    [data-testid="stSidebar"] [data-testid="stExpander"] div {
        color: var(--text) !important; /* Force dark text */
    }
    
    /* Ensure Checkbox labels are also visible */
    div[data-testid="stCheckbox"] label p {
        color: var(--text) !important; /* Force dark text for checkbox labels */
    }

    /* New styles for sidebar navigation */
    .sidebar-nav-link {
        display: block;
        text-align: center;
        text-decoration: none;
        color: var(--text);
        padding: 0.5rem 0.25rem;
        border-radius: 4px;
        transition: all 0.2s;
        font-weight: 500;
        font-size: 0.9rem;
    }

    .sidebar-nav-link:hover {
        color: var(--primary);
        background-color: rgba(30, 101, 243, 0.08);
    }

    /* Button styles in sidebar */
    [data-testid="stSidebar"] button {
        background-color: white !important;
        color: var(--text) !important;
        border: 1px solid #e0e0e0 !important;
        border-radius: 6px !important;
        margin-bottom: 0.5rem !important;
        font-weight: 500 !important;
        transition: all 0.2s !important;
        box-shadow: none !important;
    }

    [data-testid="stSidebar"] button:hover {
        background-color: #f8f9fa !important;
        border-color: var(--primary) !important;
        color: var(--primary) !important;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05) !important;
        transform: translateY(-1px) !important;
    }
    </style>
    """, unsafe_allow_html=True)

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
                return json.dumps(data, indent=2, default=str) # Use default=str for datetimes if needed
            except Exception as e:
                logger.error(f"Error serializing result to JSON: {e}")
                return json.dumps({"error": "Failed to serialize result"})
                
        # Add the method to the class
        setattr(ReconnaissanceResult, 'to_json', to_json)
    else:
         logger.debug("ReconnaissanceResult already has to_json method.")

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
            return "🟠 AWS"
        elif "azure" in provider or "microsoft" in provider:
            return "🔵 Azure"
        elif "google" in provider or "gcp" in provider:
            return "🟢 GCP"
        elif "cloudflare" in provider:
            return "🟡 Cloudflare"
        elif "digital ocean" in provider:
            return "🔷 Digital Ocean"
        elif "oracle" in provider:
            return "🔶 Oracle"
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
        # Use st.text_area for plain text logs
        st.text_area(
            "Log Output", 
            value=filtered_content,  # Use the filtered content directly
            height=500, 
            key="log_area",
            help="Raw process logs. ANSI color codes are stripped for display."
        )
    
    with col2:
        # Download button uses the raw original log_content
        st.download_button(
            "📥 Download Logs",
            data=log_content, 
            file_name=f"recon_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            key="download_logs"
        )
        
        # Log statistics
        st.markdown("**Log Statistics:**")
        log_stats = {
            "Total Lines": log_content.count('\n') + (1 if log_content else 0),
            "INFO": sum(1 for line in log_content.split('\n') if " INFO " in line), # Use spaces to avoid matching level name in message
            "WARNING": sum(1 for line in log_content.split('\n') if " WARNING " in line),
            "ERROR": sum(1 for line in log_content.split('\n') if " ERROR " in line),
            "DEBUG": sum(1 for line in log_content.split('\n') if " DEBUG " in line)
        }
        for key, value in log_stats.items():
            if key == "WARNING" and value > 0:
                st.warning(f"{key}: {value}")
            elif key == "ERROR" and value > 0:
                st.error(f"{key}: {value}")
            else:
                st.info(f"{key}: {value}")

# --- Main App ---
def main():
    # Initialize the database first
    db_manager.init_db()
    
    # Apply custom CSS
    apply_custom_css()
    
    # Ensure the to_json method exists in ReconnaissanceResult
    ensure_to_json_method()
    
    # --- Session State Initialization ---
    # Check if keys exist before initializing to avoid overwriting loaded data
    if 'recon_result' not in st.session_state:
        st.session_state.recon_result = None
    if 'log_stream' not in st.session_state:
        st.session_state.log_stream = io.StringIO()
    if 'log_handler' not in st.session_state: # Add handler to session state
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
        st.session_state.max_workers = discovery_orchestrator.DEFAULT_MAX_WORKERS
    if 'include_subdomains' not in st.session_state:
        st.session_state.include_subdomains = True
    if 'current_view' not in st.session_state:
        st.session_state.current_view = "home"
    
    # Flag to indicate if we need to ask the user about loading vs scanning
    if 'ask_load_or_scan' not in st.session_state:
        st.session_state.ask_load_or_scan = False
    if 'existing_scan_id' not in st.session_state:
        st.session_state.existing_scan_id = None
    if 'expand_history' not in st.session_state:
        st.session_state.expand_history = False

    # Custom header
    st.markdown(f'<div class="app-header"><div class="app-logo">{ICONS["app"]}</div><div class="app-title">Enterprise Asset Reconnaissance</div></div>', unsafe_allow_html=True)

    # Callbacks para botones de navegación
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

    # --- Sidebar ---
    with st.sidebar:
        # Logo and title at the top
        st.markdown(f"""
        <div class="sidebar-header">
            <div class="sidebar-logo">{ICONS["app"]}</div>
            <div class="sidebar-title">Recon Tool</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
        
        # Main navigation section
        st.markdown('<div class="sidebar-section"><div class="sidebar-section-title">Navigation</div></div>', unsafe_allow_html=True)
        
        # Botones de navegación con callbacks - versión sin columnas
        st.button("🏠 Home", on_click=go_home, key="nav_home", use_container_width=True)
        st.button("🔍 New Scan", on_click=go_new_scan, key="nav_scan", use_container_width=True)
        st.button("📚 History", on_click=go_history, key="nav_history", use_container_width=True)
        
        # Separador
        st.markdown('<div class="sidebar-divider"></div>', unsafe_allow_html=True)
        
        # Quick help section
        st.markdown('<div class="sidebar-section"><div class="sidebar-section-title">Help & Resources</div></div>', unsafe_allow_html=True)
        
        # Help and resources con clase adicional para margen inferior
        with st.expander("ℹ️ About This Tool", expanded=False):
            st.markdown("""
            **Enterprise Asset Reconnaissance** is a cybersecurity tool that discovers and maps digital assets belonging to an organization.
            
            **Key capabilities:**
            - ASN & IP range identification
            - Domain & subdomain discovery
            - Cloud service detection
            - Network visualization
            """)
        
        with st.expander("📋 Quick Tips", expanded=False):
            st.markdown("""
            - Enter the exact legal name for best results
            - Add known domains to improve accuracy
            - Use advanced options for complex scans
            - Check logs tab for detailed information
            """)
        
        # Añadir espacio adicional después del último expansor
        st.markdown('<div style="margin-bottom: 80px;"></div>', unsafe_allow_html=True)
        
        # Footer section
        st.markdown(f"""
        <div class="sidebar-footer">
            <div class="footer-company">Recon Tool</div>
            <div class="footer-version">Version 1.0</div>
            <div class="footer-copyright">© {datetime.now().year}</div>
        </div>
        """, unsafe_allow_html=True)

    # --- Input Form & Scan Trigger Logic --- 
    # Mostrar contenido basado en la vista actual
    if st.session_state.current_view == "new_scan":
        # Mostrar formulario de nuevo escaneo
        st.markdown("### 🎯 Target Configuration")
        form_container = st.container()
        with form_container:
            with st.form("recon_form", border=False):
                target_org_input = st.text_input(
                    "**Organization Name**", 
                    value=st.session_state.target_org, # Use session state value
                    placeholder="e.g., Acme Corporation",
                    help="Enter the exact legal name for best results"
                )
                base_domains_input = st.text_input(
                    "Known Domains (Optional)", 
                    value=", ".join(st.session_state.base_domains), # Use session state value
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
                             value=st.session_state.max_workers,
                             help="Higher values may improve performance but can trigger rate limits"
                         )
                    with col_opts2:
                         # Add some vertical space to align checkbox better with slider
                         st.write("") 
                         st.write("") 
                         include_subdomains = st.checkbox(
                             "Include Subdomains", 
                             value=st.session_state.include_subdomains,
                             help="Discovery and scan subdomains of the target domains"
                         )
                
                submitted = st.form_submit_button(f'{ICONS["scan"]} Check Target / Start Scan', type="primary", use_container_width=True)
                    
                if submitted:
                    if not target_org_input:
                        st.error("⛔ Organization Name is required.")
                    else:
                        # Update session state with current inputs
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
                            st.session_state.run_scan = False # Don't run scan yet
                            st.session_state.load_scan_id = None
                        else:
                            st.session_state.ask_load_or_scan = False
                            st.session_state.run_scan = True # No recent scan, proceed
                            st.session_state.load_scan_id = None
                        st.rerun()
    elif st.session_state.current_view == "history":
        # Mostrar historial directamente
        st.markdown("### 📚 Scan History")
        st.markdown("Review your previous reconnaissance scans:")
        # Expandir automáticamente el historial de escaneos
        st.session_state.expand_history = True
    else:  # "home" por defecto
        # Mostrar la pantalla de inicio normal
        st.markdown("### 🎯 Target Configuration")
        form_container = st.container()
        with form_container:
            with st.form("recon_form", border=False):
                target_org_input = st.text_input(
                    "**Organization Name**", 
                    value=st.session_state.target_org, # Use session state value
                    placeholder="e.g., Acme Corporation",
                    help="Enter the exact legal name for best results"
                )
                base_domains_input = st.text_input(
                    "Known Domains (Optional)", 
                    value=", ".join(st.session_state.base_domains), # Use session state value
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
                             value=st.session_state.max_workers,
                             help="Higher values may improve performance but can trigger rate limits"
                         )
                    with col_opts2:
                         # Add some vertical space to align checkbox better with slider
                         st.write("") 
                         st.write("") 
                         include_subdomains = st.checkbox(
                             "Include Subdomains", 
                             value=st.session_state.include_subdomains,
                             help="Discovery and scan subdomains of the target domains"
                         )
                
                submitted = st.form_submit_button(f'{ICONS["scan"]} Check Target / Start Scan', type="primary", use_container_width=True)
                    
                if submitted:
                    if not target_org_input:
                        st.error("⛔ Organization Name is required.")
                    else:
                        # Update session state with current inputs
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
                            st.session_state.run_scan = False # Don't run scan yet
                            st.session_state.load_scan_id = None
                        else:
                            st.session_state.ask_load_or_scan = False
                            st.session_state.run_scan = True # No recent scan, proceed
                            st.session_state.load_scan_id = None
                        st.rerun()

    # --- Ask User: Load Existing or Run New Scan? ---
    if st.session_state.get("ask_load_or_scan", False):
        st.warning(f'{ICONS["db"]} Found a recent scan for "{st.session_state.target_org}".')
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f'{ICONS["load"]} Load Previous Results', use_container_width=True):
                st.session_state.load_scan_id = st.session_state.existing_scan_id
                st.session_state.run_scan = False
                st.session_state.ask_load_or_scan = False
                st.session_state.recon_result = None # Clear any previous result
                st.rerun()
        with col2:
            if st.button(f'{ICONS["scan"]} Run New Scan Anyway', use_container_width=True):
                st.session_state.load_scan_id = None
                st.session_state.run_scan = True
                st.session_state.ask_load_or_scan = False
                st.session_state.recon_result = None # Clear any previous result
                st.rerun()
        # Prevent further execution until user chooses
        st.stop()
        
    # --- Load Scan Execution --- 
    if st.session_state.get("load_scan_id", None) is not None:
        scan_id_to_load = st.session_state.load_scan_id
        logger.info(f"Loading results for scan ID: {scan_id_to_load}")
        with st.spinner(f"Loading results from database for scan ID {scan_id_to_load}..."):
            loaded_result = db_manager.get_result_by_scan_id(scan_id_to_load)
        if loaded_result:
            st.session_state.recon_result = loaded_result
            st.session_state.log_stream.seek(0)
            st.session_state.log_stream.truncate(0)
            st.session_state.log_stream.write(f"--- Loaded results from database for target: {loaded_result.target_organization} ---\n")
            if loaded_result.warnings:
                 st.session_state.log_stream.write(f"\n--- Warnings from loaded scan ---\n")
                 for w in loaded_result.warnings:
                     st.session_state.log_stream.write(f"- {w}\n")
            st.success(f"Successfully loaded previous scan results for '{loaded_result.target_organization}'.")
        else:
            st.error(f"Failed to load results for scan ID {scan_id_to_load}. Please try running a new scan.")
        # Reset flags after loading attempt
        st.session_state.load_scan_id = None
        st.session_state.run_scan = False
        st.session_state.scan_running = False
        st.rerun() # Rerun to display loaded results
        
    # --- New Scan Execution --- 
    if st.session_state.get("run_scan", False):
        target_org = st.session_state.target_org 
        base_domains_set = st.session_state.base_domains
        max_workers = st.session_state.max_workers
        include_subdomains = st.session_state.include_subdomains 

        st.session_state.scan_running = True
        
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
        
        # Configure logging using the HANDLER from session state with enhanced formatting
        configure_logging(
            level=logging.INFO, 
            stream_handler=st.session_state.log_handler,
            use_enhanced_formatter=True,
            color_enabled=True
        ) 

        # Clear the underlying StringIO buffer
        st.session_state.log_stream.seek(0)
        st.session_state.log_stream.truncate(0) 
        
        with st.status("🚀 Running reconnaissance scan...", expanded=True) as overall_status:
            try:
                # Create progress tracker
                progress_container = st.empty()
                progress_bar = st.progress(0.0, text="Initializing scan...")
                
                logger.info(f"Starting reconnaissance scan for target: {target_org}")
                if base_domains_set:
                    logger.info(f"Base domains provided: {', '.join(base_domains_set)}")
                logger.info(f"Using {max_workers} concurrent workers")
                
                # Run the unified discovery process with progress and status callbacks
                current_result = discovery_orchestrator.run_discovery(
                    target_organization=target_org,
                    base_domains=base_domains_set,
                    include_subdomain_discovery=include_subdomains,
                    max_workers=max_workers,
                    progress_callback=lambda p, msg: progress_bar.progress(p / 100.0, msg),
                    status_callback=lambda icon, msg: overall_status.write(f"{icon} {msg}")
                )
                
                # Store the result in session state
                st.session_state.recon_result = current_result
                
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
                logger.info(f"Reconnaissance completed successfully in {total_duration:.2f} seconds")
                st.success(f"Reconnaissance completed successfully in {total_duration:.2f} seconds!")
                
                # --- Save result to DB --- 
                with st.spinner("💾 Saving results to database..."):
                    logger.info(f"Starting database save for target: '{current_result.target_organization}'")
                    save_successful = db_manager.save_scan_result(current_result)
                    
                    # Log success or failure based on return value
                    if save_successful:
                        logger.info("Database save completed successfully.")
                        st.info("Scan results saved to database.")
                    else:
                        logger.error("Database save failed. Check previous logs in db_manager for details.")
                        # Optionally show a more prominent error in the UI
                        st.error("Failed to save scan results to the database. Some data might be lost.")
                # --- End Save --- 
                
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