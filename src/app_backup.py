import streamlit as st

# Set page config at the very beginning
st.set_page_config(
    layout="wide", 
    page_title="ReconForge | Enterprise Asset Intelligence", 
    page_icon="🛡️",
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
DEFAULT_PAGINATION_SIZE = 25
DEFAULT_MAX_WORKERS = 10
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Professional Icons with Enhanced Categories
ICONS = {
    # Core Application
    "app": "🛡️", "forge": "⚡", "enterprise": "🏢", "discovery": "🔬", "intelligence": "🧠",
    
    # Data Types
    "asn": "🌐", "ip": "💻", "domain": "🌍", "subdomain": "🔗", "cloud": "☁️",
    
    # Actions & Status
    "scan": "🎯", "search": "🔍", "load": "📂", "save": "💾", "export": "📤",
    "success": "✅", "warning": "⚠️", "error": "❌", "info": "ℹ️", "pending": "⏳", 
    "running": "⌛", "completed": "✓", "shield": "🔰", "radar": "📡", "target": "🎯",
    
    # Interface Elements
    "dashboard": "📊", "summary": "📈", "graph": "🕸️", "logs": "📋", "settings": "⚙️",
    "home": "🏠", "history": "📚", "analytics": "📊", "reports": "📄", "tools": "🛠️",
    
    # Security & Professional
    "security": "🛡️", "threat": "⚠️", "monitoring": "📈", "assessment": "🔍",
    "compliance": "✓", "audit": "📋", "forensics": "🔬", "investigation": "🔍"
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
    """Apply professional, modern CSS styling with advanced design patterns"""
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    /* CSS Variables for Professional Theming */
    :root {{
        /* Brand Colors */
        --primary: {COLORS["primary"]};
        --primary-light: {COLORS["primary_light"]};
        --primary-dark: {COLORS["primary_dark"]};
        --primary-gradient: {COLORS["primary_gradient"]};
        
        /* Secondary & Accent */
        --secondary: {COLORS["secondary"]};
        --secondary-light: {COLORS["secondary_light"]};
        --accent: {COLORS["accent"]};
        --accent-secondary: {COLORS["accent_secondary"]};
        --accent-warning: {COLORS["accent_warning"]};
        --accent-info: {COLORS["accent_info"]};
        
        /* Backgrounds */
        --background: {COLORS["background"]};
        --background-dark: {COLORS["background_dark"]};
        --surface: {COLORS["surface"]};
        --surface-secondary: {COLORS["surface_secondary"]};
        --surface-elevated: {COLORS["surface_elevated"]};
        --surface-dark: {COLORS["surface_dark"]};
        
        /* Text */
        --text: {COLORS["text"]};
        --text-secondary: {COLORS["text_secondary"]};
        --text-muted: {COLORS["text_muted"]};
        --text-light: {COLORS["text_light"]};
        --text-inverse: {COLORS["text_inverse"]};
        
        /* Semantic */
        --success: {COLORS["success"]};
        --success-bg: {COLORS["success_bg"]};
        --warning: {COLORS["accent_warning"]};
        --warning-bg: {COLORS["warning_bg"]};
        --error: {COLORS["error"]};
        --error-bg: {COLORS["error_bg"]};
        --info: {COLORS["info"]};
        --info-bg: {COLORS["info_bg"]};
        
        /* Borders & Effects */
        --border: {COLORS["border"]};
        --border-light: {COLORS["border_light"]};
        --shadow: {COLORS["shadow"]};
        --shadow-lg: {COLORS["shadow_lg"]};
        
        /* Sidebar */
        --sidebar-bg: {COLORS["sidebar_bg"]};
        --sidebar-surface: {COLORS["sidebar_surface"]};
        --sidebar-text: {COLORS["sidebar_text"]};
        --sidebar-text-muted: {COLORS["sidebar_text_muted"]};
        
        /* Advanced Gradients */
        --gradient-primary: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
        --gradient-accent: linear-gradient(135deg, var(--accent) 0%, var(--primary) 100%);
        --gradient-dark: linear-gradient(135deg, var(--secondary) 0%, var(--primary-dark) 100%);
        --gradient-surface: linear-gradient(135deg, var(--surface) 0%, var(--surface-elevated) 100%);
        
        /* Shadows */
        --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
        --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        
        /* Animations */
        --transition-fast: 0.15s ease-in-out;
        --transition-normal: 0.25s ease-in-out;
        --transition-slow: 0.4s ease-in-out;
    }}
    
    /* Global Reset & Base Styles */
    * {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    
    .main {{
        background: var(--background);
        color: var(--text);
        padding: 0;
        margin: 0;
    }}
    
    /* Hide Streamlit Default Elements */
    #MainMenu {{visibility: hidden;}}
    footer {{visibility: hidden;}}
    header {{visibility: hidden;}}
    .stDeployButton {{visibility: hidden;}}
    
    /* Enhanced Header Design */
    .professional-header {{
        background: var(--primary-gradient);
        position: relative;
        margin: -1rem -1rem 2rem -1rem;
        padding: 2.5rem 2rem 3rem 2rem;
        border-radius: 0 0 32px 32px;
        box-shadow: var(--shadow-xl);
        overflow: hidden;
    }}
    
    .professional-header::before {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M30 30l10-10v8h8v4h-8v8l-10-10zM10 10l10 10-10 10V20H2v-4h8v-6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        opacity: 0.1;
    }}
    
    .professional-header::after {{
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
        background-size: 30px 30px;
        animation: float 20s ease-in-out infinite;
    }}
    
    @keyframes float {{
        0%, 100% {{ transform: translate(0, 0) rotate(0deg); }}
        33% {{ transform: translate(10px, -10px) rotate(120deg); }}
        66% {{ transform: translate(-5px, 5px) rotate(240deg); }}
    }}
    
    .header-content {{
        position: relative;
        z-index: 2;
        text-align: center;
    }}
    
    .header-title {{
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
    }}
    
    .header-subtitle {{
        font-size: 1.25rem;
        color: rgba(255,255,255,0.9);
        margin: 0 0 1.5rem 0;
        font-weight: 400;
        letter-spacing: 0.025em;
    }}
    
    .header-badge {{
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
        transition: all var(--transition-normal);
    }}
    
    .header-badge:hover {{
        background: rgba(255,255,255,0.25);
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }}
    
    /* Professional Cards */
    .professional-card {{
        background: var(--surface);
        border-radius: 16px;
        padding: 2rem;
        box-shadow: var(--shadow-md);
        border: 1px solid var(--border-light);
        margin: 1.5rem 0;
        transition: all var(--transition-normal);
        position: relative;
        overflow: hidden;
    }}
    
    .professional-card::before {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: var(--primary-gradient);
    }}
    
    .professional-card:hover {{
        transform: translateY(-2px);
        box-shadow: var(--shadow-lg);
    }}
    
    .card-header {{
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1.5rem;
    }}
    
    .card-icon {{
        font-size: 2rem;
        opacity: 0.8;
    }}
    
    .card-title {{
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--text);
        margin: 0;
        line-height: 1.2;
    }}
    
    .card-subtitle {{
        font-size: 0.95rem;
        color: var(--text-muted);
        margin: 0.25rem 0 0 0;
    }}
    
    /* Professional Sidebar */
    .css-1d391kg {{
        background: var(--sidebar-bg) !important;
        border-right: 1px solid var(--border) !important;
    }}
    
    .sidebar-header {{
        background: var(--gradient-accent);
        margin: -1rem -1rem 2rem -1rem;
        padding: 2rem 1rem;
        text-align: center;
        border-radius: 0 0 24px 24px;
        box-shadow: var(--shadow-lg);
        position: relative;
        overflow: hidden;
    }}
    
    .sidebar-logo {{
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
    }}
    
    .sidebar-title {{
        font-size: 1.5rem;
        font-weight: 700;
        color: white;
        margin: 0;
    }}
    
    /* Enhanced Metrics */
    .metrics-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1.5rem;
        margin: 2rem 0;
    }}
    
    .metric-card {{
        background: var(--surface);
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
        box-shadow: var(--shadow-sm);
        border: 1px solid var(--border-light);
        transition: all var(--transition-normal);
        position: relative;
        overflow: hidden;
    }}
    
    .metric-card::before {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: var(--primary-gradient);
    }}
    
    .metric-card:hover {{
        transform: translateY(-2px);
        box-shadow: var(--shadow-md);
    }}
    
    .metric-icon {{
        font-size: 2rem;
        margin-bottom: 0.5rem;
        opacity: 0.8;
    }}
    
    .metric-value {{
        font-size: 2rem;
        font-weight: 700;
        color: var(--primary);
        margin: 0;
        line-height: 1;
    }}
    
    .metric-label {{
        font-size: 0.9rem;
        color: var(--text-muted);
        margin: 0.5rem 0 0 0;
        font-weight: 500;
    }}
    
    /* Status Badges */
    .status-badge {{
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.25rem 0.75rem;
        border-radius: 50px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }}
    
    .status-success {{
        background: var(--success-bg);
        color: var(--success);
        border: 1px solid var(--success);
    }}
    
    .status-warning {{
        background: var(--warning-bg);
        color: var(--warning);
        border: 1px solid var(--warning);
    }}
    
    .status-error {{
        background: var(--error-bg);
        color: var(--error);
        border: 1px solid var(--error);
    }}
    
    .status-info {{
        background: var(--info-bg);
        color: var(--info);
        border: 1px solid var(--info);
    }}
    
    /* Enhanced Progress Bar */
    .professional-progress {{
        width: 100%;
        height: 8px;
        background: var(--surface-secondary);
        border-radius: 50px;
        overflow: hidden;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
    }}
    
    .professional-progress-bar {{
        height: 100%;
        background: var(--primary-gradient);
        border-radius: 50px;
        transition: width var(--transition-normal);
        position: relative;
    }}
    
    .professional-progress-bar::after {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
        animation: shimmer 2s infinite;
    }}
    
    @keyframes shimmer {{
        0% {{ transform: translateX(-100%); }}
        100% {{ transform: translateX(100%); }}
    }}
    
    /* Animation Classes */
    .fade-in {{
        animation: fadeIn 0.6s ease-in-out;
    }}
    
    .fade-in-up {{
        animation: fadeInUp 0.6s ease-in-out;
    }}
    
    .slide-in-left {{
        animation: slideInLeft 0.6s ease-in-out;
    }}
    
    @keyframes fadeIn {{
        from {{ opacity: 0; }}
        to {{ opacity: 1; }}
    }}
    
    @keyframes fadeInUp {{
        from {{ 
            opacity: 0;
            transform: translateY(20px);
        }}
        to {{ 
            opacity: 1;
            transform: translateY(0);
        }}
    }}
    
    @keyframes slideInLeft {{
        from {{ 
            opacity: 0;
            transform: translateX(-20px);
        }}
        to {{ 
            opacity: 1;
            transform: translateX(0);
        }}
    }}
    
    /* Enhanced Streamlit Component Overrides */
    .stTextInput > div > div > input {{
        background: var(--surface) !important;
        border: 2px solid var(--border) !important;
        border-radius: 12px !important;
        color: var(--text) !important;
        padding: 0.75rem 1rem !important;
        font-size: 0.95rem !important;
        font-weight: 500 !important;
        transition: all var(--transition-fast) !important;
    }}
    
    .stTextInput > div > div > input:focus {{
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.1) !important;
        outline: none !important;
    }}
    
    .stTextInput > div > div > input::placeholder {{
        color: var(--text-light) !important;
        opacity: 0.8 !important;
        font-style: italic !important;
    }}
    
    .stSelectbox > div > div {{
        background: var(--surface) !important;
        border: 2px solid var(--border) !important;
        border-radius: 12px !important;
    }}
    
    .stButton > button {{
        background: var(--primary-gradient) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        font-weight: 600 !important;
        transition: all var(--transition-normal) !important;
        box-shadow: var(--shadow-sm) !important;
        padding: 0.75rem 1.5rem !important;
        font-size: 0.95rem !important;
    }}
    
    .stButton > button:hover {{
        transform: translateY(-2px) !important;
        box-shadow: var(--shadow-md) !important;
    }}
    
    .stExpander {{
        background: var(--surface) !important;
        border: 1px solid var(--border-light) !important;
        border-radius: 12px !important;
        box-shadow: var(--shadow-sm) !important;
    }}
    
    .stSlider > div > div > div > div {{
        background: var(--primary) !important;
    }}
    
    .stCheckbox > label {{
        font-weight: 500 !important;
        color: var(--text) !important;
    }}
    
    /* Responsive Design */
    @media (max-width: 768px) {{
        .professional-header {{
            padding: 2rem 1rem;
            border-radius: 0 0 20px 20px;
        }}
        
        .header-title {{
            font-size: 2rem;
            flex-direction: column;
            gap: 0.5rem;
        }}
        
        .metrics-grid {{
            grid-template-columns: 1fr;
            gap: 1rem;
        }}
        
        .professional-card {{
            padding: 1.5rem;
            border-radius: 12px;
        }}
    }}
    
    /* Custom Scrollbar */
    ::-webkit-scrollbar {{
        width: 8px;
        height: 8px;
    }}
    
    ::-webkit-scrollbar-track {{
        background: var(--surface-secondary);
        border-radius: 4px;
    }}
    
    ::-webkit-scrollbar-thumb {{
        background: var(--primary);
        border-radius: 4px;
    }}
    
    ::-webkit-scrollbar-thumb:hover {{
        background: var(--primary-dark);
    }}
    </style>
    """, unsafe_allow_html=True)

def render_professional_header():
    """Render the professional enterprise-grade header"""
    st.markdown(f"""
    <div class="professional-header fade-in">
        <div class="header-content">
            <h1 class="header-title">
                <span>{ICONS['app']}</span>
                <span>ReconForge</span>
            </h1>
            <p class="header-subtitle">Enterprise Asset Intelligence & Discovery Platform</p>
            <div class="header-badge">
                <span>{ICONS['security']}</span>
                <span>Professional Security Assessment Tool</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_professional_sidebar():
    """Render the professional sidebar navigation"""
    with st.sidebar:
        st.markdown(f"""
        <div class="sidebar-header">
            <div class="sidebar-logo">{ICONS['forge']}</div>
            <div class="sidebar-title">ReconForge</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Navigation Menu
        st.markdown("### 🎯 Navigation")
        
        # Home Button
        if st.button(f"{ICONS['home']} Command Center", 
                    key="nav_home", 
                    use_container_width=True,
                    type="secondary"):
            st.session_state.current_view = "home"
            st.rerun()
        
        # New Mission Button
        if st.button(f"{ICONS['scan']} New Mission", 
                    key="nav_new_scan", 
                    use_container_width=True,
                    type="primary"):
            st.session_state.current_view = "new_scan"
            st.session_state.recon_result = None
            st.session_state.run_scan = False
            st.session_state.ask_load_or_scan = False
            st.session_state.target_org = ""
            st.session_state.base_domains = set()
            st.rerun()
        
        # Intel Archive Button
        if st.button(f"{ICONS['history']} Intel Archive", 
                    key="nav_history", 
                    use_container_width=True,
                    type="secondary"):
            st.session_state.current_view = "history"
            st.session_state.expand_history = True
            st.rerun()
        
        st.markdown("---")
        
        # Current Mission Status
        if st.session_state.get('recon_result'):
            st.markdown("### 📊 Current Mission")
            result = st.session_state.recon_result
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("ASNs", len(result.asns))
                st.metric("Domains", len(result.domains))
            with col2:
                st.metric("IP Ranges", len(result.ip_ranges))
                st.metric("Cloud Services", len(result.cloud_services))
        
        else:
            st.markdown("### 🎯 Quick Start")
            st.markdown("""
            **Ready to begin reconnaissance?**
            
            1. Click **New Mission**
            2. Enter target organization
            3. Add known domains (optional)
            4. Launch discovery
            """)
        
        st.markdown("---")
        
        # System Information
        st.markdown("### ⚙️ System Status")
        
        # Database status
        try:
            scan_count = len(db_manager.get_scan_history())
            st.success(f"Database: {scan_count} missions stored")
        except:
            st.error("Database: Connection issues")
        
        # Quick stats
        if st.button("📈 System Analytics", use_container_width=True):
            st.toast("Analytics dashboard coming soon!", icon="📊")

def render_enhanced_metrics_dashboard(result: ReconnaissanceResult):
    """Render an enhanced metrics dashboard"""
    
    # Calculate comprehensive metrics
    total_subdomains = sum(len(d.subdomains) for d in result.domains)
    active_subdomains = sum(1 for domain in result.domains 
                           for subdomain in domain.subdomains 
                           if subdomain.status == "active")
    
    # IPv4 vs IPv6 breakdown
    ipv4_ranges = sum(1 for ipr in result.ip_ranges if ipr.version == 4)
    ipv6_ranges = sum(1 for ipr in result.ip_ranges if ipr.version == 6)
    
    # Cloud provider distribution
    cloud_providers = {}
    for service in result.cloud_services:
        provider = service.provider
        cloud_providers[provider] = cloud_providers.get(provider, 0) + 1
    
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['dashboard']}</div>
            <div>
                <h3 class="card-title">Mission Intelligence Overview</h3>
                <p class="card-subtitle">Real-time asset discovery metrics for {result.target_organization}</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Main metrics grid
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['asn']}</div>
            <div class="metric-value">{len(result.asns)}</div>
            <div class="metric-label">Autonomous Systems</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['ip']}</div>
            <div class="metric-value">{len(result.ip_ranges)}</div>
            <div class="metric-label">IP Ranges</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['domain']}</div>
            <div class="metric-value">{len(result.domains)}</div>
            <div class="metric-label">Root Domains</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['cloud']}</div>
            <div class="metric-value">{len(result.cloud_services)}</div>
            <div class="metric-label">Cloud Services</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Secondary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['subdomain']}</div>
            <div class="metric-value">{total_subdomains}</div>
            <div class="metric-label">Total Subdomains</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['success']}</div>
            <div class="metric-value">{active_subdomains}</div>
            <div class="metric-label">Active Subdomains</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        ip_percentage = f"{(ipv4_ranges / max(len(result.ip_ranges), 1)) * 100:.0f}%" if result.ip_ranges else "0%"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">🌐</div>
            <div class="metric-value">{ip_percentage}</div>
            <div class="metric-label">IPv4 Ranges</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        top_provider = max(cloud_providers.items(), key=lambda x: x[1])[0] if cloud_providers else "None"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">{ICONS['cloud']}</div>
            <div class="metric-value">{top_provider}</div>
            <div class="metric-label">Top Cloud Provider</div>
        </div>
        """, unsafe_allow_html=True)

def render_welcome_screen():
    """Render the professional welcome screen with enhanced design."""
    st.markdown(f"""
    <div class="professional-card fade-in-up" style="text-align: center; padding: 4rem 2rem;">
        <div style="font-size: 5rem; margin-bottom: 2rem; background: {COLORS['primary_gradient']}; 
                    -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
                    background-clip: text;">{ICONS['forge']}</div>
        <h2 style="color: {COLORS['text']}; margin-bottom: 1rem; font-size: 2.5rem; font-weight: 700;">
            Welcome to ReconForge
        </h2>
        <p style="font-size: 1.25rem; color: {COLORS['text_muted']}; max-width: 700px; margin: 0 auto 3rem auto; line-height: 1.6;">
            Advanced Enterprise Asset Intelligence & Discovery Platform
        </p>
        
        <div style="background: {COLORS['surface_secondary']}; padding: 3rem 2rem; border-radius: 16px; margin: 2rem 0; border: 1px solid {COLORS['border_light']};">
            <h3 style="color: {COLORS['text']}; margin-bottom: 2rem; font-size: 1.5rem;">🚀 Mission Overview</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 2rem; text-align: left;">
                <div style="padding: 1.5rem; background: {COLORS['surface']}; border-radius: 12px; border: 1px solid {COLORS['border']};">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">{ICONS['target']}</div>
                    <strong style="color: {COLORS['text']};">1. Target Configuration</strong><br>
                    <small style="color: {COLORS['text_muted']};">Define organization parameters and known assets</small>
                </div>
                <div style="padding: 1.5rem; background: {COLORS['surface']}; border-radius: 12px; border: 1px solid {COLORS['border']};">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">{ICONS['intelligence']}</div>
                    <strong style="color: {COLORS['text']};">2. Intelligence Gathering</strong><br>
                    <small style="color: {COLORS['text_muted']};">Automated multi-source reconnaissance</small>
                </div>
                <div style="padding: 1.5rem; background: {COLORS['surface']}; border-radius: 12px; border: 1px solid {COLORS['border']};">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">{ICONS['analytics']}</div>
                    <strong style="color: {COLORS['text']};">3. Analysis & Assessment</strong><br>
                    <small style="color: {COLORS['text_muted']};">Comprehensive security posture evaluation</small>
                </div>
                <div style="padding: 1.5rem; background: {COLORS['surface']}; border-radius: 12px; border: 1px solid {COLORS['border']};">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">{ICONS['reports']}</div>
                    <strong style="color: {COLORS['text']};">4. Intelligence Reporting</strong><br>
                    <small style="color: {COLORS['text_muted']};">Export and share actionable findings</small>
                </div>
            </div>
        </div>
        
        <div style="margin-top: 3rem;">
            <p style="color: {COLORS['text_light']}; font-size: 0.95rem;">
                Click <strong>New Mission</strong> in the sidebar to begin your reconnaissance operation
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_mission_form():
    """Render the professional mission configuration form."""
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['target']}</div>
            <div>
                <h3 class="card-title">Mission Configuration</h3>
                <p class="card-subtitle">Configure reconnaissance parameters for optimal intelligence gathering</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("professional_mission_form", border=False):
        # Enhanced organization input
        st.markdown("### 🎯 Target Specification")
        target_org_input = st.text_input(
            "**Primary Target Organization**", 
            value=st.session_state.target_org,
            placeholder="Enter organization name (e.g., Acme Corporation, Microsoft Corporation)",
            help="Enter the exact legal name of the organization for optimal discovery results"
        )
        
        # Enhanced domains input
        base_domains_input = st.text_input(
            "**Known Domain Assets (Optional)**", 
            value=", ".join(st.session_state.base_domains),
            placeholder="Enter known domains separated by commas (e.g., acme.com, acmecorp.net, example.org)",
            help="Comma-separated list of verified domains to enhance discovery accuracy"
        )
        
        # Advanced mission parameters
        with st.expander("⚙️ Advanced Mission Parameters", expanded=False):
            st.markdown("#### 🔧 Performance Configuration")
            
            col1, col2 = st.columns(2)
            
            with col1:
                workers = st.slider(
                    "Concurrent Threads", 
                    min_value=5, 
                    max_value=50,
                    value=st.session_state.max_workers,
                    help="Higher values improve speed but may trigger rate limits"
                )
                
                include_subdomains = st.checkbox(
                    "Deep Subdomain Analysis", 
                    value=st.session_state.include_subdomains,
                    help="Comprehensive subdomain discovery and validation"
                )
            
            with col2:
                st.markdown("**Mission Scope:**")
                st.markdown("""
                - **ASN Discovery**: Network infrastructure mapping
                - **IP Range Analysis**: Address space enumeration  
                - **Domain Intelligence**: DNS footprint analysis
                - **Cloud Detection**: Multi-provider service identification
                """)
        
        # Professional submit button
        submitted = st.form_submit_button(
            f'{ICONS["scan"]} Launch Reconnaissance Mission', 
            type="primary", 
            use_container_width=True,
            help="Initialize comprehensive asset discovery operation"
        )
        
        return submitted, target_org_input, base_domains_input, workers, include_subdomains

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

def display_enhanced_dataframe(df: pd.DataFrame, title: str, icon: str = "📊", page_size: int = DEFAULT_PAGINATION_SIZE):
    """Display DataFrame with professional styling and enhanced features."""
    if df.empty:
        render_professional_card(title, f"<p style='color: {COLORS['text_muted']}; text-align: center; padding: 2rem;'>No data available</p>", icon)
        return
    
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{icon}</div>
            <div>
                <h3 class="card-title">{title}</h3>
                <p class="card-subtitle">{len(df)} total records found</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Add search functionality with enhanced UI
    col1, col2 = st.columns([3, 1])
    with col1:
        search_term = st.text_input(
            f"🔍 Search {title.lower()}", 
            key=f"search_{title.lower().replace(' ', '_')}",
            placeholder=f"Search across all {title.lower()} data..."
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)  # Spacer
        export_all = st.button("📤 Export All", key=f"export_all_{title.lower().replace(' ', '_')}")
    
    # Filter dataframe based on search
    filtered_df = df
    if search_term:
        # Search across all string columns
        mask = df.astype(str).apply(lambda x: x.str.contains(search_term, case=False, na=False)).any(axis=1)
        filtered_df = df[mask]
        
        if len(filtered_df) < len(df):
            st.markdown(f"""
            <div class="status-badge status-info">
                📊 Showing {len(filtered_df)} of {len(df)} records matching '{search_term}'
            </div>
            """, unsafe_allow_html=True)
    
    # Enhanced pagination
    total_rows = len(filtered_df)
    if total_rows > page_size:
        total_pages = (total_rows - 1) // page_size + 1
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if st.button("⏮️ First", key=f"first_{title.lower().replace(' ', '_')}"):
                st.session_state[f"page_{title.lower().replace(' ', '_')}"] = 1
        with col2:
            page = st.selectbox(
                f"Page", 
                range(1, total_pages + 1), 
                key=f"page_{title.lower().replace(' ', '_')}",
                format_func=lambda x: f"Page {x} of {total_pages}"
            )
        with col3:
            if st.button("⏭️ Last", key=f"last_{title.lower().replace(' ', '_')}"):
                st.session_state[f"page_{title.lower().replace(' ', '_')}"] = total_pages
        
        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_rows)
        displayed_df = filtered_df.iloc[start_idx:end_idx]
        
        st.markdown(f"""
        <div class="status-badge status-info">
            📄 Showing rows {start_idx + 1}-{end_idx} of {total_rows}
        </div>
        """, unsafe_allow_html=True)
    else:
        displayed_df = filtered_df
    
    # Display the dataframe with professional styling
    st.dataframe(
        displayed_df, 
        use_container_width=True, 
        hide_index=True,
        height=min(400, len(displayed_df) * 35 + 100)
    )
    
    # Export functionality
    if export_all or search_term:
        csv = (filtered_df if search_term else df).to_csv(index=False)
        st.download_button(
            label=f"📥 Download {title} CSV",
            data=csv,
            file_name=f"{title.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key=f"download_{title.lower().replace(' ', '_')}",
            use_container_width=True
        )

def display_empty_state(message: str, icon: str = "🔍"):
    """Display professional empty state."""
    st.markdown(f"""
    <div class="professional-card fade-in-up" style="text-align: center; padding: 3rem;">
        <div style="font-size: 4rem; margin-bottom: 1.5rem; opacity: 0.3;">{icon}</div>
        <h3 style="color: {COLORS['text_muted']}; margin-bottom: 1rem;">No Data Available</h3>
        <p style="color: {COLORS['text_light']}; font-size: 1.1rem;">{message}</p>
        <div style="margin-top: 2rem;">
            <p style="color: {COLORS['text_muted']}; font-size: 0.9rem;">
                Start a new reconnaissance mission to populate this section
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def display_asn_details(asns: Set[ASN]):
    """Display ASN details with enhanced professional styling."""
    if not asns:
        display_empty_state("No autonomous systems discovered in this mission", ICONS["asn"])
        return
    
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['asn']}</div>
            <div>
                <h3 class="card-title">Autonomous Systems Network</h3>
                <p class="card-subtitle">Infrastructure ownership and routing analysis</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced statistics
    countries = {asn.country for asn in asns if asn.country}
    providers = {asn.name for asn in asns if asn.name}
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total ASNs", len(asns), help="Autonomous System Numbers discovered")
    with col2:
        st.metric("Countries", len(countries), help="Geographic distribution")
    with col3:
        st.metric("Providers", len(providers), help="Unique network providers")
    with col4:
        largest_asn = max(asns, key=lambda x: x.number)
        st.metric("Largest ASN", f"AS{largest_asn.number}", help="Highest ASN number found")
    
    # Display enhanced dataframe
    df = get_asn_df(asns)
    display_enhanced_dataframe(df, "ASN Intelligence Report", ICONS["asn"])

def display_ip_range_details(ip_ranges: Set[IPRange]):
    """Display IP range details with enhanced professional visualization."""
    if not ip_ranges:
        display_empty_state("No IP address ranges discovered in this mission", ICONS["ip"])
        return
    
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['ip']}</div>
            <div>
                <h3 class="card-title">IP Address Infrastructure</h3>
                <p class="card-subtitle">Network blocks and address space analysis</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced analytics
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
    
    # Enhanced dataframe display
    df = get_ip_range_df(ip_ranges)
    display_enhanced_dataframe(df, "IP Range Intelligence Report", ICONS["ip"])

def display_domain_details(domains: Set[Domain]):
    """Display domain details with enhanced professional subdomain analysis."""
    if not domains:
        display_empty_state("No domains discovered in this mission", ICONS["domain"])
        return
    
    total_subdomains = sum(len(d.subdomains) for d in domains)
    active_subdomains = sum(len([s for s in d.subdomains if s.status == "Active"]) for d in domains)
    
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['domain']}</div>
            <div>
                <h3 class="card-title">Domain Infrastructure Analysis</h3>
                <p class="card-subtitle">DNS footprint and subdomain attack surface</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced domain metrics
    registrars = {d.registrar for d in domains if d.registrar}
    
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
    
    # Enhanced tabs for different views
    tab1, tab2 = st.tabs([f"{ICONS['domain']} Root Domains", f"{ICONS['subdomain']} Subdomain Intel"])
    
    with tab1:
        df = get_domain_df(domains)
        display_enhanced_dataframe(df, "Root Domain Intelligence Report", ICONS["domain"])
    
    with tab2:
        if total_subdomains > 0:
            df = get_subdomain_df(domains)
            display_enhanced_dataframe(df, "Subdomain Intelligence Report", ICONS["subdomain"])
        else:
            display_empty_state("No subdomains discovered", ICONS["subdomain"])

def display_cloud_services(services: Set[CloudService]):
    """Display cloud services with enhanced provider breakdown and analysis."""
    if not services:
        display_empty_state("No cloud services detected in this mission", ICONS["cloud"])
        return
    
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['cloud']}</div>
            <div>
                <h3 class="card-title">Cloud Infrastructure Assessment</h3>
                <p class="card-subtitle">Multi-cloud presence and service distribution</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced provider analytics
    provider_counts = {}
    region_counts = {}
    for service in services:
        provider_counts[service.provider] = provider_counts.get(service.provider, 0) + 1
        if service.region:
            region_counts[service.region] = region_counts.get(service.region, 0) + 1
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Services", len(services))
    with col2:
        st.metric("Cloud Providers", len(provider_counts))
    with col3:
        st.metric("Regions", len(region_counts))
    with col4:
        top_provider = max(provider_counts.items(), key=lambda x: x[1])[0] if provider_counts else "None"
        st.metric("Primary Provider", top_provider)
    
    # Provider distribution visualization
    if len(provider_counts) > 1:
        st.markdown("### 🏢 Provider Distribution")
        
        cols = st.columns(min(len(provider_counts), 4))
        for i, (provider, count) in enumerate(sorted(provider_counts.items(), key=lambda x: x[1], reverse=True)):
            with cols[i % 4]:
                percentage = (count / len(services)) * 100
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-icon">☁️</div>
                    <div class="metric-value">{count}</div>
                    <div class="metric-label">{provider} ({percentage:.1f}%)</div>
                </div>
                """, unsafe_allow_html=True)
    
    # Enhanced dataframe display
    df = get_cloud_service_df(services)
    display_enhanced_dataframe(df, "Cloud Service Intelligence Report", ICONS["cloud"])

def display_comprehensive_summary(result: ReconnaissanceResult):
    """Display a comprehensive executive summary with professional analytics."""
    if not result:
        display_empty_state("No reconnaissance data available", ICONS["summary"])
        return
    
    # Calculate advanced metrics
    total_asns = len(result.asns)
    total_ip_ranges = len(result.ip_ranges)
    total_domains = len(result.domains)
    total_subdomains = sum(len(d.subdomains) for d in result.domains)
    total_cloud_services = len(result.cloud_services)
    active_subdomains = sum(len([s for s in d.subdomains if s.status == "Active"]) for d in result.domains)
    
    # Enhanced header
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['summary']}</div>
            <div>
                <h3 class="card-title">Executive Intelligence Report</h3>
                <p class="card-subtitle">Comprehensive digital asset discovery for {result.target_organization}</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Render enhanced metrics dashboard
    render_enhanced_metrics_dashboard(result)
    
    # Advanced analysis section
    st.markdown("### 🔍 Strategic Assessment")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Security posture analysis
        st.markdown(f"""
        <div class="professional-card">
            <div class="card-header">
                <div class="card-icon">{ICONS['security']}</div>
                <div>
                    <h4 class="card-title">Security Posture</h4>
                    <p class="card-subtitle">Attack surface assessment</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Attack surface analysis with professional badges
        if total_subdomains > 100:
            st.markdown(f"""
            <div class="status-badge status-warning">
                ⚠️ Extensive Attack Surface: {total_subdomains} subdomains
            </div>
            """, unsafe_allow_html=True)
        elif total_subdomains > 50:
            st.markdown(f"""
            <div class="status-badge status-info">
                ℹ️ Moderate Attack Surface: {total_subdomains} subdomains
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="status-badge status-success">
                ✅ Controlled Attack Surface: {total_subdomains} subdomains
            </div>
            """, unsafe_allow_html=True)
        
        # Cloud exposure analysis
        if total_cloud_services > 10:
            st.markdown(f"""
            <div class="status-badge status-info">
                ☁️ Significant Cloud Presence: {total_cloud_services} services
            </div>
            """, unsafe_allow_html=True)
        elif total_cloud_services > 0:
            st.markdown(f"""
            <div class="status-badge status-success">
                ☁️ Limited Cloud Exposure: {total_cloud_services} services
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        # Infrastructure overview
        st.markdown(f"""
        <div class="professional-card">
            <div class="card-header">
                <div class="card-icon">{ICONS['analytics']}</div>
                <div>
                    <h4 class="card-title">Infrastructure Overview</h4>
                    <p class="card-subtitle">Network distribution analysis</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Geographic diversity
        countries = {asn.country for asn in result.asns if asn.country}
        if len(countries) > 5:
            st.markdown(f"""
            <div class="status-badge status-info">
                🌍 Global Infrastructure: {len(countries)} countries
            </div>
            """, unsafe_allow_html=True)
        elif len(countries) > 1:
            st.markdown(f"""
            <div class="status-badge status-success">
                🌍 Multi-Region Setup: {len(countries)} countries
            </div>
            """, unsafe_allow_html=True)
        
        # Network diversity
        if total_asns > 20:
            st.markdown(f"""
            <div class="status-badge status-warning">
                🌐 Highly Distributed: {total_asns} ASNs
            </div>
            """, unsafe_allow_html=True)
        elif total_asns > 5:
            st.markdown(f"""
            <div class="status-badge status-info">
                🌐 Well Distributed: {total_asns} ASNs
            </div>
            """, unsafe_allow_html=True)
    
    # Warnings and recommendations
    if result.warnings:
        st.markdown("### ⚠️ Mission Alerts")
        
        st.markdown(f"""
        <div class="professional-card">
            <div class="card-header">
                <div class="card-icon">⚠️</div>
                <div>
                    <h4 class="card-title">Analysis Warnings</h4>
                    <p class="card-subtitle">{len(result.warnings)} items require attention</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        for i, warning in enumerate(result.warnings[:5]):
            st.markdown(f"""
            <div style="padding: 1rem; margin: 0.5rem 0; border-left: 4px solid {COLORS['warning']}; 
                        background: {COLORS['warning_bg']}; border-radius: 8px;">
                <strong>⚠️ Warning {i+1}:</strong> {warning}
            </div>
            """, unsafe_allow_html=True)
        
        if len(result.warnings) > 5:
            st.markdown(f"<p><em>... and {len(result.warnings) - 5} additional warnings</em></p>", unsafe_allow_html=True)

def display_process_logs(log_stream: io.StringIO):
    """Display process logs with professional styling and advanced filtering."""
    st.markdown(f"""
    <div class="professional-card fade-in-up">
        <div class="card-header">
            <div class="card-icon">{ICONS['logs']}</div>
            <div>
                <h3 class="card-title">Mission Process Logs</h3>
                <p class="card-subtitle">Real-time reconnaissance activity monitoring</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    log_content = log_stream.getvalue()
    
    if not log_content.strip():
        display_empty_state("No process logs available yet", "📝")
        return
    
    # Enhanced filter and search options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_options = ["All Logs", "Info Only", "Warnings & Errors", "Debug Only"]
        selected_filter = st.selectbox("🔍 Filter Level:", filter_options)
    
    with col2:
        search_term = st.text_input("🔍 Search logs", placeholder="Enter search term...")
    
    with col3:
        st.markdown("<br>", unsafe_allow_html=True)  # Spacer
        export_logs = st.button("📥 Export Logs", use_container_width=True)
    
    # Process and filter logs
    filtered_logs = []
    for line in log_content.split('\n'):
        if search_term and search_term.lower() not in line.lower():
            continue
            
        if selected_filter == "All Logs":
            filtered_logs.append(line)
        elif selected_filter == "Info Only" and "INFO" in line:
            filtered_logs.append(line)
        elif selected_filter == "Warnings & Errors" and ("WARNING" in line or "ERROR" in line):
            filtered_logs.append(line)
        elif selected_filter == "Debug Only" and "DEBUG" in line:
            filtered_logs.append(line)
    
    filtered_content = '\n'.join(filtered_logs)
    
    # Enhanced log display
    col_logs, col_stats = st.columns([3, 1])
    
    with col_logs:
        st.text_area(
            "Process Output", 
            value=filtered_content,
            height=500, 
            key="professional_log_area",
            help="Live process logs with enhanced filtering capabilities"
        )
    
    with col_stats:
        # Enhanced log statistics
        st.markdown("**📊 Log Analytics:**")
        log_stats = {
            "Total Lines": log_content.count('\n') + (1 if log_content else 0),
            "INFO": sum(1 for line in log_content.split('\n') if " INFO " in line),
            "WARNING": sum(1 for line in log_content.split('\n') if " WARNING " in line),
            "ERROR": sum(1 for line in log_content.split('\n') if " ERROR " in line),
            "DEBUG": sum(1 for line in log_content.split('\n') if " DEBUG " in line)
        }
        
        for level, count in log_stats.items():
            if level in ["WARNING", "ERROR"] and count > 0:
                badge_type = "warning" if level == "WARNING" else "error"
                st.markdown(f"""
                <div class="status-badge status-{badge_type}">
                    {level}: {count}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.metric(level, count)
        
        # Export functionality
        if export_logs:
            st.download_button(
                "📥 Download Full Logs",
                data=log_content, 
                file_name=f"mission_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                key="download_professional_logs",
                use_container_width=True
            )

# --- Main App ---
def main():
    # Initialize the database first
    db_manager.init_db()
    
    # Apply professional CSS styling
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
    if 'cancel_scan' not in st.session_state:
        st.session_state.cancel_scan = False

    # Render professional header
    render_professional_header()
    
    # Render professional sidebar
    render_professional_sidebar()

    # --- Main Content Based on Current View ---
    if st.session_state.current_view == "home":
        # Command Center View
        render_welcome_screen()
        
        # Show recent activity overview if available
        recent_scans = db_manager.get_scan_history(limit=3)
        if recent_scans:
            st.markdown("### 📚 Recent Intelligence Operations")
            
            cols = st.columns(min(len(recent_scans), 3))
            for i, scan in enumerate(recent_scans):
                with cols[i]:
                    scan_date = scan['scan_timestamp'].strftime("%d %b %Y")
                    scan_time = scan['scan_timestamp'].strftime("%H:%M")
                    
                    st.markdown(f"""
                    <div class="professional-card" style="padding: 1.5rem; cursor: pointer;">
                        <div style="font-weight: 600; color: {COLORS['text']}; margin-bottom: 0.5rem;">
                            {scan['target_organization']}
                        </div>
                        <div style="font-size: 0.9rem; color: {COLORS['text_muted']}; margin-bottom: 1rem;">
                            {scan_date} at {scan_time}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if st.button(f"📂 Load Mission", key=f"quick_load_{scan['scan_id']}", use_container_width=True):
                        st.session_state.load_scan_id = scan['scan_id']
                        st.session_state.run_scan = False
                        st.session_state.ask_load_or_scan = False
                        st.session_state.recon_result = None
                        st.rerun()
    
    elif st.session_state.current_view == "new_scan":
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
        <div class="professional-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['history']}</div>
                <div>
                    <h3 class="card-title">Intelligence Archive</h3>
                    <p class="card-subtitle">Historical reconnaissance missions and analysis</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        recent_scans = db_manager.get_scan_history()
        
        if recent_scans:
            # Enhanced search and filtering
            col1, col2 = st.columns([2, 1])
            with col1:
                search_term = st.text_input(
                    "🔍 Search intelligence archive",
                    placeholder="Filter by organization name...",
                    key="archive_search"
                )
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                sort_order = st.selectbox("Sort by", ["Most Recent", "Oldest First", "Organization A-Z"])
            
            # Filter and sort scans
            filtered_scans = recent_scans
            if search_term:
                filtered_scans = [
                    scan for scan in recent_scans 
                    if search_term.lower() in scan['target_organization'].lower()
                ]
            
            if sort_order == "Oldest First":
                filtered_scans = sorted(filtered_scans, key=lambda x: x['scan_timestamp'])
            elif sort_order == "Organization A-Z":
                filtered_scans = sorted(filtered_scans, key=lambda x: x['target_organization'].lower())
            
            if filtered_scans:
                st.markdown(f"""
                <div class="status-badge status-info">
                    📊 Showing {len(filtered_scans)} of {len(recent_scans)} missions
                </div>
                """, unsafe_allow_html=True)
                
                # Enhanced mission cards
                cols_per_row = 2
                scan_rows = [filtered_scans[i:i + cols_per_row] for i in range(0, len(filtered_scans), cols_per_row)]
                
                for row in scan_rows:
                    cols = st.columns(cols_per_row)
                    for idx, scan in enumerate(row):
                        with cols[idx]:
                            # Enhanced mission card design
                            scan_date = scan['scan_timestamp'].strftime("%d %b %Y")
                            scan_time = scan['scan_timestamp'].strftime("%H:%M")
                            days_ago = (datetime.now() - scan['scan_timestamp']).days
                            time_ago = f"{days_ago} days ago" if days_ago > 0 else "Today"
                            
                            # Create gradient color based on org name
                            target_name = scan['target_organization']
                            first_letter = target_name[0].lower() if target_name else 'a'
                            hue = (ord(first_letter) - ord('a')) * 25 % 360 if first_letter.isalpha() else 200
                            
                            st.markdown(f"""
                            <div class="professional-card" style="min-height: 200px;">
                                <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                                    <div style="width: 48px; height: 48px; border-radius: 12px; 
                                               background: linear-gradient(135deg, hsl({hue}, 70%, 60%), hsl({hue+40}, 70%, 50%)); 
                                               display: flex; align-items: center; justify-content: center; 
                                               color: white; font-weight: bold; margin-right: 1rem; font-size: 1.2rem;">
                                        {target_name[0].upper()}
                                    </div>
                                    <div style="flex: 1;">
                                        <div style="font-weight: 700; color: {COLORS['text']}; font-size: 1.1rem; margin-bottom: 0.25rem;">
                                            {target_name}
                                        </div>
                                        <div style="font-size: 0.9rem; color: {COLORS['text_muted']};">
                                            {scan_date} at {scan_time}
                                        </div>
                                        <div style="font-size: 0.85rem; color: {COLORS['text_light']};">
                                            {time_ago}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            if st.button(f"{ICONS['load']} Load Mission Intelligence", 
                                       key=f"archive_load_{scan['scan_id']}", 
                                       use_container_width=True,
                                       type="primary"):
                                st.session_state.load_scan_id = scan['scan_id']
                                st.session_state.run_scan = False
                                st.session_state.ask_load_or_scan = False
                                st.session_state.recon_result = None
                                st.rerun()
            else:
                st.markdown(f"""
                <div class="status-badge status-warning">
                    🔍 No missions found matching '{search_term}'
                </div>
                """, unsafe_allow_html=True)
        else:
            display_empty_state("No previous missions found in the intelligence archive", ICONS["history"])
            st.markdown("""
            <div style="text-align: center; padding: 2rem; color: {COLORS['text_muted']};">
                <p>Launch your first reconnaissance mission to build your intelligence archive!</p>
            </div>
            """, unsafe_allow_html=True)

    # --- Handle Load Scan ---
    if st.session_state.load_scan_id:
        with st.spinner("🔄 Loading mission intelligence..."):
            loaded_result = db_manager.load_scan_result(st.session_state.load_scan_id)
            if loaded_result:
                st.session_state.recon_result = loaded_result
                st.success("✅ Mission intelligence loaded successfully!")
                logger.info(f"Loaded scan result for {loaded_result.target_organization}")
            else:
                st.error("❌ Failed to load mission intelligence from database.")
                logger.error(f"Failed to load scan with ID: {st.session_state.load_scan_id}")
        
        st.session_state.load_scan_id = None
        st.rerun()

    # --- Handle Ask Load or Scan Logic ---
    if st.session_state.ask_load_or_scan:
        st.markdown(f"""
        <div class="professional-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['warning']}</div>
                <div>
                    <h3 class="card-title">Mission Conflict Detected</h3>
                    <p class="card-subtitle">Previous intelligence exists for this target</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.warning(f"🔍 **Intelligence Alert**: Recent reconnaissance data exists for '{st.session_state.target_org}'. Choose your next action:")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"{ICONS['load']} Load Existing Intelligence", 
                        type="primary", 
                        use_container_width=True,
                        help="Load the most recent mission data for this target"):
                st.session_state.load_scan_id = st.session_state.existing_scan_id
                st.session_state.ask_load_or_scan = False
                st.rerun()
        
        with col2:
            if st.button(f"{ICONS['scan']} Launch New Mission", 
                        use_container_width=True,
                        help="Execute fresh reconnaissance (may take several minutes)"):
                st.session_state.run_scan = True
                st.session_state.ask_load_or_scan = False
                st.rerun()

    # --- Handle Scan Execution ---
    if st.session_state.run_scan and not st.session_state.scan_running:
        # Enhanced mission initialization
        st.markdown(f"""
        <div class="professional-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['radar']}</div>
                <div>
                    <h3 class="card-title">Mission Initialization</h3>
                    <p class="card-subtitle">Launching reconnaissance operation for {st.session_state.target_org}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.session_state.scan_running = True
        
        # Enhanced progress tracking
        status_container = st.container()
        progress_container = st.container()
        results_preview_container = st.container()
        
        # Mission control panel
        control_col1, control_col2 = st.columns([3, 1])
        with control_col2:
            if st.button("🛑 Cancel Mission", key="cancel_mission_btn", type="secondary"):
                st.session_state.cancel_scan = True
        
        def update_progress(progress: float, message: str):
            with progress_container.container():
                st.markdown(f"""
                <div class="professional-progress">
                    <div class="professional-progress-bar" style="width: {progress}%"></div>
                </div>
                """, unsafe_allow_html=True)
                st.caption(f"⚡ {message}")

        def update_status(icon: str, message: str):
            with status_container.container():
                st.markdown(f"""
                <div class="status-badge status-info">
                    {icon} {message}
                </div>
                """, unsafe_allow_html=True)

        def update_results_preview(result: ReconnaissanceResult):
            with results_preview_container.container():
                st.markdown("### 📡 Live Intelligence Feed")
                render_enhanced_metrics_dashboard(result)

        try:
            # Enhanced orchestrator initialization
            orchestrator = IntelligentDiscoveryOrchestrator()
            
            # Mission parameters
            target_org = st.session_state.target_org
            base_domains = st.session_state.base_domains if st.session_state.base_domains else None
            
            logger.info(f"🚀 Launching enhanced reconnaissance mission for: {target_org}")
            update_status("🚀", f"Initializing mission for {target_org}")
            
            def enhanced_progress_callback(progress: float, message: str):
                update_progress(progress, message)
                if st.session_state.cancel_scan:
                    raise InterruptedError("Mission cancelled by user")

            def enhanced_status_callback(icon: str, message: str):
                update_status(icon, message)

            def enhanced_phase_callback(phase, phase_result):
                phase_name = phase.value.replace('_', ' ').title()
                if phase_result.success:
                    update_status("✅", f"{phase_name} completed successfully")
                else:
                    update_status("⚠️", f"{phase_name} completed with warnings")

            # Execute enhanced reconnaissance
            final_result = orchestrator.run_enhanced_discovery(
                target_organization=target_org,
                base_domains=base_domains,
                progress_callback=enhanced_progress_callback,
                status_callback=enhanced_status_callback,
                phase_callback=enhanced_phase_callback
            )

            if final_result:
                st.session_state.recon_result = final_result
                update_results_preview(final_result)
                
                # Enhanced success notification
                st.markdown(f"""
                <div class="professional-card" style="background: {COLORS['success_bg']}; border-left: 4px solid {COLORS['success']};">
                    <div class="card-header">
                        <div class="card-icon">{ICONS['success']}</div>
                        <div>
                            <h3 class="card-title">Mission Accomplished</h3>
                            <p class="card-subtitle">Intelligence gathering completed successfully</p>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Save to database
                logger.info(f"Saving enhanced reconnaissance results for: '{final_result.target_organization}'")
                save_successful = db_manager.save_scan_result(final_result)
                
                if save_successful:
                    logger.info("Enhanced reconnaissance results saved to database successfully.")
                    st.success("💾 Mission intelligence archived successfully")
                else:
                    logger.error("Database save failed.")
                    st.error("❌ Failed to archive mission intelligence")
            
        except InterruptedError:
            st.warning("🛑 Mission cancelled by operator")
            if hasattr(orchestrator, 'partial_result') and orchestrator.partial_result:
                st.session_state.recon_result = orchestrator.partial_result
                st.info("💾 Partial intelligence preserved")
            else:
                st.session_state.recon_result = None
                
        except Exception as e:
            logger.exception("Unhandled error during enhanced reconnaissance")
            st.error(f"❌ Mission failed: {e}")
            st.session_state.recon_result = None
            
        finally:
            st.session_state.scan_running = False
            st.session_state.run_scan = False
            st.session_state.cancel_scan = False
            
            # Clear streaming containers
            status_container.empty()
            progress_container.empty()
            results_preview_container.empty()
            
            # Enhanced action buttons
            if st.session_state.recon_result:
                col1, col2, col3 = st.columns([1, 1, 1])
                with col1:
                    if st.button("📊 Analyze Intelligence", type="primary", use_container_width=True):
                        st.rerun()
                with col2:
                    if st.button("🔄 New Mission", use_container_width=True):
                        st.session_state.current_view = "new_scan"
                        st.session_state.recon_result = None
                        st.rerun()
                with col3:
                    if st.button("🏠 Command Center", use_container_width=True):
                        st.session_state.current_view = "home"
                        st.rerun()
            else:
                if st.button("🔄 Retry Mission", use_container_width=True):
                    st.rerun()

    # --- Enhanced Results Display ---
    if st.session_state.recon_result and not st.session_state.scan_running:
        result_data = st.session_state.recon_result
        
        # Enhanced mission header
        target_org = result_data.target_organization
        scan_time = datetime.now().strftime(DATE_FORMAT)
        
        st.markdown(f"""
        <div class="professional-card fade-in-up">
            <div class="card-header">
                <div class="card-icon">{ICONS['app']}</div>
                <div>
                    <h3 class="card-title">Mission Intelligence Report</h3>
                    <p class="card-subtitle">Target: {target_org} | Analysis Complete: {scan_time}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Professional tabs with enhanced icons
        tab_configs = {
            "summary": (f"{ICONS['summary']} Executive Summary", display_comprehensive_summary),
            "asns": (f"{ICONS['asn']} Network Infrastructure", display_asn_details),
            "ips": (f"{ICONS['ip']} Address Space", display_ip_range_details),
            "domains": (f"{ICONS['domain']} Domain Intelligence", display_domain_details),
            "cloud": (f"{ICONS['cloud']} Cloud Assessment", display_cloud_services),
            "graph": (f"{ICONS['graph']} Network Visualization", None),
            "logs": (f"{ICONS['logs']} Process Intelligence", display_process_logs)
        }
        
        tab_summary, tab_asns, tab_ips, tab_domains, tab_cloud, tab_graph, tab_logs = st.tabs([
            config[0] for config in tab_configs.values()
        ])

        with tab_summary:
            display_comprehensive_summary(result_data)
            
        with tab_asns:
            display_asn_details(result_data.asns)
            
        with tab_ips:
            display_ip_range_details(result_data.ip_ranges)
            
        with tab_domains:
            display_domain_details(result_data.domains)
            
        with tab_cloud:
            display_cloud_services(result_data.cloud_services)
            
        with tab_graph:
            st.markdown(f"""
            <div class="professional-card fade-in-up">
                <div class="card-header">
                    <div class="card-icon">{ICONS['graph']}</div>
                    <div>
                        <h3 class="card-title">Network Relationship Visualization</h3>
                        <p class="card-subtitle">Interactive asset relationship mapping</p>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            graph_html_path = generate_network_graph(result_data)
            if graph_html_path:
                try:
                    with open(graph_html_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    st.components.v1.html(html_content, height=800, scrolling=True)
                    
                    # Enhanced download functionality
                    with open(graph_html_path, "rb") as fp:
                        st.download_button(
                            label="📥 Export Network Visualization",
                            data=fp,
                            file_name=f"network_graph_{target_org.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html",
                            key="download_professional_graph",
                            use_container_width=True
                        )
                except FileNotFoundError:
                    st.error(f"Visualization file not found: {graph_html_path}")
                except Exception as e:
                    logger.error(f"Error displaying graph: {e}")
                    st.error("Could not display network visualization.")
            else:
                display_empty_state("Network visualization generation failed", ICONS["graph"])
                
        with tab_logs:
            display_process_logs(st.session_state.log_stream)

    # Enhanced footer with professional branding
    st.markdown(f"""
    <div style="margin-top: 4rem; padding: 2rem; background: {COLORS['surface_secondary']}; 
                border-radius: 16px; text-align: center; border: 1px solid {COLORS['border_light']};">
        <div style="display: flex; align-items: center; justify-content: center; gap: 1rem; margin-bottom: 1rem;">
            <div style="font-size: 1.5rem;">{ICONS['app']}</div>
            <div style="font-size: 1.2rem; font-weight: 700; color: {COLORS['text']};">ReconForge</div>
        </div>
        <p style="margin: 0; font-size: 0.95rem; color: {COLORS['text_muted']};">
            Enterprise Asset Intelligence & Discovery Platform
        </p>
        <p style="margin: 0.5rem 0 0 0; font-size: 0.85rem; color: {COLORS['text_light']};">
            Developed with ❤️ for cybersecurity professionals
        </p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main() 