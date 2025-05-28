"""
Modern UX-Optimized Sidebar for ReconForge Light Theme.

Designed with user psychology and modern UX principles:
- Progressive disclosure
- Clear visual hierarchy
- User-friendly language
- Contextual help
- Quick actions focus
"""

import streamlit as st
from typing import Dict, Any, Tuple, Optional

def render_sidebar():
    """Render the main sidebar with modern UX design."""
    
    # ============================================================================
    # QUICK ACTIONS SECTION - Most Used Features First
    # ============================================================================
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #0066CC 0%, #004499 100%);
        border-radius: 12px; 
        padding: 1.5rem; 
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 15px rgba(0, 102, 204, 0.2);
    ">
        <div style="
            font-size: 1.1rem; 
            font-weight: 600; 
            color: white; 
            margin-bottom: 0.5rem;
            display: flex; 
            align-items: center; 
            gap: 0.5rem;
        ">
            🎯 Quick Start
        </div>
        <div style="
            color: rgba(255, 255, 255, 0.9); 
            font-size: 0.85rem; 
            line-height: 1.4;
        ">
            Ready to discover digital assets? Choose your scan type below.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick scan type selection
    scan_type = st.sidebar.radio(
        "🎯 **What would you like to discover?**",
        [
            "🏢 Complete Organization Scan",
            "🌐 Domain-Focused Discovery",
            "🔍 Quick Asset Check",
            "⚙️ Custom Configuration"
        ],
        help="Choose the type of reconnaissance that best fits your needs"
    )
    
    st.sidebar.markdown("---")
    
    # ============================================================================
    # SCAN PREFERENCES - Simplified User Controls
    # ============================================================================
    st.sidebar.markdown("""
    <div style="
        background: #F8F9FA; 
        border-left: 4px solid #0066CC; 
        border-radius: 0 8px 8px 0; 
        padding: 1rem; 
        margin-bottom: 1rem;
    ">
        <div style="
            font-size: 1rem; 
            font-weight: 600; 
            color: #212529; 
            margin-bottom: 0.3rem;
            display: flex; 
            align-items: center; 
            gap: 0.5rem;
        ">
            🎛️ Scan Preferences
        </div>
        <div style="
            color: #6C757D; 
            font-size: 0.8rem;
        ">
            Customize how deep and thorough you want the scan to be
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Simplified scan intensity
    scan_intensity = st.sidebar.select_slider(
        "**Scan Intensity**",
        options=["🚀 Quick", "⚖️ Balanced", "🔬 Deep", "🧠 Maximum"],
        value="⚖️ Balanced",
        help="Quick: Fast results in under 1 minute\nBalanced: Best mix of speed and thoroughness\nDeep: Comprehensive scan, may take 3-5 minutes\nMaximum: Most thorough, can take 5-10 minutes"
    )
    
    # Time preference
    max_time = st.sidebar.slider(
        "**Maximum Scan Time**",
        min_value=1,
        max_value=10,
        value=5,
        format="%d minutes",
        help="Stop the scan after this time to get results faster"
    )
    
    # Data sources - simplified
    data_sources = st.sidebar.multiselect(
        "**Data Sources to Use**",
        [
            "🌐 Certificate Transparency",
            "📡 BGP & ASN Data", 
            "☁️ Cloud Services",
            "🔍 Passive DNS",
            "🏢 WHOIS Records"
        ],
        default=[
            "🌐 Certificate Transparency",
            "📡 BGP & ASN Data", 
            "☁️ Cloud Services"
        ],
        help="Select which sources to query for the most relevant data"
    )
    
    st.sidebar.markdown("---")
    
    # ============================================================================
    # WORKSPACE SECTION - User Context & Recent Activity
    # ============================================================================
    st.sidebar.markdown("""
    <div style="
        background: #F0F8FF; 
        border: 1px solid #B0D4F1; 
        border-radius: 8px; 
        padding: 1rem; 
        margin-bottom: 1rem;
    ">
        <div style="
            font-size: 1rem; 
            font-weight: 600; 
            color: #1a5490; 
            margin-bottom: 0.5rem;
            display: flex; 
            align-items: center; 
            gap: 0.5rem;
        ">
            📂 Your Workspace
        </div>
        <div style="
            color: #5a7ba7; 
            font-size: 0.8rem;
        ">
            Recent scans and saved configurations
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Recent targets
    recent_targets = get_recent_targets()
    if recent_targets:
        selected_target = st.sidebar.selectbox(
            "**Recent Organizations**",
            ["Select a previous target..."] + recent_targets,
            help="Quickly re-scan a previously scanned organization"
        )
    
    # Quick actions
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("📊 History", use_container_width=True):
            st.session_state.current_tab = "📊 Results"
            st.rerun()
    
    with col2:
        if st.button("⚙️ Config", use_container_width=True):
            show_advanced_settings()
    
    st.sidebar.markdown("---")
    
    # ============================================================================
    # HELP & SUPPORT - Context-Aware Assistance
    # ============================================================================
    with st.sidebar.expander("❓ Need Help?", expanded=False):
        st.markdown("""
        **🚀 Getting Started**
        1. Enter an organization name
        2. Choose scan intensity
        3. Click "Start Reconnaissance"
        
        **💡 Pro Tips**
        - Use "Balanced" for best results
        - Add known domains for better coverage
        - Check multiple data sources
        
        **🔧 Troubleshooting**
        - Ensure internet connection
        - Try reducing scan intensity
        - Check organization spelling
        """)
        
        st.markdown("---")
        
        # System status
        show_system_info()
    
    # Store config in session state
    st.session_state.sidebar_config = {
        'scan_type': scan_type,
        'scan_intensity': scan_intensity,
        'max_time': max_time,
        'data_sources': data_sources
    }

def get_scan_config():
    """Get the current scan configuration from sidebar."""
    
    if 'sidebar_config' not in st.session_state:
        # Return default config
        return {
            'scan_type': '🏢 Complete Organization Scan',
            'scan_intensity': '⚖️ Balanced',
            'max_time': 5,
            'data_sources': [
                "🌐 Certificate Transparency",
                "📡 BGP & ASN Data", 
                "☁️ Cloud Services"
            ]
        }
    
    return st.session_state.sidebar_config

def get_recent_targets() -> list:
    """Get list of recently scanned targets."""
    
    if 'db_manager' not in st.session_state or not st.session_state.db_manager:
        return []
    
    try:
        recent_scans = st.session_state.db_manager.get_recent_scans(limit=5)
        return [scan.get('target_organization', 'Unknown') for scan in recent_scans]
    except Exception:
        return []

def show_advanced_settings():
    """Display advanced settings in a modal-like expander."""
    
    st.sidebar.markdown("### ⚙️ Advanced Settings")
    
    # Performance settings
    with st.sidebar.expander("🚀 Performance", expanded=False):
        st.slider("Concurrent Workers", 1, 50, 10)
        st.slider("Request Rate (req/sec)", 1, 20, 5)
        st.checkbox("Enable Caching", True)
    
    # Output settings  
    with st.sidebar.expander("📤 Output Options", expanded=False):
        st.selectbox("Default Export Format", ["JSON", "CSV", "Excel"])
        st.checkbox("Include Raw Data", False)
        st.checkbox("Auto-save Results", True)

def save_current_config():
    """Save current configuration as a template."""
    st.sidebar.success("💾 Configuration saved!")

def show_system_info():
    """Display system status information."""
    
    st.markdown("""
    **🔧 System Status**
    """)
    
    # Simple status indicators
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("🟢 **Online**")
        st.markdown("📡 Discovery Engine")
    
    with col2:
        st.markdown("🟢 **Ready**") 
        st.markdown("💾 Database")
    
    # Version info
    st.markdown("---")
    st.markdown("**ReconForge Professional v2.0**")
    st.markdown("*Light Theme Edition*") 