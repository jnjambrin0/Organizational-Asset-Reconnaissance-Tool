"""
Main interface components for ReconForge Streamlit application.
"""

import streamlit as st
from typing import Tuple, Optional, Set

def render_main_interface() -> Tuple[str, Optional[Set[str]]]:
    """
    Render the main interface for target input and scan configuration.
    
    Returns:
        Tuple of (target_organization, base_domains)
    """
    
    st.markdown("## 🎯 Target Configuration")
    
    # Organization input
    target_org = st.text_input(
        "**Target Organization**",
        placeholder="e.g., Telefonica, Microsoft, Amazon",
        help="Enter the name of the organization you want to reconnaissance"
    )
    
    # Base domains input
    st.markdown("### 🌐 Known Domains (Optional)")
    
    domains_input = st.text_area(
        "Base Domains",
        placeholder="telefonica.com\nmovistar.es\nexample.org",
        help="Enter known domains (one per line) to accelerate discovery",
        height=100
    )
    
    # Parse base domains
    base_domains = None
    if domains_input.strip():
        domains_list = [domain.strip() for domain in domains_input.split('\n') if domain.strip()]
        base_domains = set(domains_list) if domains_list else None
        
        if base_domains:
            st.info(f"✅ {len(base_domains)} base domains configured")
    
    # Advanced options
    with st.expander("🔧 Advanced Target Options"):
        st.markdown("#### Intelligence Seeding")
        
        col1, col2 = st.columns(2)
        
        with col1:
            enable_asn_boost = st.checkbox(
                "ASN Intelligence Boost",
                value=True,
                help="Use ASN data to accelerate organization discovery"
            )
            
            enable_domain_patterns = st.checkbox(
                "Domain Pattern Learning",
                value=True,
                help="Learn organization patterns from domain structures"
            )
        
        with col2:
            enable_cloud_detection = st.checkbox(
                "Cloud Service Detection",
                value=True,
                help="Identify cloud infrastructure and services"
            )
            
            enable_subdomain_expansion = st.checkbox(
                "Subdomain Expansion",
                value=True,
                help="Perform extensive subdomain enumeration"
            )
    
    # Scan preview
    if target_org:
        st.markdown("### 📋 Scan Preview")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Target",
                target_org,
                help="Primary organization target"
            )
        
        with col2:
            domain_count = len(base_domains) if base_domains else 0
            st.metric(
                "Base Domains",
                domain_count,
                help="Known domains to seed discovery"
            )
        
        with col3:
            estimated_duration = "1-3 min"
            if domain_count > 5:
                estimated_duration = "2-5 min"
            elif domain_count > 10:
                estimated_duration = "3-7 min"
                
            st.metric(
                "Est. Duration",
                estimated_duration,
                help="Estimated scan completion time"
            )
        
        # Show discovery strategy
        st.markdown("#### 🧠 Discovery Strategy")
        
        strategy_info = f"""
        **Intelligent Discovery Plan:**
        - 🔍 **Initial Search**: Use '{target_org}' as primary search term
        """
        
        if base_domains:
            strategy_info += f"\n- 🌐 **Domain Seeding**: Bootstrap with {len(base_domains)} known domains"
        
        strategy_info += """
        - 🧠 **Adaptive Learning**: Extract organization patterns from discovered data
        - 🔄 **Iterative Expansion**: Progressively expand search based on learned intelligence
        - 📊 **Convergence Detection**: Automatically stop when diminishing returns detected
        """
        
        st.info(strategy_info)
    
    return target_org, base_domains

def render_scan_status(scan_running: bool, progress: float, status: str):
    """
    Render scan status and progress information.
    
    Args:
        scan_running: Whether scan is currently running
        progress: Progress percentage (0-100)
        status: Current status message
    """
    
    if scan_running:
        st.markdown("### 🔄 Scan in Progress")
        
        # Progress bar
        progress_bar = st.progress(progress / 100.0)
        
        # Status message
        st.info(f"**Status:** {status}")
        
        # Cancel button
        if st.button("🛑 Cancel Scan", type="secondary"):
            st.warning("Scan cancellation requested")
            return True
    
    return False 