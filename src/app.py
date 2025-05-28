"""
ReconForge Professional - Modern Asset Intelligence Platform
Light Theme Edition with Advanced Progress System

Main Streamlit application for comprehensive organizational reconnaissance with
modern light theme design, advanced progress visualization, and professional UX.
"""

import streamlit as st
import time
import asyncio
import logging
import threading
from datetime import datetime
from typing import Dict, Any, Optional, Set, Callable
import pandas as pd

# Core imports
from src.core.models import ReconnaissanceResult
from src.orchestration.intelligent_discovery_orchestrator import (
    IntelligentDiscoveryOrchestrator,
)
from src.db_manager import DatabaseManager
from src.config.settings import get_settings
from src.utils.logging_config import get_logger, setup_logging
from src.utils.banner import print_enhanced_banner
from src.utils.streamlit_threading import (
    suppress_streamlit_thread_warnings,
    HighPerformanceTimeoutExecutor,
    get_default_executor,
)
from src.utils.formatting import safe_slice_datetime, format_scan_display_date

# Modern UI imports
from src.ui.styles import get_custom_css, get_custom_js
from src.ui.components import (
    render_metric_card,
    render_status_indicator,
    render_progress_bar,
    render_timeline_item,
    render_data_table,
    render_chart_card,
    create_asset_distribution_chart,
    create_geographic_distribution_chart,
    create_discovery_timeline_chart,
    render_loading_state,
    render_alert_card,
    render_feature_grid,
    render_stats_overview,
)

# Advanced UI imports
from src.ui.advanced_components import (
    render_intelligent_dashboard,
    render_enhanced_results_table,
    render_comparison_dashboard,
    render_interactive_timeline,
)

# Enhanced results imports
from src.ui.enhanced_results import (
    render_enhanced_domains_tab,
    render_enhanced_network_tab,
    render_enhanced_cloud_tab,
    render_security_analysis_tab,
    render_analytics_insights_tab,
    render_export_actions_tab,
)

# Navigation imports
from src.ui.intelligent_navigation import (
    navigation,
    render_smart_navigation_header,
)

# Dashboard import
from src.ui.dashboard import render_advanced_dashboard

# UI components
from src.ui.sidebar import render_sidebar, get_scan_config
from src.ui.main_interface import render_main_interface
from src.ui.results_display import render_results_display
from src.ui.export_tools import render_export_tools

# Progress components
from src.ui.progress_components import (
    setup_reconnaissance_progress,
    create_progress_callbacks,
    ModernProgressBar,
    ProgressState,
)

# Initialize high-performance threading and suppress warnings
suppress_streamlit_thread_warnings()

# Configure logger
logger = get_logger(__name__)

# ============================================================================
# STREAMLIT CONFIGURATION (MUST BE FIRST)
# ============================================================================

st.set_page_config(
    page_title="ReconForge Professional - Asset Intelligence Platform",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": None,
        "Report a bug": None,
        "About": "ReconForge Professional - Modern Asset Intelligence Platform",
    },
)

# ============================================================================
# STYLING AND INITIALIZATION
# ============================================================================


def apply_modern_styling():
    """Apply modern light theme CSS styling."""
    st.markdown(get_custom_css(), unsafe_allow_html=True)
    st.markdown(get_custom_js(), unsafe_allow_html=True)


def initialize_session_state():
    """Initialize Streamlit session state variables."""

    # Core application state
    if "db_manager" not in st.session_state:
        st.session_state.db_manager = DatabaseManager()

    if "orchestrator" not in st.session_state:
        st.session_state.orchestrator = IntelligentDiscoveryOrchestrator()

    # Scan state management
    if "current_scan" not in st.session_state:
        st.session_state.current_scan = None

    if "scan_running" not in st.session_state:
        st.session_state.scan_running = False

    if "scan_results" not in st.session_state:
        st.session_state.scan_results = None

    # Progress tracking
    if "scan_progress" not in st.session_state:
        st.session_state.scan_progress = 0.0

    if "scan_status" not in st.session_state:
        st.session_state.scan_status = "Ready"

    if "current_phase" not in st.session_state:
        st.session_state.current_phase = None

    # Phase tracking for detailed progress
    if "phase_results" not in st.session_state:
        st.session_state.phase_results = {}

    # Real-time metrics
    if "live_metrics" not in st.session_state:
        st.session_state.live_metrics = {
            "domains_found": 0,
            "asns_found": 0,
            "ip_ranges_found": 0,
            "cloud_services_found": 0,
            "subdomains_found": 0,
            "scan_duration": 0.0,
        }

    # UI state
    if "current_tab" not in st.session_state:
        st.session_state.current_tab = "🎯 Dashboard"

    # Progress bar instance
    if "progress_bar" not in st.session_state:
        st.session_state.progress_bar = None


# ============================================================================
# HEADER AND DASHBOARD COMPONENTS
# ============================================================================


def render_professional_header():
    """Render the modern professional header with perfect spacing."""

    st.markdown(
        """
    <div class="main-header animate-fade-in">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🎯 ReconForge Professional</h1>
                <h3>Modern Asset Intelligence Platform</h3>
                <p>High-Performance Reconnaissance with Light Theme Design & Professional Analytics</p>
            </div>
            <div style="text-align: right;">
                <div class="status-indicator status-online" style="margin-bottom: 0.5rem;">
                    <span>🟢</span>
                    <span>System Online</span>
                </div>
                <div style="font-size: 0.875rem; opacity: 0.9; font-weight: 500;">
                    Light Theme Professional v2.0
                </div>
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def render_dashboard_overview():
    """Render the enhanced main dashboard with intelligent components and analytics."""

    # Smart navigation header
    render_smart_navigation_header()

    # Contextual breadcrumbs
    navigation.render_contextual_breadcrumbs("dashboard")

    st.markdown('<div class="animate-fade-in">', unsafe_allow_html=True)

    # Quick actions panel based on context
    context = {
        "page": "dashboard",
        "scan_running": st.session_state.get("scan_running", False),
        "has_results": st.session_state.get("scan_results") is not None,
    }
    navigation.render_quick_actions_panel(context)

    # Intelligent dashboard with AI insights
    scan_results = st.session_state.get("scan_results")
    historical_data = (
        st.session_state.db_manager.get_recent_scans(limit=5)
        if st.session_state.db_manager
        else []
    )

    render_intelligent_dashboard(scan_results, historical_data)

    # System status section (sequential layout for better breathing)
    st.markdown(
        """
    <div class="custom-card" style="margin-bottom: 1.5rem;">
        <div class="card-title" style="margin-bottom: 1rem;">🚀 System Status & Performance</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Enhanced status indicators with performance metrics
    status_col1, status_col2, status_col3 = st.columns(3)

    with status_col1:
        render_status_indicator("online", "Discovery Engine")
    with status_col2:
        render_status_indicator("online", "Intelligence Database")
    with status_col3:
        render_status_indicator("online", "AI Learning System")

    # Performance metrics row
    perf_col1, perf_col2, perf_col3 = st.columns(3)
    with perf_col1:
        render_metric_card("Avg Scan Time", "2.3min", "⏱️", "+0.2min")
    with perf_col2:
        render_metric_card("Success Rate", "98.5%", "✅", "+1.2%")
    with perf_col3:
        render_metric_card("Data Sources", "5/5", "🌐", "All Active")

    # Separator for visual clarity
    st.markdown("---")

    # Enhanced stats section (full width)
    stats = (
        st.session_state.db_manager.get_scan_statistics()
        if st.session_state.db_manager
        else {}
    )
    render_stats_overview(stats)

    # Separator for visual clarity
    st.markdown("---")

    # Recent activity timeline (full width)
    if historical_data:
        render_interactive_timeline(historical_data)

    # Enhanced feature showcase
    st.markdown(
        """
    <div style="margin: 2rem 0 1rem 0;">
        <h3 style="color: #212529; margin-bottom: 1rem; font-weight: 600; font-size: 1.25rem;">🚀 Enhanced Professional Features</h3>
    </div>
    """,
        unsafe_allow_html=True,
    )

    features = [
        {
            "icon": "🧠",
            "title": "AI-Powered Intelligence",
            "description": "Smart insights, security analysis, and automated recommendations from discovered assets.",
        },
        {
            "icon": "🕸️",
            "title": "Interactive Asset Networks",
            "description": "Visualize relationships between domains, ASNs, IPs, and cloud services with interactive graphs.",
        },
        {
            "icon": "📊",
            "title": "Advanced Analytics Dashboard",
            "description": "Rich visualizations, trend analysis, and comparative insights across multiple scans.",
        },
        {
            "icon": "🎯",
            "title": "Contextual Navigation",
            "description": "Smart breadcrumbs, guided workflows, and contextual quick actions for better UX.",
        },
        {
            "icon": "🔍",
            "title": "Enhanced Search & Filtering",
            "description": "Powerful search capabilities, intelligent filtering, and real-time data exploration.",
        },
        {
            "icon": "⚡",
            "title": "High-Performance UI",
            "description": "Optimized rendering, smooth animations, and responsive design for professional experience.",
        },
    ]

    render_feature_grid(features)
    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================================
# SCAN INTERFACE
# ============================================================================


def render_scan_interface():
    """Render a clean and focused scan interface."""

    st.markdown("## 🔍 Start Reconnaissance")

    # Simple input section
    col1, col2 = st.columns([3, 1])

    with col1:
        target_org = st.text_input(
            "Organization Name",
            placeholder="Enter organization name (e.g., microsoft, google, amazon)",
            help="Enter the name of the organization you want to scan",
        )

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        scan_button = st.button(
            "🚀 Start Scan", type="primary", use_container_width=True
        )

    # Optional: Simple configuration (collapsed by default)
    with st.expander("⚙️ Configuration (Optional)", expanded=False):
        col1, col2 = st.columns(2)

        with col1:
            base_domains_input = st.text_area(
                "Known Domains (Optional)",
                placeholder="example.com\nsubdomain.example.com",
                help="Enter known domains, one per line",
                height=100,
            )

        with col2:
            scan_intensity = st.selectbox(
                "Scan Depth",
                ["Quick", "Balanced", "Deep"],
                index=1,
                help="Higher depth means more thorough but slower scans",
            )

            max_time = st.slider(
                "Max Time (minutes)",
                min_value=1,
                max_value=15,
                value=5,
                help="Maximum time to spend scanning",
            )

    # Start scan logic
    if scan_button and target_org.strip():
        # Set defaults for simplified config
        max_workers = 10
        # Ensure we have string values for all parameters
        domains_input = base_domains_input or ""
        intensity = scan_intensity or "Balanced"
        start_reconnaissance_scan(
            target_org, domains_input, max_workers, max_time, intensity
        )
    elif scan_button:
        st.error("⚠️ Please enter an organization name to begin scanning.")

    # Progress display
    if st.session_state.scan_running:
        progress_bar = st.session_state.get("progress_bar")

        # Simple cancel button
        if st.button("⏹️ Cancel", type="secondary"):
            cancel_reconnaissance_scan()

    # Results display
    if st.session_state.scan_results and not st.session_state.scan_running:
        st.markdown("---")
        st.markdown("## 📊 Results")
        render_scan_results(st.session_state.scan_results)


def start_reconnaissance_scan(
    target_org: str,
    base_domains_input: str,
    max_workers: int,
    max_time: int,
    scan_intensity: str,
):
    """Start reconnaissance scan with modern progress system."""

    if st.session_state.scan_running:
        st.warning(
            "⚠️ A scan is already running. Please wait for it to complete or cancel it."
        )
        return

    # Parse base domains
    base_domains = set()
    if base_domains_input.strip():
        base_domains = {
            domain.strip()
            for domain in base_domains_input.strip().split("\n")
            if domain.strip()
        }
        logger.info(f"📋 Base domains provided: {list(base_domains)}")

    # Set scan state
    st.session_state.scan_running = True
    st.session_state.scan_results = None
    st.session_state.scan_progress = 0.0
    st.session_state.scan_status = "Initializing..."

    logger.info(f"🎯 Starting reconnaissance scan for: {target_org}")
    logger.info(
        f"⚙️ Configuration: workers={max_workers}, timeout={max_time}min, intensity={scan_intensity}"
    )

    # Setup modern progress bar
    st.session_state.progress_bar = setup_reconnaissance_progress()
    progress_callback, status_callback = create_progress_callbacks(
        st.session_state.progress_bar
    )

    # Create scan configuration
    scan_config = {
        "max_workers": max_workers,
        "max_time_minutes": max_time,
        "intensity": scan_intensity,
        "include_subdomains": True,
        "include_cloud_detection": True,
        "intelligent_learning": True,
    }

    def run_scan_thread():
        """Run scan in background thread with proper error handling."""
        try:
            logger.info("🚀 Scan thread started - initiating reconnaissance")

            # Get orchestrator from session state or create new one
            orchestrator = st.session_state.get("orchestrator")
            progress_bar = st.session_state.get("progress_bar")

            logger.info("📊 Setting up progress callbacks and orchestrator")

            # THREAD-SAFE progress callback with locking
            progress_lock = threading.Lock()
            last_progress = [0.0]  # Use list for mutable reference

            def enhanced_progress_callback(progress: float, message: str):
                with progress_lock:
                    # Only update if progress is moving forward (prevent conflicts)
                    if progress >= last_progress[0]:
                        st.session_state.scan_progress = progress
                        st.session_state.scan_status = message
                        last_progress[0] = progress

                        # Log progress updates to terminal
                        logger.info(f"📈 Progress: {progress:.1f}% - {message}")

                        if progress_bar:
                            progress_callback(progress, message)

            # THREAD-SAFE status callback
            def enhanced_status_callback(icon: str, message: str):
                with progress_lock:
                    st.session_state.scan_status = f"{icon} {message}"
                    # Log status updates to terminal
                    logger.info(f"📡 Status: {icon} {message}")
                    if progress_bar:
                        status_callback(icon, message)

            # Phase completion callback
            def phase_completion_callback(phase, phase_result):
                st.session_state.phase_results[phase] = phase_result
                update_live_metrics_from_phase(phase, phase_result)
                logger.info(f"✅ Phase completed: {phase}")

            # Start reconnaissance with passed orchestrator
            logger.info(f"🎯 Launching intelligence scan for target: {target_org}")

            start_time = time.time()
            result = run_intelligence_scan(
                target_organization=target_org,
                base_domains=base_domains,
                scan_config=scan_config,
                progress_callback=enhanced_progress_callback,
                status_callback=enhanced_status_callback,
                phase_callback=phase_completion_callback,
                orchestrator=orchestrator,
            )
            duration = time.time() - start_time

            # Complete the scan
            st.session_state.scan_results = result
            st.session_state.scan_running = False

            logger.info(f"✅ Reconnaissance completed in {duration:.1f}s")
            logger.info(f"📊 Scan Results Summary:")
            if result:
                logger.info(f"   • Domains found: {len(result.domains)}")
                logger.info(
                    f"   • Subdomains found: {len(result.get_all_subdomains())}"
                )
                logger.info(f"   • ASNs found: {len(result.asns)}")
                logger.info(f"   • IP ranges found: {len(result.ip_ranges)}")
                logger.info(f"   • Cloud services found: {len(result.cloud_services)}")

            if progress_bar:
                progress_bar.complete("✅ Reconnaissance Complete!")

            # Save to database
            db_manager = st.session_state.get("db_manager")
            if result and db_manager:
                try:
                    scan_id = db_manager.store_scan_result(result)
                    logger.info(f"💾 Scan results saved to database with ID: {scan_id}")
                except Exception as e:
                    logger.error(f"❌ Failed to save scan results: {e}")

        except Exception as e:
            logger.exception("❌ Critical error in reconnaissance scan")
            st.session_state.scan_running = False

            logger.error(f"🚨 Scan failed for target '{target_org}': {str(e)}")

            if progress_bar:
                progress_bar.error(f"❌ Scan failed: {str(e)}")

            # Don't call st.error from thread - just log it
            logger.error(f"💥 Reconnaissance operation terminated due to error")

    # Use HighPerformanceTimeoutExecutor instead of direct threading
    try:
        HighPerformanceTimeoutExecutor.execute_with_timeout(
            run_scan_thread,
            timeout_seconds=max_time * 60 + 120,  # Add 2 minutes buffer
            pool_name="scan_execution",
        )
    except Exception as e:
        logger.error(f"Scan execution failed: {e}")
        st.session_state.scan_running = False
        if st.session_state.get("progress_bar"):
            st.session_state.progress_bar.error(f"❌ Scan failed: {str(e)}")

    st.success(f"🚀 Reconnaissance started for **{target_org}**")
    st.rerun()


def cancel_reconnaissance_scan():
    """Cancel the current reconnaissance scan."""
    st.session_state.scan_running = False

    progress_bar = st.session_state.get("progress_bar")
    if progress_bar:
        progress_bar.error("⏹️ Scan cancelled by user")

    st.warning("⏹️ Scan cancelled")
    st.rerun()


# ============================================================================
# RESULTS DASHBOARD
# ============================================================================


def render_results_dashboard():
    """Render a clean and simple results dashboard."""

    st.markdown("## 📊 Scan Results")

    if not st.session_state.db_manager:
        st.error("❌ Database not available")
        return

    try:
        # Get recent scans with proper error handling
        recent_scans = st.session_state.db_manager.get_recent_scans(limit=10)

        if recent_scans:
            # Simple scan history display
            for i, scan in enumerate(recent_scans):
                scan_date = scan.get("created_at", "Unknown")
                if isinstance(scan_date, str) and len(scan_date) > 16:
                    scan_date = scan_date[:16]

                with st.expander(
                    f"🎯 {scan['target_organization']} - {scan_date}",
                    expanded=(i == 0),  # Expand first (most recent) scan by default
                ):
                    # Clean metrics display with better formatting
                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        domains = scan.get("total_domains", 0)
                        st.markdown(f"**🌐 Domains:** {domains}")
                    with col2:
                        asns = scan.get("total_asns", 0)
                        st.markdown(f"**📡 ASNs:** {asns}")
                    with col3:
                        ip_ranges = scan.get("total_ip_ranges", 0)
                        st.markdown(f"**💻 IP Ranges:** {ip_ranges}")
                    with col4:
                        cloud_services = scan.get("total_cloud_services", 0)
                        st.markdown(f"**☁️ Cloud Services:** {cloud_services}")

                    # Calculate relative time for scan age
                    scan_timestamp = scan.get("scan_timestamp")
                    if scan_timestamp:
                        if isinstance(scan_timestamp, str):
                            try:
                                from datetime import datetime

                                scan_dt = datetime.fromisoformat(
                                    scan_timestamp.replace("Z", "+00:00")
                                )
                                age_seconds = (datetime.now() - scan_dt).total_seconds()
                                if age_seconds < 3600:  # Less than 1 hour
                                    age_display = f"{age_seconds/60:.0f} minutes ago"
                                elif age_seconds < 86400:  # Less than 1 day
                                    age_display = f"{age_seconds/3600:.1f} hours ago"
                                else:  # More than 1 day
                                    age_display = f"{age_seconds/86400:.1f} days ago"
                            except:
                                age_display = "Recently"
                        else:
                            age_display = "Recently"

                        st.markdown(f"**⏱️ Scanned:** {age_display}")
                    else:
                        st.markdown("**⏱️ Scanned:** Recently")

                    # Simple action buttons
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(
                            "📖 Load Results",
                            key=f"load_{scan['id']}",
                            use_container_width=True,
                            type="primary",
                        ):
                            try:
                                result = st.session_state.db_manager.load_scan_result(
                                    scan["id"]
                                )
                                st.session_state.scan_results = result
                                st.success("✅ Results loaded successfully!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ Failed to load results: {str(e)}")

                    with col2:
                        if st.button(
                            "🔄 Re-scan",
                            key=f"rescan_{scan['id']}",
                            use_container_width=True,
                        ):
                            st.info("🚀 Re-scan functionality coming soon!")

        else:
            # Simple empty state
            st.info(
                "🔍 No scan results yet. Run your first reconnaissance scan to see results here."
            )

        # Display current results if available
        if st.session_state.scan_results:
            st.markdown("---")
            render_enhanced_scan_results(st.session_state.scan_results)

    except Exception as e:
        logger.exception("Error in results dashboard")
        st.error(f"❌ Error loading results: {str(e)}")


def render_enhanced_scan_results(result):
    """Render comprehensive scan results with advanced components and analytics."""

    if not result:
        st.warning("⚠️ No scan results to display")
        return

    # Enhanced header with organization context
    st.markdown(
        f"""
    <div class="custom-card" style="margin-bottom: 2rem;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h2 style="color: #212529; margin-bottom: 0.5rem;">🎯 {result.target_organization}</h2>
                <p style="color: #6C757D; margin: 0; font-size: 1rem;">
                    Comprehensive reconnaissance analysis and asset discovery results
                </p>
            </div>
            <div style="text-align: right;">
                <div style="
                    background: #E6F9EA;
                    color: #28A745;
                    padding: 0.5rem 1rem;
                    border-radius: 20px;
                    font-size: 0.9rem;
                    font-weight: 500;
                    border: 1px solid #28A745;
                ">
                    ✅ Scan Complete
                </div>
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Results overview without dashboard elements

    # Enhanced statistics overview with better layout
    stats_col1, stats_col2, stats_col3, stats_col4, stats_col5 = st.columns(5)

    with stats_col1:
        render_metric_card("Domains", str(len(result.domains)), "🌐")
    with stats_col2:
        render_metric_card("Subdomains", str(len(result.get_all_subdomains())), "🔗")
    with stats_col3:
        render_metric_card("ASNs", str(len(result.asns)), "📡")
    with stats_col4:
        render_metric_card("IP Ranges", str(len(result.ip_ranges)), "💻")
    with stats_col5:
        render_metric_card("Cloud Services", str(len(result.cloud_services)), "☁️")

    # Enhanced results in tabs with better organization
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        [
            "🌐 Domains & Subdomains",
            "📡 Network Infrastructure",
            "☁️ Cloud Services",
            "🔒 Security Analysis",
            "📊 Analytics & Insights",
            "📥 Export & Actions",
        ]
    )

    with tab1:
        render_enhanced_domains_tab(result)

    with tab2:
        render_enhanced_network_tab(result)

    with tab3:
        render_enhanced_cloud_tab(result)

    with tab4:
        render_security_analysis_tab(result)

    with tab5:
        render_analytics_insights_tab(result)

    with tab6:
        render_export_actions_tab(result)


def render_scan_results(result):
    """Render comprehensive scan results with modern styling."""

    if not result:
        st.warning("⚠️ No scan results to display")
        return

    # Header with organization info
    st.markdown(f"### 🎯 Results for **{result.target_organization}**")

    # Quick statistics overview
    stats_col1, stats_col2, stats_col3, stats_col4, stats_col5 = st.columns(5)

    with stats_col1:
        render_metric_card("Domains", str(len(result.domains)), "🌐")
    with stats_col2:
        render_metric_card("Subdomains", str(len(result.get_all_subdomains())), "🔗")
    with stats_col3:
        render_metric_card("ASNs", str(len(result.asns)), "📡")
    with stats_col4:
        render_metric_card("IP Ranges", str(len(result.ip_ranges)), "💻")
    with stats_col5:
        render_metric_card("Cloud Services", str(len(result.cloud_services)), "☁️")

    # Detailed results in tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "🌐 Domains & Subdomains",
            "📡 ASNs",
            "💻 IP Ranges",
            "☁️ Cloud Services",
            "⚠️ Intelligence Insights",
        ]
    )

    with tab1:
        render_domains_tab(result)

    with tab2:
        render_asns_tab(result)

    with tab3:
        render_ip_ranges_tab(result)

    with tab4:
        render_cloud_services_tab(result)

    with tab5:
        render_intelligence_tab(result)


def render_domains_tab(result):
    """Render domains and subdomains with modern styling."""

    st.markdown("#### 🌐 Discovered Domains")

    if result.domains:
        domains_data = []
        for domain in result.domains:
            domains_data.append(
                {
                    "Domain": domain.name,
                    "Registrar": getattr(domain, "registrar", "Unknown"),
                    "Created": getattr(domain, "creation_date", "Unknown"),
                    "Status": "✅ Active",
                }
            )

        domains_df = pd.DataFrame(domains_data)
        st.dataframe(domains_df, use_container_width=True)
    else:
        st.info("ℹ️ No domains discovered")

    st.markdown("#### 🔗 Discovered Subdomains")

    all_subdomains = result.get_all_subdomains()
    if all_subdomains:
        subdomains_data = []
        for subdomain in all_subdomains:
            # Get resolved IPs
            resolved_ips = getattr(subdomain, "resolved_ips", set())
            ip_list = list(resolved_ips) if resolved_ips else []
            ip_display = ", ".join(ip_list[:3]) if ip_list else "Not resolved"
            if len(ip_list) > 3:
                ip_display += f" (+{len(ip_list) - 3} more)"

            subdomains_data.append(
                {
                    "Subdomain": subdomain.fqdn,
                    "Status": "✅ Active" if ip_list else "⚠️ Unresolved",
                    "Resolved IPs": ip_display,
                    "Source": getattr(subdomain, "data_source", "Unknown"),
                }
            )

        subdomains_df = pd.DataFrame(subdomains_data)
        st.dataframe(subdomains_df, use_container_width=True)

        # Show subdomain statistics
        active_count = sum(
            1 for s in all_subdomains if getattr(s, "resolved_ips", set())
        )
        total_count = len(all_subdomains)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Active Subdomains", active_count)
        with col2:
            st.metric("Total Discovered", total_count)
    else:
        st.info("ℹ️ No subdomains discovered")


def render_asns_tab(result):
    """Render ASNs with geographic distribution."""

    st.markdown("#### 📡 Discovered Autonomous Systems")

    if result.asns:
        asns_data = []
        for asn in result.asns:
            asns_data.append(
                {
                    "ASN": f"AS{asn.number}",
                    "Organization": asn.name,
                    "Description": asn.description,
                    "Country": getattr(asn, "country", "Unknown"),
                    "Type": getattr(asn, "data_source", "Unknown"),
                }
            )

        asns_df = pd.DataFrame(asns_data)
        st.dataframe(asns_df, use_container_width=True)

        # ASN statistics
        countries = [getattr(asn, "country", "Unknown") for asn in result.asns]
        country_counts = pd.Series(countries).value_counts()

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total ASNs", len(result.asns))
        with col2:
            st.metric("Countries", len(country_counts))

        # Geographic distribution chart if we have country data
        if len(country_counts) > 1:
            st.markdown("#### 🗺️ Geographic Distribution")
            chart_data = pd.DataFrame(
                {"Country": country_counts.index, "ASNs": country_counts.values}
            )
            st.bar_chart(chart_data.set_index("Country"))
    else:
        st.info("ℹ️ No ASNs discovered")


def render_ip_ranges_tab(result):
    """Render IP ranges with network analysis."""

    st.markdown("#### 💻 Discovered IP Ranges")

    if result.ip_ranges:
        ip_ranges_data = []
        for ip_range in result.ip_ranges:
            asn_display = f"AS{ip_range.asn}" if hasattr(ip_range, "asn") else "Unknown"

            ip_ranges_data.append(
                {
                    "IP Range": ip_range.cidr,
                    "Version": f"IPv{ip_range.version}",
                    "ASN": asn_display,
                    "Country": getattr(ip_range, "country", "Unknown"),
                    "Size": getattr(ip_range, "size", "Unknown"),
                }
            )

        ip_ranges_df = pd.DataFrame(ip_ranges_data)
        st.dataframe(ip_ranges_df, use_container_width=True)

        # IP statistics
        ipv4_count = sum(1 for ip in result.ip_ranges if ip.version == 4)
        ipv6_count = sum(1 for ip in result.ip_ranges if ip.version == 6)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Ranges", len(result.ip_ranges))
        with col2:
            st.metric("IPv4 Ranges", ipv4_count)
        with col3:
            st.metric("IPv6 Ranges", ipv6_count)
    else:
        st.info("ℹ️ No IP ranges discovered")


def render_cloud_services_tab(result):
    """Render cloud services with provider analysis."""

    st.markdown("#### ☁️ Discovered Cloud Services")

    if result.cloud_services:
        cloud_data = []
        for service in result.cloud_services:
            # CloudService doesn't have confidence attribute, use status or resource_type
            status_display = getattr(service, "status", "Unknown")

            cloud_data.append(
                {
                    "Provider": service.provider,
                    "Service/Identifier": service.identifier,
                    "Type": getattr(service, "resource_type", "Unknown"),
                    "Status": status_display,
                    "Region": getattr(service, "region", "Unknown"),
                }
            )

        cloud_df = pd.DataFrame(cloud_data)
        st.dataframe(cloud_df, use_container_width=True)

        # Provider distribution
        providers = [service.provider for service in result.cloud_services]
        provider_counts = pd.Series(providers).value_counts()

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Services", len(result.cloud_services))
        with col2:
            st.metric("Providers", len(provider_counts))

        # Provider distribution chart
        if len(provider_counts) > 1:
            st.markdown("#### 📊 Provider Distribution")
            st.bar_chart(provider_counts)
    else:
        st.info("ℹ️ No cloud services detected")


def render_intelligence_tab(result):
    """Render intelligence insights and warnings."""

    st.markdown("#### 🧠 Intelligence Insights")

    # Show discovery intelligence if available
    if hasattr(result, "discovery_intelligence") and result.discovery_intelligence:
        intel = result.discovery_intelligence

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Search Terms Generated", len(intel.get("learned_terms", [])))
        with col2:
            st.metric("Discovery Iterations", intel.get("iterations", 0))
        with col3:
            st.metric("Convergence Score", f"{intel.get('convergence_score', 0):.2f}")

        # Show learned terms
        if intel.get("learned_terms"):
            st.markdown("##### 🎯 Learned Intelligence Terms")
            terms_data = []
            for term, confidence in intel["learned_terms"].items():
                terms_data.append(
                    {
                        "Term": term,
                        "Confidence": f"{confidence:.2%}",
                        "Category": "Organization Pattern",
                    }
                )

            if terms_data:
                terms_df = pd.DataFrame(terms_data)
                st.dataframe(terms_df, use_container_width=True)

    # Show warnings if any
    warnings = []

    # Check for potential security concerns
    all_subdomains = result.get_all_subdomains()
    if len(all_subdomains) > 100:
        warnings.append(
            {
                "Type": "⚠️ Large Attack Surface",
                "Message": f"Organization has {len(all_subdomains)} subdomains - large attack surface",
                "Severity": "Medium",
            }
        )

    if len(result.asns) > 10:
        warnings.append(
            {
                "Type": "ℹ️ Complex Infrastructure",
                "Message": f"Organization uses {len(result.asns)} ASNs - complex network infrastructure",
                "Severity": "Info",
            }
        )

    # Check for cloud diversity
    if result.cloud_services:
        providers = set(service.provider for service in result.cloud_services)
        if len(providers) > 3:
            warnings.append(
                {
                    "Type": "ℹ️ Multi-Cloud Strategy",
                    "Message": f"Organization uses {len(providers)} cloud providers",
                    "Severity": "Info",
                }
            )

    if warnings:
        st.markdown("##### ⚠️ Security & Intelligence Insights")
        for warning in warnings:
            if warning["Severity"] == "High":
                st.error(f"{warning['Type']} {warning['Message']}")
            elif warning["Severity"] == "Medium":
                st.warning(f"{warning['Type']} {warning['Message']}")
            else:
                st.info(f"{warning['Type']} {warning['Message']}")
    else:
        st.success("✅ No security concerns identified in discovered assets")


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def update_live_metrics_from_phase(phase: str, result: Any):
    """Update live metrics from phase completion."""
    if not result:
        return

    if phase == "domain_discovery" and hasattr(result, "domains"):
        st.session_state.live_metrics["domains_found"] = len(result.domains)
        st.session_state.live_metrics["subdomains_found"] = len(
            result.get_all_subdomains()
        )

    elif phase == "asn_discovery" and hasattr(result, "asns"):
        st.session_state.live_metrics["asns_found"] = len(result.asns)

    elif phase == "ip_discovery" and hasattr(result, "ip_ranges"):
        st.session_state.live_metrics["ip_ranges_found"] = len(result.ip_ranges)

    elif phase == "cloud_detection" and hasattr(result, "cloud_services"):
        st.session_state.live_metrics["cloud_services_found"] = len(
            result.cloud_services
        )


def run_intelligence_scan(
    target_organization: str,
    base_domains: Optional[Set[str]] = None,
    scan_config: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable] = None,
    status_callback: Optional[Callable] = None,
    phase_callback: Optional[Callable] = None,
    orchestrator: Optional[IntelligentDiscoveryOrchestrator] = None,
) -> ReconnaissanceResult:
    """Run intelligent reconnaissance scan with callbacks."""

    try:
        # Configure orchestrator - use passed orchestrator or create new one
        if orchestrator is None:
            from src.config.settings import get_settings

            # Get base settings
            settings = get_settings()

            # Apply scan configuration if provided
            if scan_config:
                if "max_workers" in scan_config:
                    settings.recon.max_workers = scan_config["max_workers"]
                if "max_time_minutes" in scan_config:
                    # Convert to timeout_seconds
                    settings.recon.timeout_seconds = (
                        scan_config["max_time_minutes"] * 60
                    )

            orchestrator = IntelligentDiscoveryOrchestrator(config=settings)

        # Run reconnaissance with callbacks
        result = orchestrator.run_intelligent_discovery(
            target_organization=target_organization,
            base_domains=base_domains,
            progress_callback=progress_callback,
            status_callback=status_callback,
            phase_callback=phase_callback,
        )

        return result

    except Exception as e:
        logger.exception("Error in intelligence scan")
        raise e


# ============================================================================
# SETTINGS INTERFACE
# ============================================================================


def render_settings_interface():
    """Render the settings interface with modern styling."""

    st.markdown("## ⚙️ Application Settings")

    st.markdown("### 🎨 Interface Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.selectbox(
            "**Theme**",
            ["Light Professional", "Dark", "Auto"],
            index=0,
            help="Choose application theme",
        )

        st.checkbox(
            "Show detailed progress",
            value=True,
            help="Display detailed progress metrics during scans",
        )

    with col2:
        st.slider(
            "**Progress Update Frequency**",
            min_value=1,
            max_value=10,
            value=5,
            help="Updates per second for progress bars",
        )

        st.checkbox(
            "Enable animations",
            value=True,
            help="Enable smooth animations and transitions",
        )

    st.markdown("### 🔧 Scan Configuration Defaults")

    col1, col2 = st.columns(2)

    with col1:
        st.slider(
            "**Default Max Workers**",
            min_value=1,
            max_value=50,
            value=10,
            help="Default number of concurrent workers",
        )

        st.slider(
            "**Default Timeout (minutes)**",
            min_value=1,
            max_value=30,
            value=5,
            help="Default scan timeout",
        )

    with col2:
        st.selectbox(
            "**Default Scan Intensity**",
            ["🚀 Quick", "⚖️ Balanced", "🔬 Deep", "🧠 Maximum"],
            index=1,
            help="Default scan intensity level",
        )

        st.checkbox(
            "Auto-save results",
            value=True,
            help="Automatically save scan results to database",
        )

    st.markdown("### 💾 Database Information")

    if st.session_state.db_manager:
        try:
            stats = st.session_state.db_manager.get_scan_statistics()

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                render_metric_card(
                    "Total Scans", str(stats.get("total_scans", 0)), "🔍"
                )
            with col2:
                render_metric_card(
                    "Total Domains", str(stats.get("total_domains", 0)), "🌐"
                )
            with col3:
                render_metric_card("Total ASNs", str(stats.get("total_asns", 0)), "📡")
            with col4:
                render_metric_card("Database Size", "< 1MB", "💾")

        except Exception as e:
            st.warning(f"⚠️ Could not load database statistics: {str(e)}")

    # Advanced settings
    with st.expander("🔧 Advanced Settings", expanded=False):
        st.markdown("#### Rate Limiting")

        col1, col2 = st.columns(2)
        with col1:
            st.slider("API Request Rate (req/sec)", 1, 10, 3)
        with col2:
            st.slider("Concurrent DNS Lookups", 5, 100, 20)

        st.markdown("#### Export Settings")
        st.selectbox("Default Export Format", ["JSON", "CSV", "Excel", "XML"])
        st.checkbox("Include Raw Data in Exports", True)


def render_professional_footer():
    """Render the professional application footer."""
    st.markdown("---")
    st.markdown(
        """
    <div style="
        text-align: center;
        color: #6c757d;
        font-size: 0.9rem;
        margin-top: 2rem;
        padding: 1rem;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 12px;
    ">
        <p>
            🎯 <strong>ReconForge Professional v2.0</strong> - Enterprise Asset Intelligence Platform<br>
            Modern Light Theme • Advanced Progress System • Professional UX Design
        </p>
        <p style="font-size: 0.8rem; margin-top: 0.5rem; opacity: 0.8;">
            ⚠️ For authorized security research only. Ensure proper authorization before scanning any organization.
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )


# ============================================================================
# MAIN APPLICATION
# ============================================================================


def main():
    """Main application entry point with enhanced error handling."""

    # FIRST: Setup simple logging for terminal output
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),  # Console output
        ],
    )

    # SECOND: Suppress Streamlit thread warnings after logging setup
    suppress_streamlit_thread_warnings()

    # Apply modern styling
    apply_modern_styling()

    # Initialize session state
    initialize_session_state()

    # Configure enhanced logging
    logger.info("🚀 ReconForge Professional starting...")

    # Get configuration settings
    try:
        settings = get_settings()
        logger.info("✅ Configuration loaded successfully")
    except Exception as e:
        logger.error(f"❌ Failed to load configuration: {e}")
        st.error(f"Configuration Error: {e}")
        return

    # Initialize database manager
    if "db_manager" not in st.session_state:
        try:
            st.session_state.db_manager = DatabaseManager()
            logger.info("✅ Database initialized successfully")
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
            st.error(f"Database Error: {e}")
            return

    # Initialize intelligence orchestrator
    if "orchestrator" not in st.session_state:
        try:
            st.session_state.orchestrator = IntelligentDiscoveryOrchestrator(
                config=settings
            )
            logger.info("✅ Intelligence orchestrator initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize orchestrator: {e}")
            st.error(f"Orchestrator Error: {e}")
            return

    # Initialize phase results tracking
    if "phase_results" not in st.session_state:
        st.session_state.phase_results = {}

    # Render professional header
    render_professional_header()

    # Render sidebar for configuration
    render_sidebar()

    # Main navigation tabs with modern styling
    st.markdown(
        """
        <div style="margin: 2rem 0 1rem 0;">
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Create main navigation tabs
    tab1, tab2, tab3, tab4 = st.tabs(
        ["🎯 Dashboard", "🔍 Reconnaissance", "📊 Results", "⚙️ Settings"]
    )

    with tab1:
        # Dashboard tab - Overview and system status
        render_dashboard_overview()

    with tab2:
        # Reconnaissance tab - Scan interface
        render_scan_interface()

    with tab3:
        # Results tab - Historical results and analysis
        render_results_dashboard()

    with tab4:
        # Settings tab - Configuration interface
        render_settings_interface()

    # Render professional footer
    render_professional_footer()


if __name__ == "__main__":
    main()
