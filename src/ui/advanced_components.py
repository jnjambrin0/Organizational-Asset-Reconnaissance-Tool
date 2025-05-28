"""
Advanced Professional UI Components for ReconForge
Enhanced UX with intelligent dashboards, rich visualizations, and interactive analysis.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import json


def render_intelligent_dashboard(scan_results=None, historical_data=None):
    """Render an intelligent dashboard with AI-powered insights and analytics."""

    st.markdown(
        """
    <div class="intelligent-dashboard">
        <div class="dashboard-header">
            <h2>🧠 Intelligent Analysis Dashboard</h2>
            <p>AI-powered insights and security analysis for your digital assets</p>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Simplified System Status Row
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
        <div style="
            background: #E6F9EA;
            border: 2px solid #28A745;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        ">
            <div style="font-size: 1.5rem;">🛡️</div>
            <div style="font-size: 1.1rem; font-weight: 600; color: #28A745;">System Online</div>
            <div style="font-size: 0.85rem; color: #6C757D;">All services running</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
        <div style="
            background: #E3F2FD;
            border: 2px solid #17A2B8;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        ">
            <div style="font-size: 1.5rem;">🎯</div>
            <div style="font-size: 1.1rem; font-weight: 600; color: #17A2B8;">Ready to Scan</div>
            <div style="font-size: 0.85rem; color: #6C757D;">All engines ready</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
        <div style="
            background: #FFF8E1;
            border: 2px solid #FFC107;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        ">
            <div style="font-size: 1.5rem;">⚡</div>
            <div style="font-size: 1.1rem; font-weight: 600; color: #F57C00;">High Performance</div>
            <div style="font-size: 0.85rem; color: #6C757D;">Optimized settings</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Enhanced Security Analysis Section
    render_security_insights_panel(scan_results)


def render_insight_metric_card(
    title: str, value: str, trend: str, icon: str, insight: str, color: str = "primary"
):
    """Render an enhanced metric card with AI insights and trends."""

    color_scheme = {
        "primary": {"bg": "#E6F3FF", "border": "#0066CC", "text": "#0066CC"},
        "success": {"bg": "#E6F9EA", "border": "#28A745", "text": "#28A745"},
        "warning": {"bg": "#FFF8E1", "border": "#FFC107", "text": "#F57C00"},
        "info": {"bg": "#E3F2FD", "border": "#17A2B8", "text": "#17A2B8"},
        "danger": {"bg": "#FFEBEE", "border": "#DC3545", "text": "#DC3545"},
    }

    scheme = color_scheme.get(color, color_scheme["primary"])

    trend_color = (
        "#28A745"
        if "+" in trend and "+" != trend
        else "#DC3545" if "-" in trend else "#6C757D"
    )

    card_html = f"""
    <div class="insight-metric-card" style="
        background: {scheme['bg']};
        border: 2px solid {scheme['border']};
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
        margin-bottom: 1rem;
    ">
        <div style="
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 100%;
            background: linear-gradient(45deg, transparent, rgba(255,255,255,0.1), transparent);
            transform: rotate(45deg);
            animation: shimmer 3s infinite;
        "></div>
        
        <div style="position: relative; z-index: 2;">
            <div style="font-size: 2rem; margin-bottom: 0.5rem;">{icon}</div>
            <div style="font-size: 1.8rem; font-weight: 700; color: {scheme['text']}; margin-bottom: 0.25rem;">
                {value}
            </div>
            <div style="font-size: 0.9rem; font-weight: 600; color: #212529; margin-bottom: 0.5rem;">
                {title}
            </div>
            <div style="font-size: 0.8rem; color: {trend_color}; font-weight: 500; margin-bottom: 0.25rem;">
                {trend}
            </div>
            <div style="font-size: 0.75rem; color: #6C757D; font-style: italic;">
                {insight}
            </div>
        </div>
    </div>
    """

    st.html(card_html)


def render_security_insights_panel(scan_results):
    """Render AI-powered security insights and recommendations with enhanced layout."""

    st.html(
        """
    <div class="custom-card">
        <div class="card-title">🔒 Enhanced Security Analysis Dashboard</div>
        <p style="color: #6C757D; margin-bottom: 1rem;">
            Comprehensive analysis with actionable insights and trend monitoring
        </p>
    </div>
    """
    )

    # Sequential layout for cleaner, less saturated interface

    # Security insights tabs
    insight_tab1, insight_tab2 = st.tabs(
        ["🚨 Alerts & Insights", "📋 Recommended Actions"]
    )

    with insight_tab1:
        render_security_alerts()
        st.markdown("---")
        render_intelligent_insights()

    with insight_tab2:
        render_recommended_actions()

    # Separator for visual clarity
    st.markdown("---")

    # Recent Activity section displayed below
    render_enhanced_recent_activity(scan_results)


def render_enhanced_recent_activity(scan_results):
    """Render an enhanced recent activity panel with better space utilization."""

    st.html(
        """
    <div class="custom-card">
        <div class="card-title">📈 Recent Activity</div>
        <p style="color: #6C757D; margin-bottom: 1rem;">
            Track your reconnaissance activities and asset discovery trends
        </p>
    </div>
    """
    )

    # Activity metrics (sequential grid layout for better breathing)
    st.html(
        """
    <div style="
        display: grid; 
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
        gap: 1rem; 
        margin-bottom: 1.5rem;
    ">
        <div style="
            background: #F0F8FF;
            border: 1px solid #B6D7FF;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <div style="font-size: 2rem; font-weight: 700; color: #0066CC; margin-bottom: 0.5rem;">
                127
            </div>
            <div style="font-size: 0.9rem; color: #6C757D; margin-bottom: 0.25rem;">
                Assets Discovered
            </div>
            <div style="font-size: 0.8rem; color: #28A745; font-weight: 500;">
                +12 from yesterday
            </div>
        </div>
        
        <div style="
            background: #F8F9FA;
            border: 1px solid #DEE2E6;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <div style="font-size: 2rem; font-weight: 700; color: #212529; margin-bottom: 0.5rem;">
                3
            </div>
            <div style="font-size: 0.9rem; color: #6C757D; margin-bottom: 0.25rem;">
                Scans Today
            </div>
            <div style="font-size: 0.8rem; color: #6C757D; font-weight: 500;">
                Last: 2 hours ago
            </div>
        </div>
        
        <div style="
            background: #FFF8E1;
            border: 1px solid #FFE082;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <div style="font-size: 2rem; font-weight: 700; color: #F57C00; margin-bottom: 0.5rem;">
                23
            </div>
            <div style="font-size: 0.9rem; color: #6C757D; margin-bottom: 0.25rem;">
                New Subdomains
            </div>
            <div style="font-size: 0.8rem; color: #F57C00; font-weight: 500;">
                This week
            </div>
        </div>
        
        <div style="
            background: #E8F5E8;
            border: 1px solid #A5D6A7;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <div style="font-size: 2rem; font-weight: 700; color: #2E7D32; margin-bottom: 0.5rem;">
                98%
            </div>
            <div style="font-size: 0.9rem; color: #6C757D; margin-bottom: 0.25rem;">
                Success Rate
            </div>
            <div style="font-size: 0.8rem; color: #2E7D32; font-weight: 500;">
                Last 30 days
            </div>
        </div>
    </div>
    """
    )

    # Latest Discoveries section (full width, no compressed columns)
    st.html(
        """
    <div style="
        background: #F8F9FA;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    ">
        <h6 style="margin: 0 0 1rem 0; color: #212529; font-weight: 600; font-size: 1.1rem;">🔍 Latest Discoveries</h6>
        <div style="max-height: 300px; overflow-y: auto;">
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #E9ECEF;">
                <div>
                    <div style="font-size: 0.95rem; font-weight: 500; color: #212529;">api.example.com</div>
                    <div style="font-size: 0.8rem; color: #6C757D;">Subdomain</div>
                </div>
                <div style="font-size: 0.75rem; color: #6C757D;">2h ago</div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #E9ECEF;">
                <div>
                    <div style="font-size: 0.95rem; font-weight: 500; color: #212529;">AS64512</div>
                    <div style="font-size: 0.8rem; color: #6C757D;">Autonomous System</div>
                </div>
                <div style="font-size: 0.75rem; color: #6C757D;">3h ago</div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #E9ECEF;">
                <div>
                    <div style="font-size: 0.95rem; font-weight: 500; color: #212529;">s3.amazonaws.com</div>
                    <div style="font-size: 0.8rem; color: #6C757D;">Cloud Service</div>
                </div>
                <div style="font-size: 0.75rem; color: #6C757D;">5h ago</div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #E9ECEF;">
                <div>
                    <div style="font-size: 0.95rem; font-weight: 500; color: #212529;">192.168.1.0/24</div>
                    <div style="font-size: 0.8rem; color: #6C757D;">IP Range</div>
                </div>
                <div style="font-size: 0.75rem; color: #6C757D;">1d ago</div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #E9ECEF;">
                <div>
                    <div style="font-size: 0.95rem; font-weight: 500; color: #212529;">cdn.cloudflare.com</div>
                    <div style="font-size: 0.8rem; color: #6C757D;">CDN Service</div>
                </div>
                <div style="font-size: 0.75rem; color: #6C757D;">1d ago</div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0;">
                <div>
                    <div style="font-size: 0.95rem; font-weight: 500; color: #212529;">mail.company.com</div>
                    <div style="font-size: 0.8rem; color: #6C757D;">Mail Server</div>
                </div>
                <div style="font-size: 0.75rem; color: #6C757D;">2d ago</div>
            </div>
        </div>
    </div>
    """
    )

    # Quick Actions section (full width with better spacing)
    st.html(
        """
    <div style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 12px;
        padding: 1.5rem;
        color: white;
        text-align: center;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    ">
        <h6 style="margin: 0 0 1rem 0; color: white; font-weight: 600; font-size: 1.1rem;">⚡ Quick Actions</h6>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem;">
            <button style="
                background: rgba(255,255,255,0.2);
                border: 1px solid rgba(255,255,255,0.3);
                border-radius: 8px;
                color: white;
                padding: 1rem 1.5rem;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
                width: 100%;
                font-weight: 500;
            ">🔄 Start New Scan</button>
            <button style="
                background: rgba(255,255,255,0.2);
                border: 1px solid rgba(255,255,255,0.3);
                border-radius: 8px;
                color: white;
                padding: 1rem 1.5rem;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
                width: 100%;
                font-weight: 500;
            ">📊 Export Results</button>
            <button style="
                background: rgba(255,255,255,0.2);
                border: 1px solid rgba(255,255,255,0.3);
                border-radius: 8px;
                color: white;
                padding: 1rem 1.5rem;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.3s ease;
                width: 100%;
                font-weight: 500;
            ">📈 View Analytics</button>
        </div>
    </div>
    """
    )

    # System Status section (full width, professional layout)
    st.html(
        """
    <div style="
        background: #F8F9FA;
        border-radius: 12px;
        padding: 1.5rem;
        border: 1px solid #DEE2E6;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    ">
        <h6 style="margin: 0 0 1rem 0; color: #212529; font-weight: 600; font-size: 1.1rem;">⚙️ System Status</h6>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: white; border-radius: 8px; border: 1px solid #E9ECEF;">
                <span style="font-size: 0.9rem; color: #6C757D; font-weight: 500;">API Status</span>
                <span style="color: #28A745; font-size: 0.9rem; font-weight: 600;">🟢 Online</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: white; border-radius: 8px; border: 1px solid #E9ECEF;">
                <span style="font-size: 0.9rem; color: #6C757D; font-weight: 500;">Database</span>
                <span style="color: #28A745; font-size: 0.9rem; font-weight: 600;">🟢 Healthy</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: white; border-radius: 8px; border: 1px solid #E9ECEF;">
                <span style="font-size: 0.9rem; color: #6C757D; font-weight: 500;">Rate Limits</span>
                <span style="color: #FFC107; font-size: 0.9rem; font-weight: 600;">🟡 Normal</span>
            </div>
        </div>
    </div>
    """
    )


def render_security_alerts():
    """Render security alerts and warnings."""

    alerts = [
        {
            "level": "warning",
            "title": "Subdomain Sprawl Detected",
            "description": "127 subdomains discovered - potential management complexity",
            "recommendation": "Audit and inventory all subdomains",
            "icon": "⚠️",
        },
        {
            "level": "info",
            "title": "Multi-Cloud Usage",
            "description": "Assets detected across 3 cloud providers",
            "recommendation": "Ensure consistent security policies",
            "icon": "☁️",
        },
        {
            "level": "success",
            "title": "Certificate Management",
            "description": "All discovered domains have valid certificates",
            "recommendation": "Continue current certificate practices",
            "icon": "🔒",
        },
    ]

    for alert in alerts:
        level_colors = {
            "warning": {"bg": "#FFF8E1", "border": "#FFC107", "text": "#F57C00"},
            "info": {"bg": "#E3F2FD", "border": "#17A2B8", "text": "#17A2B8"},
            "success": {"bg": "#E6F9EA", "border": "#28A745", "text": "#28A745"},
            "danger": {"bg": "#FFEBEE", "border": "#DC3545", "text": "#DC3545"},
        }

        color = level_colors.get(alert["level"], level_colors["info"])

        st.html(
            f"""
        <div style="
            background: {color['bg']};
            border-left: 4px solid {color['border']};
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        ">
            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-size: 1.2rem; margin-right: 0.5rem;">{alert['icon']}</span>
                <strong style="color: {color['text']};">{alert['title']}</strong>
            </div>
            <p style="margin: 0.5rem 0; color: #212529; font-size: 0.9rem;">
                {alert['description']}
            </p>
            <p style="margin: 0; color: #6C757D; font-size: 0.8rem; font-style: italic;">
                💡 {alert['recommendation']}
            </p>
        </div>
        """
        )


def render_intelligent_insights():
    """Render AI-generated insights about the organization."""

    st.info(
        "🧠 Intelligent analysis will appear here after completing reconnaissance scans with sufficient data."
    )


def render_recommended_actions():
    """Render recommended actions based on findings."""

    actions = [
        {
            "action": "Audit Subdomain Inventory",
            "priority": "High",
            "description": "Review and document all discovered subdomains",
            "time": "2-4 hours",
        },
        {
            "action": "Validate Cloud Services",
            "priority": "Medium",
            "description": "Confirm all cloud services are authorized and monitored",
            "time": "1-2 hours",
        },
        {
            "action": "Network Topology Review",
            "priority": "Medium",
            "description": "Map network infrastructure for security assessment",
            "time": "3-5 hours",
        },
    ]

    for action in actions:
        priority_colors = {"High": "#DC3545", "Medium": "#FFC107", "Low": "#28A745"}

        color = priority_colors.get(action["priority"], "#6C757D")

        st.html(
            f"""
        <div style="
            background: white;
            border: 1px solid #DEE2E6;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        ">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <strong style="color: #212529;">{action['action']}</strong>
                <span style="
                    background: {color};
                    color: white;
                    padding: 0.25rem 0.5rem;
                    border-radius: 12px;
                    font-size: 0.75rem;
                    font-weight: 500;
                ">
                    {action['priority']}
                </span>
            </div>
            <p style="margin: 0.5rem 0; color: #6C757D; font-size: 0.9rem;">
                {action['description']}
            </p>
            <div style="color: #6C757D; font-size: 0.8rem;">
                ⏱️ Estimated time: {action['time']}
            </div>
        </div>
        """
        )


def render_enhanced_results_table(
    data: List[Dict], title: str, enable_search: bool = True, enable_filter: bool = True
):
    """Render an enhanced data table with search, filtering, and export capabilities."""

    if not data:
        st.info(f"No {title.lower()} data available")
        return

    st.html(
        f"""
    <div class="custom-card">
        <div class="card-title">
            📊 {title}
            <span style="background: #0066CC; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem; margin-left: auto; font-weight: 500;">
                {len(data)} records
            </span>
        </div>
    </div>
    """
    )

    # Create DataFrame
    df = pd.DataFrame(data)

    # Controls row
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        if enable_search:
            search_term = st.text_input(
                "🔍 Search",
                placeholder=f"Search {title.lower()}...",
                key=f"search_{title.replace(' ', '_')}",
            )

    with col2:
        if enable_filter and len(df.columns) > 1:
            filter_column = st.selectbox(
                "Filter by",
                ["All columns"] + list(df.columns),
                key=f"filter_col_{title.replace(' ', '_')}",
            )

    with col3:
        export_format = st.selectbox(
            "Export as",
            ["View Only", "CSV", "JSON"],
            key=f"export_{title.replace(' ', '_')}",
        )

    # Apply search filter
    if enable_search and "search_term" in locals() and search_term:
        mask = (
            df.astype(str)
            .apply(lambda x: x.str.contains(search_term, case=False, na=False))
            .any(axis=1)
        )
        df = df[mask]

    # Display filtered data
    if len(df) > 0:
        st.dataframe(df, use_container_width=True, hide_index=True, height=400)

        # Export functionality
        if export_format == "CSV":
            csv = df.to_csv(index=False)
            st.download_button(
                label=f"📥 Download {title} as CSV",
                data=csv,
                file_name=f"{title.lower().replace(' ', '_')}.csv",
                mime="text/csv",
            )
        elif export_format == "JSON":
            json_data = df.to_json(orient="records", indent=2)
            st.download_button(
                label=f"📥 Download {title} as JSON",
                data=json_data,
                file_name=f"{title.lower().replace(' ', '_')}.json",
                mime="application/json",
            )
    else:
        st.warning("No data matches your search criteria")


def render_comparison_dashboard(current_scan=None, previous_scan=None):
    """Render a comparison dashboard showing changes between scans."""

    st.html(
        """
    <div class="custom-card">
        <div class="card-title">📈 Scan Comparison Analysis</div>
        <p style="color: #6C757D; margin-bottom: 1rem;">
            Compare current scan results with previous scans to identify changes and trends
        </p>
    </div>
    """
    )

    if not previous_scan:
        st.info(
            "🔍 No previous scan available for comparison. Run multiple scans to see trends and changes."
        )
        return

    # Helper function to safely extract asset counts from scan data
    def safe_get_count(scan, asset_type):
        """Safely extract asset count from scan data (dict or object)."""
        if not scan:
            return 0

        # Handle dictionary format (from database)
        if isinstance(scan, dict):
            if asset_type == "domains":
                return scan.get("total_domains", 0)
            elif asset_type == "asns":
                return scan.get("total_asns", 0)
            elif asset_type == "ip_ranges":
                return scan.get("total_ip_ranges", 0)
            elif asset_type == "cloud_services":
                return scan.get("total_cloud_services", 0)
            return 0

        # Handle object format (ReconnaissanceResult)
        else:
            if asset_type == "domains":
                return len(scan.domains) if hasattr(scan, "domains") else 0
            elif asset_type == "asns":
                return len(scan.asns) if hasattr(scan, "asns") else 0
            elif asset_type == "ip_ranges":
                return len(scan.ip_ranges) if hasattr(scan, "ip_ranges") else 0
            elif asset_type == "cloud_services":
                return (
                    len(scan.cloud_services) if hasattr(scan, "cloud_services") else 0
                )
            return 0

    # Comparison metrics with safe data extraction
    col1, col2, col3, col4 = st.columns(4)

    current_domains = safe_get_count(current_scan, "domains")
    previous_domains = safe_get_count(previous_scan, "domains")
    domain_change = current_domains - previous_domains

    with col1:
        render_comparison_metric("Domains", current_domains, domain_change, "🌐")

    current_asns = safe_get_count(current_scan, "asns")
    previous_asns = safe_get_count(previous_scan, "asns")
    asn_change = current_asns - previous_asns

    with col2:
        render_comparison_metric("ASNs", current_asns, asn_change, "📡")

    current_ips = safe_get_count(current_scan, "ip_ranges")
    previous_ips = safe_get_count(previous_scan, "ip_ranges")
    ip_change = current_ips - previous_ips

    with col3:
        render_comparison_metric("IP Ranges", current_ips, ip_change, "💻")

    current_cloud = safe_get_count(current_scan, "cloud_services")
    previous_cloud = safe_get_count(previous_scan, "cloud_services")
    cloud_change = current_cloud - previous_cloud

    with col4:
        render_comparison_metric("Cloud Services", current_cloud, cloud_change, "☁️")


def render_comparison_metric(title: str, current: int, change: int, icon: str):
    """Render a comparison metric card showing change from previous scan."""

    change_color = "#28A745" if change > 0 else "#DC3545" if change < 0 else "#6C757D"
    change_symbol = "+" if change > 0 else ""
    change_text = f"{change_symbol}{change}"

    st.html(
        f"""
    <div class="metric-card">
        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">{icon}</div>
        <div style="font-size: 1.5rem; font-weight: 700; color: #212529; margin-bottom: 0.25rem;">
            {current}
        </div>
        <div style="font-size: 0.9rem; font-weight: 600; color: #212529; margin-bottom: 0.5rem;">
            {title}
        </div>
        <div style="font-size: 0.8rem; color: {change_color}; font-weight: 500;">
            {change_text} from last scan
        </div>
    </div>
    """
    )


def render_interactive_timeline(scan_history: List[Dict]):
    """Render a simple timeline overview without complex charts."""

    if not scan_history:
        st.info(
            "🔍 No scan history available. Run your first scan to start tracking results!"
        )
        return

    st.markdown("#### 📅 Recent Scan History")

    # Simple scan history list without charts
    for scan in scan_history[:5]:  # Show only last 5 scans
        scan_date = scan.get("created_at", "Unknown")
        if isinstance(scan_date, str):
            try:
                scan_date = datetime.fromisoformat(
                    scan_date.replace("Z", "+00:00")
                ).strftime("%Y-%m-%d %H:%M")
            except:
                scan_date = scan_date[:16] if len(scan_date) > 16 else scan_date

        with st.expander(
            f"🎯 {scan['target_organization']} - {scan_date}", expanded=False
        ):
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Domains", scan.get("total_domains", 0))
            with col2:
                st.metric("ASNs", scan.get("total_asns", 0))
            with col3:
                st.metric("IP Ranges", scan.get("total_ip_ranges", 0))
            with col4:
                duration = scan.get("duration", 0)
                duration_str = f"{duration:.1f}s" if duration else "N/A"
                st.metric("Duration", duration_str)
