"""
Advanced dashboard component for ReconForge Professional.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from src.ui.components import (
    render_metric_card, render_status_indicator, render_chart_card,
    render_alert_card, render_loading_state
)

def render_advanced_dashboard():
    """Render the advanced professional dashboard."""
    
    st.markdown("""
    <div class="custom-card animate-fade-in">
        <div class="card-title">🎯 Intelligence Command Center</div>
        <p style="color: var(--text-secondary);">
            Real-time monitoring and analytics for enterprise reconnaissance operations.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Main dashboard layout
    render_system_status_panel()
    
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        render_performance_metrics()
        render_discovery_analytics()
    
    with col2:
        render_activity_feed()
        render_quick_stats()

def render_system_status_panel():
    """Render system status and health indicators."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">🛡️ System Health Monitor</div>
    </div>
    """, unsafe_allow_html=True)
    
    # System status indicators
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        render_status_indicator("online", "Discovery Engine")
        st.markdown("<div style='margin-top: 0.5rem;'></div>", unsafe_allow_html=True)
        st.metric("Uptime", "99.9%", delta="0.1%")
    
    with col2:
        render_status_indicator("online", "Intelligence Database")
        st.markdown("<div style='margin-top: 0.5rem;'></div>", unsafe_allow_html=True)
        st.metric("Response Time", "145ms", delta="-5ms")
    
    with col3:
        render_status_indicator("online", "AI Learning System")
        st.markdown("<div style='margin-top: 0.5rem;'></div>", unsafe_allow_html=True)
        st.metric("Learning Rate", "94.2%", delta="2.1%")
    
    with col4:
        render_status_indicator("online", "Security Framework")
        st.markdown("<div style='margin-top: 0.5rem;'></div>", unsafe_allow_html=True)
        st.metric("Threat Level", "Low", delta="Stable")

def render_performance_metrics():
    """Render performance and efficiency metrics."""
    
    # Generate sample performance data
    performance_fig = create_performance_chart()
    
    if performance_fig:
        render_chart_card(
            performance_fig,
            "Performance Analytics",
            "Real-time system performance and scan efficiency metrics"
        )

def render_discovery_analytics():
    """Render discovery and intelligence analytics."""
    
    col1, col2 = st.columns(2)
    
    with col1:
        discovery_fig = create_discovery_trends_chart()
        if discovery_fig:
            render_chart_card(
                discovery_fig,
                "Discovery Trends",
                "Asset discovery patterns over time"
            )
    
    with col2:
        efficiency_fig = create_efficiency_chart()
        if efficiency_fig:
            render_chart_card(
                efficiency_fig,
                "Scan Efficiency",
                "Reconnaissance efficiency and success rates"
            )

def render_activity_feed():
    """Render real-time activity feed."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📡 Live Activity Feed</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Simulate activity feed
    activities = [
        {"time": "14:32", "event": "New ASN discovered", "details": "AS15169 (Google)", "status": "success"},
        {"time": "14:30", "event": "Domain scan completed", "details": "234 subdomains found", "status": "success"},
        {"time": "14:28", "event": "Cloud service detected", "details": "AWS S3 bucket", "status": "info"},
        {"time": "14:25", "event": "Rate limit triggered", "details": "BGP.HE.NET API", "status": "warning"},
        {"time": "14:22", "event": "Scan initialized", "details": "Target: example.com", "status": "info"},
    ]
    
    for activity in activities:
        status_icon = {
            "success": "✅",
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "❌"
        }.get(activity["status"], "ℹ️")
        
        st.markdown(f"""
        <div style="padding: 0.5rem; margin: 0.5rem 0; border-left: 3px solid var(--accent-color); background: rgba(255,255,255,0.05); border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 500;">{status_icon} {activity['event']}</span>
                <span style="font-size: 0.8rem; color: var(--text-secondary);">{activity['time']}</span>
            </div>
            <div style="font-size: 0.9rem; color: var(--text-secondary); margin-top: 0.25rem;">
                {activity['details']}
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_quick_stats():
    """Render quick statistics panel."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📊 Quick Statistics</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Get database stats
    if 'db_manager' in st.session_state:
        stats = st.session_state.db_manager.get_scan_statistics()
        
        # Display metrics in a compact format
        st.metric("Total Scans", stats.get('total_scans', 0))
        st.metric("Domains Discovered", stats.get('total_domains', 0))
        st.metric("ASNs Found", stats.get('total_asns', 0))
        st.metric("Active This Week", stats.get('recent_scans_7d', 0))
        
        # Success rate calculation (simulated)
        success_rate = min(95 + (stats.get('total_scans', 0) % 5), 99)
        st.metric("Success Rate", f"{success_rate}%", delta="2%")
    
    # Quick actions
    st.markdown("---")
    
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()
    
    if st.button("📊 Full Analytics", use_container_width=True):
        st.session_state.show_analytics = True
        st.rerun()

def create_performance_chart():
    """Create performance metrics chart."""
    
    # Generate sample data
    hours = list(range(24))
    scan_times = [45 + (i % 8) * 5 + (i % 3) * 2 for i in hours]
    success_rates = [95 + (i % 5) - (i % 7) for i in hours]
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Average Scan Time (seconds)', 'Success Rate (%)'),
        vertical_spacing=0.15
    )
    
    # Scan time chart
    fig.add_trace(
        go.Scatter(
            x=hours,
            y=scan_times,
            mode='lines+markers',
            name='Scan Time',
            line=dict(color='#4facfe', width=3),
            marker=dict(size=6)
        ),
        row=1, col=1
    )
    
    # Success rate chart
    fig.add_trace(
        go.Scatter(
            x=hours,
            y=success_rates,
            mode='lines+markers',
            name='Success Rate',
            line=dict(color='#00f2fe', width=3),
            marker=dict(size=6),
            fill='tonexty'
        ),
        row=2, col=1
    )
    
    fig.update_layout(
        height=400,
        showlegend=False,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#ffffff'
    )
    
    fig.update_xaxes(title_text="Hour of Day", gridcolor='rgba(255,255,255,0.1)')
    fig.update_yaxes(gridcolor='rgba(255,255,255,0.1)')
    
    return fig

def create_discovery_trends_chart():
    """Create discovery trends chart."""
    
    # Generate sample data for the last 7 days
    dates = [(datetime.now() - timedelta(days=i)).strftime('%m/%d') for i in range(6, -1, -1)]
    domains = [12, 18, 15, 22, 19, 25, 21]
    asns = [3, 5, 4, 7, 6, 8, 6]
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=dates,
        y=domains,
        name='Domains',
        marker_color='#4facfe',
        opacity=0.8
    ))
    
    fig.add_trace(go.Bar(
        x=dates,
        y=asns,
        name='ASNs',
        marker_color='#00f2fe',
        opacity=0.8
    ))
    
    fig.update_layout(
        height=300,
        barmode='group',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#ffffff',
        xaxis_title="Date",
        yaxis_title="Assets Discovered",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    
    fig.update_xaxes(gridcolor='rgba(255,255,255,0.1)')
    fig.update_yaxes(gridcolor='rgba(255,255,255,0.1)')
    
    return fig

def create_efficiency_chart():
    """Create scan efficiency chart."""
    
    # Sample efficiency data
    labels = ['ASN Discovery', 'Domain Enum', 'IP Resolution', 'Cloud Detection']
    values = [94, 87, 92, 89]
    colors = ['#4facfe', '#00f2fe', '#667eea', '#764ba2']
    
    fig = go.Figure(data=[
        go.Bar(
            x=labels,
            y=values,
            marker_color=colors,
            text=values,
            textposition='auto',
            texttemplate='%{text}%'
        )
    ])
    
    fig.update_layout(
        height=300,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#ffffff',
        yaxis_title="Efficiency (%)",
        yaxis=dict(range=[0, 100])
    )
    
    fig.update_xaxes(gridcolor='rgba(255,255,255,0.1)')
    fig.update_yaxes(gridcolor='rgba(255,255,255,0.1)')
    
    return fig

def render_scan_timeline(scan_results):
    """Render an interactive scan timeline."""
    
    if not scan_results:
        return
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📈 Scan Timeline</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Create timeline data
    timeline_data = []
    
    # Add discovery phases
    phases = [
        ("Initialization", datetime.now() - timedelta(minutes=5)),
        ("ASN Discovery", datetime.now() - timedelta(minutes=4)),
        ("Domain Enumeration", datetime.now() - timedelta(minutes=3)),
        ("IP Resolution", datetime.now() - timedelta(minutes=2)),
        ("Cloud Detection", datetime.now() - timedelta(minutes=1)),
        ("Completion", datetime.now())
    ]
    
    for i, (phase, timestamp) in enumerate(phases):
        timeline_data.append({
            "Phase": phase,
            "Start": timestamp,
            "End": timestamp + timedelta(minutes=1),
            "Progress": (i + 1) / len(phases) * 100
        })
    
    # Create Gantt-style chart
    fig = go.Figure()
    
    for item in timeline_data:
        fig.add_trace(go.Scatter(
            x=[item["Start"], item["End"]],
            y=[item["Phase"], item["Phase"]],
            mode='lines+markers',
            line=dict(width=10, color='#4facfe'),
            marker=dict(size=8),
            name=item["Phase"],
            showlegend=False
        ))
    
    fig.update_layout(
        height=300,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#ffffff',
        xaxis_title="Time",
        yaxis_title="Discovery Phase"
    )
    
    fig.update_xaxes(gridcolor='rgba(255,255,255,0.1)')
    fig.update_yaxes(gridcolor='rgba(255,255,255,0.1)')
    
    st.plotly_chart(fig, use_container_width=True)

def render_geographic_heatmap(scan_results):
    """Render geographic distribution heatmap."""
    
    if not scan_results or not scan_results.asns:
        return
    
    # Count ASNs by country
    country_counts = {}
    for asn in scan_results.asns:
        country = asn.country if asn.country else 'Unknown'
        country_counts[country] = country_counts.get(country, 0) + 1
    
    if not country_counts or len(country_counts) < 2:
        return
    
    # Create choropleth map
    fig = go.Figure(data=go.Choropleth(
        locations=list(country_counts.keys()),
        z=list(country_counts.values()),
        locationmode='country names',
        colorscale='Viridis',
        colorbar_title="ASN Count"
    ))
    
    fig.update_layout(
        title="Geographic Distribution of ASNs",
        geo=dict(
            showframe=False,
            showcoastlines=True,
            projection_type='equirectangular'
        ),
        height=400,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#ffffff'
    )
    
    render_chart_card(
        fig,
        "Global Asset Distribution",
        "Geographic spread of discovered autonomous systems"
    )

def render_threat_intelligence_panel():
    """Render threat intelligence and security insights."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">🛡️ Threat Intelligence</div>
        <p style="color: var(--text-secondary);">
            Security insights and threat indicators from reconnaissance data.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Security metrics
        render_metric_card("Risk Score", "Low", "🔒", trend="+2%")
        render_metric_card("Exposed Services", "12", "🌐", trend="-5%")
    
    with col2:
        render_metric_card("SSL Issues", "3", "⚠️", trend="+1")
        render_metric_card("Shadow IT", "8", "👻", trend="0")
    
    # Threat indicators
    st.markdown("**🚨 Recent Indicators**")
    
    indicators = [
        {"type": "Subdomain Takeover", "severity": "Medium", "count": 2},
        {"type": "Wildcard Certificate", "severity": "Low", "count": 5},
        {"type": "Exposed Admin Panel", "severity": "High", "count": 1},
        {"type": "CDN Misconfiguration", "severity": "Low", "count": 3}
    ]
    
    for indicator in indicators:
        severity_color = {
            "High": "#ff6b6b",
            "Medium": "#ffa726", 
            "Low": "#66bb6a"
        }.get(indicator["severity"], "#666")
        
        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; margin: 0.25rem 0; background: rgba(255,255,255,0.05); border-radius: 4px;">
            <span>{indicator['type']}</span>
            <div>
                <span style="background: {severity_color}; color: white; padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.8rem; margin-right: 0.5rem;">
                    {indicator['severity']}
                </span>
                <span style="color: var(--text-secondary);">{indicator['count']}</span>
            </div>
        </div>
        """, unsafe_allow_html=True) 