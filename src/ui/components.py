"""
Professional UI components for ReconForge light theme.
"""

import streamlit as st
from typing import Dict, Any, List, Optional
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots


def render_metric_card(
    title: str,
    value: str,
    icon: str,
    trend: Optional[str] = None,
    color: str = "primary",
):
    """Render a professional metric card with light theme styling."""

    trend_html = ""
    if trend:
        trend_color = (
            "#28A745" if "+" in trend else "#DC3545" if "-" in trend else "#6C757D"
        )
        trend_html = f"""
        <div style="font-size: 0.875rem; color: {trend_color}; margin-top: 0.5rem; font-weight: 500;">
            {trend}
        </div>
        """

    card_html = f"""
    <div class="metric-card animate-fade-in">
        <div class="metric-icon">{icon}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-label">{title}</div>
        {trend_html}
    </div>
    """

    st.html(card_html)


def render_status_indicator(status: str, message: str):
    """Render a status indicator with light theme styling."""

    status_classes = {
        "online": "status-online",
        "warning": "status-warning",
        "error": "status-error",
        "offline": "status-error",
    }

    icons = {"online": "🟢", "warning": "🟡", "error": "🔴", "offline": "⚫"}

    status_class = status_classes.get(status, "status-online")
    icon = icons.get(status, "🟢")

    status_html = f"""
    <div class="status-indicator {status_class}">
        <span>{icon}</span>
        <span>{message}</span>
    </div>
    """

    st.html(status_html)


def render_progress_bar(progress: float, title: str, subtitle: str = ""):
    """Render an animated progress bar with light theme."""

    subtitle_html = (
        f"<div style='font-size: 0.875rem; color: #6C757D; margin-bottom: 0.5rem;'>{subtitle}</div>"
        if subtitle
        else ""
    )

    progress_html = f"""
    <div class="progress-container animate-fade-in">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span style="font-weight: 600; color: #212529;">{title}</span>
            <span style="font-weight: 600; color: #0066CC;">{progress:.1f}%</span>
        </div>
        {subtitle_html}
        <div class="progress-bar">
            <div class="progress-fill" style="width: {progress}%;"></div>
        </div>
    </div>
    """

    st.html(progress_html)


def render_timeline_item(
    title: str, description: str, timestamp: datetime, status: str = "completed"
):
    """Render a timeline item for scan progress with light theme."""

    status_colors = {
        "completed": "#0066CC",
        "running": "#FFC107",
        "pending": "#6C757D",
        "error": "#DC3545",
    }

    color = status_colors.get(status, "#0066CC")
    time_str = timestamp.strftime("%H:%M:%S") if timestamp else ""

    timeline_html = f"""
    <div class="timeline-item animate-slide-in" style="border-left: 3px solid {color}; padding-left: 1rem; margin-bottom: 1rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <h4 style="margin: 0; color: #212529; font-size: 1.1rem; font-weight: 600;">{title}</h4>
            <span style="font-size: 0.875rem; color: #6C757D;">{time_str}</span>
        </div>
        <p style="margin: 0; color: #6C757D; line-height: 1.5;">{description}</p>
    </div>
    """

    st.html(timeline_html)


def render_data_table(data: List[Dict], title: str, columns: List[str]):
    """Render a professional data table with light theme."""

    if not data:
        st.info(f"No {title.lower()} data available")
        return

    # Create DataFrame from data
    import pandas as pd

    df = pd.DataFrame(data)

    # Filter columns if specified
    if columns:
        available_cols = [col for col in columns if col in df.columns]
        if available_cols:
            df = df[available_cols]

    # Custom table styling
    st.html(
        f"""
    <div class="custom-card">
        <div class="card-title">
            📊 {title}
            <span style="background: #0066CC; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem; margin-left: auto; font-weight: 500;">
                {len(df)} records
            </span>
        </div>
    </div>
    """
    )

    # Display the dataframe
    st.dataframe(df, use_container_width=True, hide_index=True)


def render_chart_card(fig, title: str, description: str = ""):
    """Render a chart within a professional light theme card container."""

    desc_html = (
        f"<p style='color: #6C757D; margin-bottom: 1rem;'>{description}</p>"
        if description
        else ""
    )

    st.html(
        f"""
    <div class="custom-card">
        <div class="card-title">📈 {title}</div>
        {desc_html}
    </div>
    """
    )

    # Configure chart for light theme
    fig.update_layout(
        plot_bgcolor="rgba(255,255,255,1)",
        paper_bgcolor="rgba(255,255,255,1)",
        font_color="#212529",
        font_family="Inter, sans-serif",
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=True,
        legend=dict(
            bgcolor="rgba(255,255,255,0.9)", bordercolor="#DEE2E6", borderwidth=1
        ),
    )

    # Update axes for light theme
    fig.update_xaxes(gridcolor="#E9ECEF", linecolor="#DEE2E6", tickcolor="#6C757D")
    fig.update_yaxes(gridcolor="#E9ECEF", linecolor="#DEE2E6", tickcolor="#6C757D")

    st.plotly_chart(fig, use_container_width=True)


def create_discovery_timeline_chart(phase_results: Dict[str, Any]):
    """Create a timeline chart for discovery phases with light theme."""

    if not phase_results:
        return None

    # Prepare data for timeline
    phases = []
    start_times = []
    durations = []

    for phase, result in phase_results.items():
        phases.append(phase.replace("_", " ").title())
        start_times.append(result.get("completed_at", datetime.now()))
        durations.append(1)  # Placeholder duration

    # Create Gantt-style chart with light theme colors
    fig = go.Figure()

    colors = ["#0066CC", "#0052A3", "#004499", "#003366"]

    fig.add_trace(
        go.Bar(
            y=phases,
            x=durations,
            orientation="h",
            marker=dict(
                color=colors * ((len(phases) // len(colors)) + 1), line=dict(width=0)
            ),
            text=phases,
            textposition="inside",
            hovertemplate="<b>%{y}</b><br>Duration: %{x}<extra></extra>",
        )
    )

    fig.update_layout(
        title="Discovery Phase Timeline",
        xaxis_title="Duration",
        yaxis_title="Phases",
        height=300,
        showlegend=False,
    )

    return fig


def create_asset_distribution_chart(scan_results):
    """Create a pie chart for asset type distribution with light theme."""

    if not scan_results:
        return None

    # Calculate asset counts
    asset_counts = {
        "Domains": len(scan_results.domains),
        "ASNs": len(scan_results.asns),
        "IP Ranges": len(scan_results.ip_ranges),
        "Cloud Services": len(scan_results.cloud_services),
    }

    # Filter out zero counts
    asset_counts = {k: v for k, v in asset_counts.items() if v > 0}

    if not asset_counts:
        return None

    # Light theme color palette
    colors = ["#0066CC", "#0052A3", "#004499", "#003366"]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=list(asset_counts.keys()),
                values=list(asset_counts.values()),
                hole=0.3,
                marker=dict(colors=colors, line=dict(color="#FFFFFF", width=2)),
                textinfo="label+percent",
                textfont=dict(size=12, color="#212529"),
            )
        ]
    )

    fig.update_layout(
        title="Asset Distribution",
        height=400,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2),
    )

    return fig


def create_geographic_distribution_chart(scan_results):
    """Create a geographic distribution chart for ASNs with light theme."""

    if not scan_results or not scan_results.asns:
        return None

    # Count ASNs by country
    country_counts = {}
    for asn in scan_results.asns:
        country = asn.country if asn.country else "Unknown"
        country_counts[country] = country_counts.get(country, 0) + 1

    if not country_counts:
        return None

    # Create bar chart with light theme
    countries = list(country_counts.keys())
    counts = list(country_counts.values())

    fig = go.Figure(
        data=[
            go.Bar(
                x=countries,
                y=counts,
                marker=dict(color="#0066CC", line=dict(color="#004499", width=1)),
                text=counts,
                textposition="auto",
            )
        ]
    )

    fig.update_layout(
        title="ASN Geographic Distribution",
        xaxis_title="Country",
        yaxis_title="Number of ASNs",
        height=300,
    )

    return fig


def render_loading_state(message: str = "Processing..."):
    """Render a loading state with light theme."""

    loading_html = f"""
    <div class="progress-container" style="text-align: center;">
        <div style="width: 40px; height: 40px; border: 3px solid #E9ECEF; border-top: 3px solid #0066CC; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto;"></div>
        <div style="margin-top: 1rem; color: #6C757D; font-weight: 500;">
            {message}
        </div>
    </div>
    <style>
    @keyframes spin {{
        0% {{ transform: rotate(0deg); }}
        100% {{ transform: rotate(360deg); }}
    }}
    </style>
    """

    st.html(loading_html)


def render_alert_card(message: str, alert_type: str = "info", icon: str = "ℹ️"):
    """Render a professional alert card with light theme."""

    type_styles = {
        "info": {"bg": "#F0F9FF", "border": "#17A2B8", "text": "#0C5460"},
        "success": {"bg": "#F8F9FA", "border": "#28A745", "text": "#155724"},
        "warning": {"bg": "#FFF9E6", "border": "#FFC107", "text": "#856404"},
        "error": {"bg": "#FFF5F5", "border": "#DC3545", "text": "#721C24"},
    }

    style = type_styles.get(alert_type, type_styles["info"])

    alert_html = f"""
    <div class="custom-card" style="background: {style['bg']}; border-left: 4px solid {style['border']};">
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span style="font-size: 1.5rem;">{icon}</span>
            <div>
                <p style="margin: 0; color: {style['text']}; line-height: 1.5; font-weight: 500;">{message}</p>
            </div>
        </div>
    </div>
    """

    st.html(alert_html)


def render_feature_grid(features: List[Dict[str, str]]):
    """Render a grid of feature cards with optimized light theme layout."""

    if not features:
        return

    # Dynamic column calculation: max 4 columns, adapt to feature count
    num_features = len(features)
    num_cols = min(num_features, 4)  # Maximum 4 columns
    cols = st.columns(num_cols)

    for i, feature in enumerate(features):
        col_index = i % num_cols  # Wrap around columns
        with cols[col_index]:
            feature_html = f"""
            <div class="custom-card feature-card" style="text-align: center; min-height: 180px; display: flex; flex-direction: column; justify-content: space-between; padding: 1.25rem;">
                <div style="flex-grow: 1;">
                    <div style="font-size: 2.5rem; margin-bottom: 0.75rem; display: block;">{feature.get('icon', '🔧')}</div>
                    <h3 style="color: #212529; margin-bottom: 0.75rem; font-size: 1.1rem; font-weight: 600; line-height: 1.3;">{feature.get('title', 'Feature')}</h3>
                </div>
                <p style="color: #6C757D; margin: 0; font-size: 0.85rem; line-height: 1.4; text-align: center;">{feature.get('description', 'Description')}</p>
            </div>
            """
            st.html(feature_html)


def render_stats_overview(stats: Dict[str, Any]):
    """Render a comprehensive stats overview with optimized light theme layout."""

    st.markdown(
        """
    <div class="custom-card" style="margin-bottom: 1rem;">
        <div class="card-title" style="margin-bottom: 1rem;">📊 System Statistics</div>
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem;">
    """,
        unsafe_allow_html=True,
    )

    metrics = [
        ("Total Scans", stats.get("total_scans", 0), "🎯"),
        ("ASNs Discovered", stats.get("total_asns", 0), "🌐"),
        ("Domains Found", stats.get("total_domains", 0), "🔗"),
        ("Active This Week", stats.get("recent_scans_7d", 0), "📈"),
    ]

    for title, value, icon in metrics:
        metric_html = f"""
        <div style="display: flex; align-items: center; padding: 0.5rem; background: #F8F9FA; border-radius: 8px; border: 1px solid #E9ECEF;">
            <span style="font-size: 1.25rem; margin-right: 0.75rem;">{icon}</span>
            <div>
                <div style="font-size: 1.1rem; font-weight: 600; color: #0066CC; margin-bottom: 0.125rem;">{value}</div>
                <div style="font-size: 0.75rem; color: #6C757D; text-transform: uppercase; letter-spacing: 0.5px;">{title}</div>
            </div>
        </div>
        """
        st.html(metric_html)

    st.html("</div></div>")
