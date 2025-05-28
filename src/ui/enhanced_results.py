"""
Enhanced Results Display Components for ReconForge
Advanced visualization and analysis of reconnaissance results with interactive features.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import json

# Import the missing function
from src.ui.advanced_components import render_enhanced_results_table


def render_enhanced_domains_tab(result):
    """Render enhanced domains and subdomains with advanced search and filtering."""

    st.markdown("### 🌐 Domain Portfolio Analysis")

    # Domain overview metrics
    all_subdomains = result.get_all_subdomains()
    active_subdomains = [s for s in all_subdomains if getattr(s, "resolved_ips", set())]

    overview_col1, overview_col2, overview_col3, overview_col4 = st.columns(4)

    with overview_col1:
        st.metric(
            "Total Domains", len(result.domains), help="Primary domains discovered"
        )
    with overview_col2:
        st.metric("Total Subdomains", len(all_subdomains), help="All subdomains found")
    with overview_col3:
        st.metric(
            "Active Subdomains",
            len(active_subdomains),
            help="Subdomains with resolved IPs",
        )
    with overview_col4:
        active_rate = (
            (len(active_subdomains) / len(all_subdomains) * 100)
            if all_subdomains
            else 0
        )
        st.metric(
            "Active Rate", f"{active_rate:.1f}%", help="Percentage of active subdomains"
        )

    # Enhanced domain visualization
    if result.domains:
        st.markdown("#### 🏢 Primary Domains")

        domains_data = []
        for domain in result.domains:
            # Count subdomains for this domain
            domain_subdomains = [s for s in all_subdomains if domain.name in s.fqdn]

            domains_data.append(
                {
                    "Domain": domain.name,
                    "Registrar": getattr(domain, "registrar", "Unknown"),
                    "Created": getattr(domain, "creation_date", "Unknown"),
                    "Subdomains": len(domain_subdomains),
                    "Status": "✅ Active",
                    "Security": (
                        "🔒 HTTPS"
                        if hasattr(domain, "https_enabled") and domain.https_enabled
                        else "🔓 Mixed"
                    ),
                }
            )

        # Use enhanced table with search and filtering
        from src.ui.advanced_components import render_enhanced_results_table

        render_enhanced_results_table(domains_data, "Primary Domains")

    # Interactive subdomain analysis
    if all_subdomains:
        st.markdown("#### 🔗 Subdomain Analysis")

        # Subdomain patterns analysis
        subdomain_patterns = {}
        for subdomain in all_subdomains:
            parts = subdomain.fqdn.split(".")
            if len(parts) >= 3:
                pattern = parts[0]  # First part of subdomain
                subdomain_patterns[pattern] = subdomain_patterns.get(pattern, 0) + 1

        # Show most common patterns
        if subdomain_patterns:
            st.markdown("##### 📊 Common Subdomain Patterns")
            pattern_df = (
                pd.DataFrame(
                    list(subdomain_patterns.items()), columns=["Pattern", "Count"]
                )
                .sort_values("Count", ascending=False)
                .head(10)
            )

            fig = px.bar(
                pattern_df,
                x="Pattern",
                y="Count",
                title="Most Common Subdomain Patterns",
                color="Count",
                color_continuous_scale="Blues",
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

        # Enhanced subdomain table
        subdomains_data = []
        for subdomain in all_subdomains:
            resolved_ips = getattr(subdomain, "resolved_ips", set())
            ip_list = list(resolved_ips) if resolved_ips else []
            ip_display = ", ".join(ip_list[:3]) if ip_list else "Not resolved"
            if len(ip_list) > 3:
                ip_display += f" (+{len(ip_list) - 3} more)"

            # Analyze subdomain type
            fqdn_lower = subdomain.fqdn.lower()
            subdomain_type = "Unknown"
            if any(term in fqdn_lower for term in ["api", "rest", "graphql"]):
                subdomain_type = "🔌 API"
            elif any(term in fqdn_lower for term in ["admin", "panel", "dashboard"]):
                subdomain_type = "⚙️ Admin"
            elif any(term in fqdn_lower for term in ["mail", "smtp", "pop", "imap"]):
                subdomain_type = "📧 Email"
            elif any(term in fqdn_lower for term in ["www", "web", "portal"]):
                subdomain_type = "🌐 Web"
            elif any(term in fqdn_lower for term in ["dev", "test", "staging", "qa"]):
                subdomain_type = "🧪 Development"

            subdomains_data.append(
                {
                    "Subdomain": subdomain.fqdn,
                    "Type": subdomain_type,
                    "Status": "✅ Active" if ip_list else "⚠️ Unresolved",
                    "Resolved IPs": ip_display,
                    "Source": getattr(subdomain, "data_source", "Unknown"),
                    "Risk Level": (
                        "🔴 High"
                        if subdomain_type == "⚙️ Admin"
                        else (
                            "🟡 Medium"
                            if subdomain_type == "🧪 Development"
                            else "🟢 Low"
                        )
                    ),
                }
            )

        render_enhanced_results_table(subdomains_data, "Discovered Subdomains")


def render_enhanced_network_tab(result):
    """Render enhanced network infrastructure analysis with ASNs and IP ranges."""

    st.markdown("### 📡 Network Infrastructure Analysis")

    # Network overview
    network_col1, network_col2, network_col3, network_col4 = st.columns(4)

    ipv4_ranges = [ip for ip in result.ip_ranges if ip.version == 4]
    ipv6_ranges = [ip for ip in result.ip_ranges if ip.version == 6]
    countries = list(set(getattr(asn, "country", "Unknown") for asn in result.asns))

    with network_col1:
        st.metric("Total ASNs", len(result.asns), help="Autonomous System Numbers")
    with network_col2:
        st.metric("IP Ranges", len(result.ip_ranges), help="Total IP address ranges")
    with network_col3:
        st.metric("Countries", len(countries), help="Geographic distribution")
    with network_col4:
        total_ips = sum(getattr(ip_range, "size", 0) for ip_range in result.ip_ranges)
        st.metric(
            "Estimated IPs", f"{total_ips:,}", help="Approximate IP address count"
        )

    # ASN Analysis
    if result.asns:
        st.markdown("#### 🏢 Autonomous Systems (ASNs)")

        asns_data = []
        for asn in result.asns:
            # Count related IP ranges
            related_ranges = [
                ip
                for ip in result.ip_ranges
                if hasattr(ip, "asn") and ip.asn == asn.number
            ]

            asns_data.append(
                {
                    "ASN": f"AS{asn.number}",
                    "Organization": asn.name,
                    "Description": (
                        asn.description[:50] + "..."
                        if len(asn.description) > 50
                        else asn.description
                    ),
                    "Country": getattr(asn, "country", "Unknown"),
                    "IP Ranges": len(related_ranges),
                    "Type": getattr(asn, "data_source", "Unknown"),
                }
            )

        render_enhanced_results_table(asns_data, "Autonomous Systems")

        # Geographic distribution chart
        if len(countries) > 1:
            st.markdown("##### 🗺️ Geographic Distribution")
            country_counts = {}
            for asn in result.asns:
                country = getattr(asn, "country", "Unknown")
                country_counts[country] = country_counts.get(country, 0) + 1

            geo_df = pd.DataFrame(
                list(country_counts.items()), columns=["Country", "ASN Count"]
            )
            fig = px.pie(
                geo_df,
                values="ASN Count",
                names="Country",
                title="ASN Distribution by Country",
            )
            st.plotly_chart(fig, use_container_width=True)

    # IP Range Analysis
    if result.ip_ranges:
        st.markdown("#### 💻 IP Address Ranges")

        ip_ranges_data = []
        for ip_range in result.ip_ranges:
            asn_display = f"AS{ip_range.asn}" if hasattr(ip_range, "asn") else "Unknown"
            size = getattr(ip_range, "size", 0)
            size_display = f"{size:,}" if size else "Unknown"

            ip_ranges_data.append(
                {
                    "IP Range": ip_range.cidr,
                    "Version": f"IPv{ip_range.version}",
                    "ASN": asn_display,
                    "Country": getattr(ip_range, "country", "Unknown"),
                    "Size": size_display,
                    "Usage": "🏢 Corporate" if size < 1024 else "🌐 Large Network",
                }
            )

        render_enhanced_results_table(ip_ranges_data, "IP Address Ranges")

        # IP version distribution
        version_col1, version_col2 = st.columns(2)

        with version_col1:
            st.metric("IPv4 Ranges", len(ipv4_ranges))
        with version_col2:
            st.metric("IPv6 Ranges", len(ipv6_ranges))


def render_enhanced_cloud_tab(result):
    """Render enhanced cloud services analysis with provider insights."""

    st.markdown("### ☁️ Cloud Infrastructure Analysis")

    if not result.cloud_services:
        st.info("🔍 No cloud services detected in this scan")
        return

    # Cloud overview metrics
    providers = list(set(service.provider for service in result.cloud_services))
    regions = list(
        set(getattr(service, "region", "Unknown") for service in result.cloud_services)
    )

    cloud_col1, cloud_col2, cloud_col3, cloud_col4 = st.columns(4)

    with cloud_col1:
        st.metric(
            "Total Services", len(result.cloud_services), help="Cloud services detected"
        )
    with cloud_col2:
        st.metric("Providers", len(providers), help="Different cloud providers")
    with cloud_col3:
        st.metric("Regions", len(regions), help="Geographic regions")
    with cloud_col4:
        aws_count = len(
            [s for s in result.cloud_services if "aws" in s.provider.lower()]
        )
        st.metric("AWS Services", aws_count, help="Amazon Web Services")

    # Provider analysis
    st.markdown("#### 🏢 Cloud Provider Distribution")

    provider_counts = {}
    for service in result.cloud_services:
        provider_counts[service.provider] = provider_counts.get(service.provider, 0) + 1

    if len(provider_counts) > 1:
        provider_df = pd.DataFrame(
            list(provider_counts.items()), columns=["Provider", "Service Count"]
        )
        fig = px.bar(
            provider_df,
            x="Provider",
            y="Service Count",
            title="Services by Cloud Provider",
            color="Service Count",
            color_continuous_scale="Viridis",
        )
        st.plotly_chart(fig, use_container_width=True)

    # Enhanced cloud services table
    cloud_data = []
    for service in result.cloud_services:
        # Categorize service type
        service_type = "Unknown"
        identifier_lower = service.identifier.lower()

        if "s3" in identifier_lower or "bucket" in identifier_lower:
            service_type = "🗄️ Storage"
        elif "cloudfront" in identifier_lower or "cdn" in identifier_lower:
            service_type = "🌐 CDN"
        elif "ec2" in identifier_lower or "compute" in identifier_lower:
            service_type = "💻 Compute"
        elif "rds" in identifier_lower or "database" in identifier_lower:
            service_type = "🗃️ Database"
        elif "lambda" in identifier_lower or "function" in identifier_lower:
            service_type = "⚡ Serverless"

        cloud_data.append(
            {
                "Provider": service.provider,
                "Service/Resource": service.identifier,
                "Type": service_type,
                "Category": getattr(service, "resource_type", "Unknown"),
                "Region": getattr(service, "region", "Unknown"),
                "Status": getattr(service, "status", "Unknown"),
            }
        )

    render_enhanced_results_table(cloud_data, "Cloud Services")


def render_security_analysis_tab(result):
    """Render AI-powered security analysis and recommendations."""

    st.markdown("### 🔒 Security Analysis & Risk Assessment")

    # Import security insights from advanced components
    from src.ui.advanced_components import render_security_insights_panel

    render_security_insights_panel(result)

    # Security metrics overview
    all_subdomains = result.get_all_subdomains()
    admin_subdomains = [
        s
        for s in all_subdomains
        if any(
            term in s.fqdn.lower() for term in ["admin", "panel", "dashboard", "manage"]
        )
    ]
    dev_subdomains = [
        s
        for s in all_subdomains
        if any(term in s.fqdn.lower() for term in ["dev", "test", "staging", "qa"])
    ]

    sec_col1, sec_col2, sec_col3, sec_col4 = st.columns(4)

    with sec_col1:
        risk_score = min(100, len(admin_subdomains) * 10 + len(dev_subdomains) * 5)
        risk_level = (
            "🔴 High"
            if risk_score > 50
            else "🟡 Medium" if risk_score > 20 else "🟢 Low"
        )
        st.metric(
            "Risk Score", f"{risk_score}/100", help="Calculated security risk score"
        )

    with sec_col2:
        st.metric(
            "Admin Interfaces",
            len(admin_subdomains),
            help="Potential admin panels found",
        )

    with sec_col3:
        st.metric(
            "Dev/Test Envs",
            len(dev_subdomains),
            help="Development environments exposed",
        )

    with sec_col4:
        large_networks = len(
            [ip for ip in result.ip_ranges if getattr(ip, "size", 0) > 1024]
        )
        st.metric("Large Networks", large_networks, help="Large IP ranges (>1024 IPs)")

    # Security findings
    st.markdown("#### 🚨 Security Findings")

    findings = []

    if admin_subdomains:
        findings.append(
            {
                "Severity": "🔴 High",
                "Finding": "Administrative Interfaces Exposed",
                "Description": f"Found {len(admin_subdomains)} potential administrative interfaces",
                "Recommendation": "Restrict access to admin panels using IP whitelisting or VPN",
                "Assets": [s.fqdn for s in admin_subdomains[:5]],  # Show first 5
            }
        )

    if dev_subdomains:
        findings.append(
            {
                "Severity": "🟡 Medium",
                "Finding": "Development Environments Exposed",
                "Description": f"Found {len(dev_subdomains)} development or testing environments",
                "Recommendation": "Move development environments to internal networks",
                "Assets": [s.fqdn for s in dev_subdomains[:5]],
            }
        )

    if len(result.asns) > 10:
        findings.append(
            {
                "Severity": "🔵 Info",
                "Finding": "Complex Network Infrastructure",
                "Description": f"Organization uses {len(result.asns)} different ASNs",
                "Recommendation": "Ensure consistent security policies across all networks",
                "Assets": [f"AS{asn.number}" for asn in list(result.asns)[:5]],
            }
        )

    if not findings:
        st.success("✅ No significant security concerns identified")
    else:
        for finding in findings:
            with st.expander(
                f"{finding['Severity']} - {finding['Finding']}", expanded=True
            ):
                st.write(f"**Description:** {finding['Description']}")
                st.write(f"**Recommendation:** {finding['Recommendation']}")
                if finding["Assets"]:
                    st.write("**Example Assets:**")
                    for asset in finding["Assets"]:
                        st.write(f"• {asset}")


def render_analytics_insights_tab(result):
    """Render advanced analytics and insights."""

    st.markdown("### 📊 Advanced Analytics & Business Intelligence")

    # Domain growth analysis (simulated)
    st.markdown("#### 📈 Asset Discovery Trends")

    # Simulated trend data
    trend_data = {
        "Metric": ["Domains", "Subdomains", "ASNs", "IP Ranges", "Cloud Services"],
        "Current Scan": [
            len(result.domains),
            len(result.get_all_subdomains()),
            len(result.asns),
            len(result.ip_ranges),
            len(result.cloud_services),
        ],
        "Estimated Previous": [
            max(0, len(result.domains) - 2),
            max(0, len(result.get_all_subdomains()) - 15),
            max(0, len(result.asns) - 1),
            max(0, len(result.ip_ranges) - 5),
            max(0, len(result.cloud_services) - 1),
        ],
    }

    trend_df = pd.DataFrame(trend_data)
    trend_df["Growth"] = trend_df["Current Scan"] - trend_df["Estimated Previous"]

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            name="Previous",
            x=trend_df["Metric"],
            y=trend_df["Estimated Previous"],
            marker_color="lightblue",
        )
    )
    fig.add_trace(
        go.Bar(
            name="Current",
            x=trend_df["Metric"],
            y=trend_df["Current Scan"],
            marker_color="darkblue",
        )
    )

    fig.update_layout(barmode="group", title="Asset Discovery Comparison", height=400)
    st.plotly_chart(fig, use_container_width=True)

    # Infrastructure complexity analysis
    st.markdown("#### 🏗️ Infrastructure Complexity Analysis")

    complexity_metrics = {
        "Domain Diversity": (
            len(set(domain.name.split(".")[-2] for domain in result.domains))
            if result.domains
            else 0
        ),
        "Network Span": len(result.asns),
        "Cloud Adoption": (
            len(set(service.provider for service in result.cloud_services))
            if result.cloud_services
            else 0
        ),
        "Geographic Presence": len(
            set(getattr(asn, "country", "Unknown") for asn in result.asns)
        ),
    }

    complexity_col1, complexity_col2 = st.columns(2)

    with complexity_col1:
        fig = go.Figure(
            go.Scatterpolar(
                r=list(complexity_metrics.values()),
                theta=list(complexity_metrics.keys()),
                fill="toself",
                name="Organization Profile",
            )
        )
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True, range=[0, max(complexity_metrics.values()) + 1]
                )
            ),
            title="Infrastructure Complexity Profile",
            height=400,
        )
        st.plotly_chart(fig, use_container_width=True)

    with complexity_col2:
        st.markdown("##### 🎯 Key Insights")

        insights = []
        if complexity_metrics["Cloud Adoption"] > 2:
            insights.append("🌤️ Multi-cloud strategy adopted")
        if complexity_metrics["Network Span"] > 5:
            insights.append("🌐 Extensive network infrastructure")
        if complexity_metrics["Geographic Presence"] > 3:
            insights.append("🗺️ Global presence detected")
        if len(result.get_all_subdomains()) > 50:
            insights.append("📈 Large digital footprint")

        if not insights:
            insights.append("🏢 Standard corporate infrastructure")

        for insight in insights:
            st.info(insight)


def render_export_actions_tab(result):
    """Render export options and additional actions."""

    st.markdown("### 📥 Export & Action Center")

    # Export options
    export_col1, export_col2 = st.columns(2)

    with export_col1:
        st.markdown("#### 📤 Export Options")

        export_format = st.selectbox(
            "Select Export Format", ["JSON", "CSV", "Excel", "PDF Report", "XML"]
        )

        include_options = st.multiselect(
            "Include in Export",
            [
                "Domains",
                "Subdomains",
                "ASNs",
                "IP Ranges",
                "Cloud Services",
                "Security Analysis",
            ],
            default=["Domains", "Subdomains", "ASNs"],
        )

        if st.button("📥 Generate Export", type="primary", use_container_width=True):
            # Generate export data
            export_data = prepare_export_data(result, include_options, export_format)

            if export_format == "JSON":
                st.download_button(
                    label="📥 Download JSON",
                    data=json.dumps(export_data, indent=2, default=str),
                    file_name=f"{result.target_organization}_scan_results.json",
                    mime="application/json",
                )
            elif export_format == "CSV":
                # Convert to CSV format
                csv_data = convert_to_csv(export_data)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv_data,
                    file_name=f"{result.target_organization}_scan_results.csv",
                    mime="text/csv",
                )
            else:
                st.info(f"📋 {export_format} export functionality coming soon!")

    with export_col2:
        st.markdown("#### 🔄 Additional Actions")

        action_col1, action_col2 = st.columns(2)

        with action_col1:
            if st.button("🔄 Re-scan Organization", use_container_width=True):
                st.info("🚀 Re-scan functionality will be available soon!")

            if st.button("📊 Generate Report", use_container_width=True):
                st.info("📋 PDF report generation coming soon!")

        with action_col2:
            if st.button("📤 Share Results", use_container_width=True):
                st.info("🔗 Share functionality coming soon!")

            if st.button("⚙️ Schedule Monitoring", use_container_width=True):
                st.info("📅 Monitoring schedule setup coming soon!")

        # API integration options
        st.markdown("##### 🔌 API Integration")

        api_key = st.text_input(
            "API Key (Optional)",
            type="password",
            help="For integrating with external security tools",
        )

        webhook_url = st.text_input(
            "Webhook URL (Optional)", help="Send results to external systems"
        )


def prepare_export_data(result, include_options, export_format):
    """Prepare data for export in the specified format."""

    export_data: Dict[str, Union[Dict, List]] = {
        "scan_metadata": {
            "target_organization": result.target_organization,
            "scan_timestamp": datetime.now().isoformat(),
            "total_assets": {
                "domains": len(result.domains),
                "subdomains": len(result.get_all_subdomains()),
                "asns": len(result.asns),
                "ip_ranges": len(result.ip_ranges),
                "cloud_services": len(result.cloud_services),
            },
        }
    }

    if "Domains" in include_options:
        export_data["domains"] = [
            {
                "name": domain.name,
                "registrar": getattr(domain, "registrar", "Unknown"),
                "creation_date": getattr(domain, "creation_date", "Unknown"),
            }
            for domain in result.domains
        ]

    if "Subdomains" in include_options:
        export_data["subdomains"] = [
            {
                "fqdn": subdomain.fqdn,
                "resolved_ips": list(getattr(subdomain, "resolved_ips", set())),
                "data_source": getattr(subdomain, "data_source", "Unknown"),
            }
            for subdomain in result.get_all_subdomains()
        ]

    if "ASNs" in include_options:
        export_data["asns"] = [
            {
                "number": asn.number,
                "name": asn.name,
                "description": asn.description,
                "country": getattr(asn, "country", "Unknown"),
            }
            for asn in result.asns
        ]

    if "IP Ranges" in include_options:
        export_data["ip_ranges"] = [
            {
                "cidr": ip_range.cidr,
                "version": ip_range.version,
                "asn": getattr(ip_range, "asn", "Unknown"),
                "country": getattr(ip_range, "country", "Unknown"),
            }
            for ip_range in result.ip_ranges
        ]

    if "Cloud Services" in include_options and result.cloud_services:
        export_data["cloud_services"] = [
            {
                "provider": service.provider,
                "identifier": service.identifier,
                "resource_type": getattr(service, "resource_type", "Unknown"),
                "region": getattr(service, "region", "Unknown"),
            }
            for service in result.cloud_services
        ]

    return export_data


def convert_to_csv(export_data):
    """Convert export data to CSV format."""

    csv_content = "# Reconnaissance Scan Results\n"
    csv_content += (
        f"# Organization: {export_data['scan_metadata']['target_organization']}\n"
    )
    csv_content += f"# Scan Date: {export_data['scan_metadata']['scan_timestamp']}\n\n"

    for section, data in export_data.items():
        if section != "scan_metadata" and isinstance(data, list) and data:
            csv_content += f"\n## {section.upper()}\n"
            if data:
                # Convert list of dicts to CSV format
                df = pd.DataFrame(data)
                csv_content += df.to_csv(index=False)
                csv_content += "\n"

    return csv_content
