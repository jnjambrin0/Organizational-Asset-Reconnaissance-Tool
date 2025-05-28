"""
Results display components for ReconForge Streamlit application.
"""

import streamlit as st
from typing import Optional
from src.core.models import ReconnaissanceResult

def render_results_display(result: ReconnaissanceResult, scan_id: Optional[int] = None):
    """
    Render comprehensive results display for a reconnaissance scan.
    
    Args:
        result: The ReconnaissanceResult object to display
        scan_id: Optional scan ID for reference
    """
    
    if not result:
        st.warning("No results to display")
        return
    
    # Results header
    st.markdown(f"### 🎯 Results for: {result.target_organization}")
    
    if scan_id:
        st.caption(f"Scan ID: {scan_id}")
    
    # Summary metrics
    total_subdomains = sum(len(d.subdomains) for d in result.domains)
    total_assets = len(result.asns) + len(result.ip_ranges) + len(result.domains) + total_subdomains + len(result.cloud_services)
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("🏢 ASNs", len(result.asns))
    
    with col2:
        st.metric("🌐 Domains", len(result.domains))
    
    with col3:
        st.metric("🔗 Subdomains", total_subdomains)
    
    with col4:
        st.metric("📡 IP Ranges", len(result.ip_ranges))
    
    with col5:
        st.metric("☁️ Cloud Services", len(result.cloud_services))
    
    # Detailed results tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🏢 ASNs", 
        "🌐 Domains", 
        "📡 IP Ranges", 
        "☁️ Cloud Services", 
        "⚠️ Warnings"
    ])
    
    with tab1:
        render_asns(result.asns)
    
    with tab2:
        render_domains(result.domains)
    
    with tab3:
        render_ip_ranges(result.ip_ranges)
    
    with tab4:
        render_cloud_services(result.cloud_services)
    
    with tab5:
        render_warnings(result.warnings)

def render_asns(asns):
    """Render ASN results."""
    
    if not asns:
        st.info("No ASNs discovered")
        return
    
    st.markdown(f"**{len(asns)} Autonomous Systems discovered:**")
    
    for asn in sorted(asns, key=lambda x: x.number):
        with st.expander(f"AS{asn.number} - {asn.name or 'Unknown'}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Number:** AS{asn.number}")
                st.write(f"**Name:** {asn.name or 'N/A'}")
                st.write(f"**Country:** {asn.country or 'N/A'}")
            
            with col2:
                st.write(f"**Description:** {asn.description or 'N/A'}")
                st.write(f"**Data Source:** {asn.data_source or 'N/A'}")

def render_domains(domains):
    """Render domain results."""
    
    if not domains:
        st.info("No domains discovered")
        return
    
    st.markdown(f"**{len(domains)} domains discovered:**")
    
    for domain in sorted(domains, key=lambda x: x.name):
        subdomain_count = len(domain.subdomains)
        
        with st.expander(f"🌐 {domain.name} ({subdomain_count} subdomains)"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Domain:** {domain.name}")
                st.write(f"**Registrar:** {domain.registrar or 'N/A'}")
                st.write(f"**Creation Date:** {domain.creation_date or 'N/A'}")
            
            with col2:
                st.write(f"**Data Source:** {domain.data_source or 'N/A'}")
                st.write(f"**Subdomains:** {subdomain_count}")
            
            if domain.subdomains:
                st.markdown("**Subdomains:**")
                subdomain_data = []
                
                for subdomain in sorted(domain.subdomains, key=lambda x: x.fqdn):
                    ips_str = ", ".join(subdomain.resolved_ips) if subdomain.resolved_ips else "N/A"
                    subdomain_data.append({
                        "FQDN": subdomain.fqdn,
                        "Status": subdomain.status or "N/A",
                        "Resolved IPs": ips_str,
                        "Last Checked": subdomain.last_checked or "N/A"
                    })
                
                if subdomain_data:
                    st.dataframe(subdomain_data, use_container_width=True)

def render_ip_ranges(ip_ranges):
    """Render IP range results."""
    
    if not ip_ranges:
        st.info("No IP ranges discovered")
        return
    
    st.markdown(f"**{len(ip_ranges)} IP ranges discovered:**")
    
    # Create table data
    ip_data = []
    for ip_range in sorted(ip_ranges, key=lambda x: x.cidr):
        asn_info = f"AS{ip_range.asn.number}" if ip_range.asn else "N/A"
        
        ip_data.append({
            "CIDR": ip_range.cidr,
            "Version": f"IPv{ip_range.version}" if ip_range.version else "N/A",
            "ASN": asn_info,
            "Country": ip_range.country or "N/A",
            "Data Source": ip_range.data_source or "N/A"
        })
    
    if ip_data:
        st.dataframe(ip_data, use_container_width=True)

def render_cloud_services(cloud_services):
    """Render cloud service results."""
    
    if not cloud_services:
        st.info("No cloud services detected")
        return
    
    st.markdown(f"**{len(cloud_services)} cloud services detected:**")
    
    # Group by provider
    providers = {}
    for service in cloud_services:
        provider = service.provider
        if provider not in providers:
            providers[provider] = []
        providers[provider].append(service)
    
    for provider, services in providers.items():
        with st.expander(f"☁️ {provider} ({len(services)} services)"):
            service_data = []
            
            for service in services:
                service_data.append({
                    "Identifier": service.identifier,
                    "Resource Type": service.resource_type or "N/A",
                    "Region": service.region or "N/A",
                    "Status": service.status or "N/A",
                    "Data Source": service.data_source or "N/A"
                })
            
            if service_data:
                st.dataframe(service_data, use_container_width=True)

def render_warnings(warnings):
    """Render warnings from the scan."""
    
    if not warnings:
        st.success("No warnings - scan completed successfully!")
        return
    
    st.markdown(f"**{len(warnings)} warnings encountered:**")
    
    for i, warning in enumerate(warnings, 1):
        st.warning(f"**Warning {i}:** {warning}") 