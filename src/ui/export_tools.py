"""
Professional export tools interface for ReconForge.
"""

import streamlit as st
import json
import csv
import io
import zipfile
from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd

from src.core.models import ReconnaissanceResult
from src.utils.formatting import format_file_timestamp

def render_export_tools(scan_results: ReconnaissanceResult, scan_id: Optional[int] = None):
    """Render the professional export tools interface."""
    
    if not scan_results:
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">📤 Export Center</div>
            <p style="color: var(--text-secondary);">No scan results available for export.</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    st.markdown("""
    <div class="custom-card animate-fade-in">
        <div class="card-title">📤 Export Center</div>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
            Export reconnaissance data in multiple formats for analysis, reporting, and integration.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Export options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        render_json_export(scan_results, scan_id)
    
    with col2:
        render_csv_export(scan_results, scan_id)
    
    with col3:
        render_specialized_exports(scan_results, scan_id)
    
    # Advanced export options
    st.markdown("---")
    
    # Bulk export
    render_bulk_export_options(scan_results, scan_id)
    
    # Export statistics
    render_export_statistics(scan_results)

def render_json_export(scan_results: ReconnaissanceResult, scan_id: Optional[int]):
    """Render JSON export options."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📋 JSON Export</div>
        <p style="color: var(--text-secondary); font-size: 0.9rem;">
            Complete data export in JSON format
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # JSON export options
    include_metadata = st.checkbox("Include Metadata", value=True, key="json_metadata")
    pretty_format = st.checkbox("Pretty Format", value=True, key="json_pretty")
    minify_json = st.checkbox("Minified Output", value=False, key="json_minify")
    
    if st.button("📥 Download JSON", use_container_width=True, key="export_json"):
        json_data = generate_json_export(scan_results, scan_id, include_metadata, pretty_format, minify_json)
        timestamp = format_file_timestamp(datetime.now())
        filename = f"recon_results_{scan_results.target_organization}_{timestamp}.json"
        
        st.download_button(
            label="📥 Download JSON File",
            data=json_data,
            file_name=filename,
            mime="application/json",
            use_container_width=True
        )

def render_csv_export(scan_results: ReconnaissanceResult, scan_id: Optional[int]):
    """Render CSV export options."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📊 CSV Export</div>
        <p style="color: var(--text-secondary); font-size: 0.9rem;">
            Structured data for spreadsheet analysis
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # CSV export options
    csv_format = st.selectbox(
        "CSV Format",
        ["Separate Files", "Single File", "Excel Workbook"],
        key="csv_format"
    )
    
    include_headers = st.checkbox("Include Headers", value=True, key="csv_headers")
    delimiter = st.selectbox("Delimiter", [",", ";", "\t"], key="csv_delimiter")
    
    if st.button("📥 Download CSV", use_container_width=True, key="export_csv"):
        
        if csv_format == "Separate Files":
            csv_zip = generate_csv_export_zip(scan_results, scan_id, include_headers, delimiter)
            timestamp = format_file_timestamp(datetime.now())
            filename = f"recon_csv_{scan_results.target_organization}_{timestamp}.zip"
            
            st.download_button(
                label="📥 Download CSV Archive",
                data=csv_zip,
                file_name=filename,
                mime="application/zip",
                use_container_width=True
            )
        
        elif csv_format == "Excel Workbook":
            excel_data = generate_excel_export(scan_results, scan_id)
            timestamp = format_file_timestamp(datetime.now())
            filename = f"recon_results_{scan_results.target_organization}_{timestamp}.xlsx"
            
            st.download_button(
                label="📥 Download Excel File",
                data=excel_data,
                file_name=filename,
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )

def render_specialized_exports(scan_results: ReconnaissanceResult, scan_id: Optional[int]):
    """Render specialized export formats."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">🎯 Specialized Exports</div>
        <p style="color: var(--text-secondary); font-size: 0.9rem;">
            Purpose-built formats for specific tools
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    export_type = st.selectbox(
        "Export Type",
        ["Domain List", "IP Ranges", "ASN List", "Nmap Targets", "Nuclei Targets"],
        key="specialized_type"
    )
    
    if st.button("📥 Generate Export", use_container_width=True, key="export_specialized"):
        
        data, filename, mime_type = generate_specialized_export(scan_results, export_type)
        
        if data:
            timestamp = format_file_timestamp(datetime.now())
            full_filename = f"{filename}_{scan_results.target_organization}_{timestamp}.txt"
            
            st.download_button(
                label=f"📥 Download {export_type}",
                data=data,
                file_name=full_filename,
                mime=mime_type,
                use_container_width=True
            )

def render_bulk_export_options(scan_results: ReconnaissanceResult, scan_id: Optional[int]):
    """Render bulk export options."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📦 Bulk Export</div>
        <p style="color: var(--text-secondary);">
            Complete intelligence package with all data formats and documentation.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        include_formats = st.multiselect(
            "Include Formats",
            ["JSON", "CSV", "Excel", "Domain Lists", "IP Lists", "Report"],
            default=["JSON", "CSV", "Report"],
            key="bulk_formats"
        )
    
    with col2:
        include_extras = st.multiselect(
            "Additional Items",
            ["Scan Metadata", "Configuration", "Timeline", "Statistics"],
            default=["Scan Metadata", "Statistics"],
            key="bulk_extras"
        )
    
    compression_level = st.slider(
        "Compression Level",
        min_value=1,
        max_value=9,
        value=6,
        help="Higher values = smaller files, longer processing time"
    )
    
    if st.button("📦 Generate Complete Export Package", type="primary", use_container_width=True):
        
        with st.spinner("Generating comprehensive export package..."):
            bulk_package = generate_bulk_export(
                scan_results, scan_id, include_formats, include_extras, compression_level
            )
            
            timestamp = format_file_timestamp(datetime.now())
            filename = f"recon_intelligence_package_{scan_results.target_organization}_{timestamp}.zip"
            
            st.download_button(
                label="📥 Download Intelligence Package",
                data=bulk_package,
                file_name=filename,
                mime="application/zip",
                use_container_width=True
            )

def render_export_statistics(scan_results: ReconnaissanceResult):
    """Render export statistics and data summary."""
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📊 Data Summary</div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_subdomains = sum(len(d.subdomains) for d in scan_results.domains)
    
    with col1:
        st.metric("Domains", len(scan_results.domains))
    with col2:
        st.metric("Subdomains", total_subdomains)
    with col3:
        st.metric("ASNs", len(scan_results.asns))
    with col4:
        st.metric("IP Ranges", len(scan_results.ip_ranges))
    
    # Data breakdown
    with st.expander("📋 Detailed Breakdown"):
        
        breakdown_data = {
            "Category": [],
            "Count": [],
            "Size Estimate": []
        }
        
        categories = [
            ("Base Domains", len(scan_results.domains), f"{len(scan_results.domains) * 100} bytes"),
            ("Subdomains", total_subdomains, f"{total_subdomains * 150} bytes"),
            ("ASNs", len(scan_results.asns), f"{len(scan_results.asns) * 200} bytes"),
            ("IP Ranges", len(scan_results.ip_ranges), f"{len(scan_results.ip_ranges) * 50} bytes"),
            ("Cloud Services", len(scan_results.cloud_services), f"{len(scan_results.cloud_services) * 100} bytes"),
            ("Warnings", len(scan_results.warnings), f"{len(scan_results.warnings) * 80} bytes")
        ]
        
        for category, count, size in categories:
            breakdown_data["Category"].append(category)
            breakdown_data["Count"].append(count)
            breakdown_data["Size Estimate"].append(size)
        
        df = pd.DataFrame(breakdown_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

def generate_json_export(scan_results: ReconnaissanceResult, scan_id: Optional[int], 
                        include_metadata: bool, pretty_format: bool, minify_json: bool) -> str:
    """Generate JSON export data."""
    
    # Convert scan results to dictionary
    export_data = {
        "target_organization": scan_results.target_organization,
        "scan_timestamp": datetime.now().isoformat(),
        "domains": [],
        "asns": [],
        "ip_ranges": [],
        "cloud_services": [],
        "warnings": scan_results.warnings
    }
    
    # Add scan metadata if requested
    if include_metadata and scan_id:
        export_data["metadata"] = {
            "scan_id": scan_id,
            "export_timestamp": datetime.now().isoformat(),
            "format_version": "2.0",
            "tool": "ReconForge Professional"
        }
    
    # Convert domains
    for domain in scan_results.domains:
        domain_data = {
            "name": domain.name,
            "registrar": domain.registrar,
            "creation_date": domain.creation_date.isoformat() if domain.creation_date else None,
            "data_source": domain.data_source,
            "subdomains": []
        }
        
        for subdomain in domain.subdomains:
            subdomain_data = {
                "fqdn": subdomain.fqdn,
                "status": subdomain.status,
                "resolved_ips": list(subdomain.resolved_ips) if subdomain.resolved_ips else [],
                "data_source": subdomain.data_source,
                "last_checked": subdomain.last_checked.isoformat() if subdomain.last_checked else None
            }
            domain_data["subdomains"].append(subdomain_data)
        
        export_data["domains"].append(domain_data)
    
    # Convert ASNs
    for asn in scan_results.asns:
        asn_data = {
            "number": asn.number,
            "name": asn.name,
            "description": asn.description,
            "country": asn.country,
            "data_source": asn.data_source
        }
        export_data["asns"].append(asn_data)
    
    # Convert IP ranges
    for ip_range in scan_results.ip_ranges:
        ip_data = {
            "cidr": ip_range.cidr,
            "version": ip_range.version,
            "asn": ip_range.asn.number if ip_range.asn else None,
            "country": ip_range.country,
            "data_source": ip_range.data_source
        }
        export_data["ip_ranges"].append(ip_data)
    
    # Convert cloud services
    for service in scan_results.cloud_services:
        service_data = {
            "provider": service.provider,
            "identifier": service.identifier,
            "resource_type": service.resource_type,
            "region": service.region,
            "status": service.status,
            "data_source": service.data_source
        }
        export_data["cloud_services"].append(service_data)
    
    # Format JSON output
    if minify_json:
        return json.dumps(export_data, separators=(',', ':'))
    elif pretty_format:
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    else:
        return json.dumps(export_data)

def generate_csv_export_zip(scan_results: ReconnaissanceResult, scan_id: Optional[int],
                           include_headers: bool, delimiter: str) -> bytes:
    """Generate ZIP file with separate CSV files."""
    
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        
        # Domains CSV
        if scan_results.domains:
            domains_csv = generate_domains_csv(scan_results.domains, include_headers, delimiter)
            zip_file.writestr("domains.csv", domains_csv)
        
        # Subdomains CSV
        subdomains_csv = generate_subdomains_csv(scan_results.domains, include_headers, delimiter)
        if subdomains_csv:
            zip_file.writestr("subdomains.csv", subdomains_csv)
        
        # ASNs CSV
        if scan_results.asns:
            asns_csv = generate_asns_csv(scan_results.asns, include_headers, delimiter)
            zip_file.writestr("asns.csv", asns_csv)
        
        # IP Ranges CSV
        if scan_results.ip_ranges:
            ip_ranges_csv = generate_ip_ranges_csv(scan_results.ip_ranges, include_headers, delimiter)
            zip_file.writestr("ip_ranges.csv", ip_ranges_csv)
        
        # Cloud Services CSV
        if scan_results.cloud_services:
            cloud_csv = generate_cloud_services_csv(scan_results.cloud_services, include_headers, delimiter)
            zip_file.writestr("cloud_services.csv", cloud_csv)
    
    zip_buffer.seek(0)
    return zip_buffer.read()

def generate_excel_export(scan_results: ReconnaissanceResult, scan_id: Optional[int]) -> bytes:
    """Generate Excel workbook with multiple sheets."""
    
    output = io.BytesIO()
    
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        
        # Overview sheet
        overview_data = {
            "Metric": ["Target Organization", "Total Domains", "Total Subdomains", "Total ASNs", "Total IP Ranges", "Total Cloud Services"],
            "Value": [
                scan_results.target_organization,
                len(scan_results.domains),
                sum(len(d.subdomains) for d in scan_results.domains),
                len(scan_results.asns),
                len(scan_results.ip_ranges),
                len(scan_results.cloud_services)
            ]
        }
        pd.DataFrame(overview_data).to_excel(writer, sheet_name="Overview", index=False)
        
        # Domains sheet
        if scan_results.domains:
            domains_data = []
            for domain in scan_results.domains:
                domains_data.append({
                    "Domain": domain.name,
                    "Registrar": domain.registrar,
                    "Creation Date": domain.creation_date.strftime('%Y-%m-%d') if domain.creation_date else '',
                    "Subdomains Count": len(domain.subdomains),
                    "Data Source": domain.data_source
                })
            pd.DataFrame(domains_data).to_excel(writer, sheet_name="Domains", index=False)
        
        # ASNs sheet
        if scan_results.asns:
            asns_data = []
            for asn in scan_results.asns:
                asns_data.append({
                    "ASN": f"AS{asn.number}",
                    "Name": asn.name,
                    "Description": asn.description,
                    "Country": asn.country,
                    "Data Source": asn.data_source
                })
            pd.DataFrame(asns_data).to_excel(writer, sheet_name="ASNs", index=False)
    
    output.seek(0)
    return output.read()

def generate_specialized_export(scan_results: ReconnaissanceResult, export_type: str) -> tuple:
    """Generate specialized export format."""
    
    if export_type == "Domain List":
        domains = [domain.name for domain in scan_results.domains]
        subdomains = []
        for domain in scan_results.domains:
            subdomains.extend([sub.fqdn for sub in domain.subdomains])
        
        all_domains = sorted(set(domains + subdomains))
        data = "\n".join(all_domains)
        return data, "domains", "text/plain"
    
    elif export_type == "IP Ranges":
        ip_ranges = [ip_range.cidr for ip_range in scan_results.ip_ranges]
        data = "\n".join(sorted(ip_ranges))
        return data, "ip_ranges", "text/plain"
    
    elif export_type == "ASN List":
        asns = [f"AS{asn.number}" for asn in scan_results.asns]
        data = "\n".join(sorted(asns))
        return data, "asns", "text/plain"
    
    elif export_type == "Nmap Targets":
        targets = []
        targets.extend([ip_range.cidr for ip_range in scan_results.ip_ranges])
        for domain in scan_results.domains:
            targets.extend([sub.fqdn for sub in domain.subdomains if sub.resolved_ips])
        data = "\n".join(sorted(set(targets)))
        return data, "nmap_targets", "text/plain"
    
    elif export_type == "Nuclei Targets":
        targets = []
        for domain in scan_results.domains:
            targets.append(f"https://{domain.name}")
            targets.append(f"http://{domain.name}")
            for subdomain in domain.subdomains:
                targets.append(f"https://{subdomain.fqdn}")
                targets.append(f"http://{subdomain.fqdn}")
        data = "\n".join(sorted(set(targets)))
        return data, "nuclei_targets", "text/plain"
    
    return "", "unknown", "text/plain"

def generate_bulk_export(scan_results: ReconnaissanceResult, scan_id: Optional[int],
                        include_formats: List[str], include_extras: List[str],
                        compression_level: int) -> bytes:
    """Generate comprehensive export package."""
    
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=compression_level) as zip_file:
        
        # JSON export
        if "JSON" in include_formats:
            json_data = generate_json_export(scan_results, scan_id, True, True, False)
            zip_file.writestr("data/complete_results.json", json_data)
        
        # CSV exports
        if "CSV" in include_formats:
            csv_zip_data = generate_csv_export_zip(scan_results, scan_id, True, ",")
            # Extract CSV files from zip and add to main package
            with zipfile.ZipFile(io.BytesIO(csv_zip_data)) as csv_zip:
                for file_info in csv_zip.filelist:
                    zip_file.writestr(f"csv/{file_info.filename}", csv_zip.read(file_info))
        
        # Excel export
        if "Excel" in include_formats:
            excel_data = generate_excel_export(scan_results, scan_id)
            zip_file.writestr("data/complete_results.xlsx", excel_data)
        
        # Specialized exports
        if "Domain Lists" in include_formats:
            for export_type in ["Domain List", "IP Ranges", "ASN List"]:
                data, filename, _ = generate_specialized_export(scan_results, export_type)
                if data:
                    zip_file.writestr(f"lists/{filename}.txt", data)
        
        # Report generation
        if "Report" in include_formats:
            report_html = generate_html_report(scan_results, scan_id)
            zip_file.writestr("report/reconnaissance_report.html", report_html)
        
        # Metadata and extras
        if "Scan Metadata" in include_extras:
            metadata = {
                "scan_info": {
                    "target": scan_results.target_organization,
                    "scan_id": scan_id,
                    "export_timestamp": datetime.now().isoformat(),
                    "tool_version": "ReconForge Professional 2.0"
                },
                "statistics": {
                    "domains": len(scan_results.domains),
                    "subdomains": sum(len(d.subdomains) for d in scan_results.domains),
                    "asns": len(scan_results.asns),
                    "ip_ranges": len(scan_results.ip_ranges),
                    "cloud_services": len(scan_results.cloud_services),
                    "warnings": len(scan_results.warnings)
                }
            }
            zip_file.writestr("metadata/scan_metadata.json", json.dumps(metadata, indent=2))
    
    zip_buffer.seek(0)
    return zip_buffer.read()

def generate_domains_csv(domains, include_headers: bool, delimiter: str) -> str:
    """Generate CSV data for domains."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter)
    
    if include_headers:
        writer.writerow(["Domain", "Registrar", "Creation Date", "Subdomains Count", "Data Source"])
    
    for domain in domains:
        writer.writerow([
            domain.name,
            domain.registrar or "",
            domain.creation_date.strftime('%Y-%m-%d') if domain.creation_date else "",
            len(domain.subdomains),
            domain.data_source or ""
        ])
    
    return output.getvalue()

def generate_subdomains_csv(domains, include_headers: bool, delimiter: str) -> str:
    """Generate CSV data for subdomains."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter)
    
    if include_headers:
        writer.writerow(["Parent Domain", "FQDN", "Status", "Resolved IPs", "Data Source", "Last Checked"])
    
    for domain in domains:
        for subdomain in domain.subdomains:
            writer.writerow([
                domain.name,
                subdomain.fqdn,
                subdomain.status or "",
                ", ".join(subdomain.resolved_ips) if subdomain.resolved_ips else "",
                subdomain.data_source or "",
                subdomain.last_checked.strftime('%Y-%m-%d %H:%M') if subdomain.last_checked else ""
            ])
    
    return output.getvalue()

def generate_asns_csv(asns, include_headers: bool, delimiter: str) -> str:
    """Generate CSV data for ASNs."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter)
    
    if include_headers:
        writer.writerow(["ASN", "Name", "Description", "Country", "Data Source"])
    
    for asn in asns:
        writer.writerow([
            f"AS{asn.number}",
            asn.name or "",
            asn.description or "",
            asn.country or "",
            asn.data_source or ""
        ])
    
    return output.getvalue()

def generate_ip_ranges_csv(ip_ranges, include_headers: bool, delimiter: str) -> str:
    """Generate CSV data for IP ranges."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter)
    
    if include_headers:
        writer.writerow(["CIDR", "Version", "ASN", "Country", "Data Source"])
    
    for ip_range in ip_ranges:
        writer.writerow([
            ip_range.cidr,
            f"IPv{ip_range.version}" if ip_range.version else "",
            f"AS{ip_range.asn.number}" if ip_range.asn else "",
            ip_range.country or "",
            ip_range.data_source or ""
        ])
    
    return output.getvalue()

def generate_cloud_services_csv(cloud_services, include_headers: bool, delimiter: str) -> str:
    """Generate CSV data for cloud services."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=delimiter)
    
    if include_headers:
        writer.writerow(["Provider", "Identifier", "Resource Type", "Region", "Status", "Data Source"])
    
    for service in cloud_services:
        writer.writerow([
            service.provider,
            service.identifier,
            service.resource_type or "",
            service.region or "",
            service.status or "",
            service.data_source or ""
        ])
    
    return output.getvalue()

def generate_html_report(scan_results: ReconnaissanceResult, scan_id: Optional[int]) -> str:
    """Generate HTML report."""
    
    total_subdomains = sum(len(d.subdomains) for d in scan_results.domains)
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReconForge Intelligence Report - {scan_results.target_organization}</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }}
            .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 8px; text-align: center; }}
            .metric-value {{ font-size: 24px; font-weight: bold; color: #667eea; }}
            .metric-label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; font-weight: 600; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎯 ReconForge Intelligence Report</h1>
            <h2>{scan_results.target_organization}</h2>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h3>📊 Executive Summary</h3>
            <div class="metric">
                <div class="metric-value">{len(scan_results.domains)}</div>
                <div class="metric-label">Domains</div>
            </div>
            <div class="metric">
                <div class="metric-value">{total_subdomains}</div>
                <div class="metric-label">Subdomains</div>
            </div>
            <div class="metric">
                <div class="metric-value">{len(scan_results.asns)}</div>
                <div class="metric-label">ASNs</div>
            </div>
            <div class="metric">
                <div class="metric-value">{len(scan_results.ip_ranges)}</div>
                <div class="metric-label">IP Ranges</div>
            </div>
            <div class="metric">
                <div class="metric-value">{len(scan_results.cloud_services)}</div>
                <div class="metric-label">Cloud Services</div>
            </div>
        </div>
        
        <div class="section">
            <h3>🔗 Domain Intelligence</h3>
            <table>
                <tr><th>Domain</th><th>Registrar</th><th>Subdomains</th><th>Data Source</th></tr>
    """
    
    # Add domain rows
    for domain in scan_results.domains:
        html_template += f"""
                <tr>
                    <td>{domain.name}</td>
                    <td>{domain.registrar or 'Unknown'}</td>
                    <td>{len(domain.subdomains)}</td>
                    <td>{domain.data_source or 'Unknown'}</td>
                </tr>
        """
    
    html_template += """
            </table>
        </div>
        
        <div class="section">
            <h3>🏢 Autonomous Systems</h3>
            <table>
                <tr><th>ASN</th><th>Name</th><th>Country</th><th>Description</th></tr>
    """
    
    # Add ASN rows
    for asn in scan_results.asns:
        html_template += f"""
                <tr>
                    <td>AS{asn.number}</td>
                    <td>{asn.name or 'Unknown'}</td>
                    <td>{asn.country or 'Unknown'}</td>
                    <td>{asn.description or 'No description'}</td>
                </tr>
        """
    
    html_template += """
            </table>
        </div>
        
        <div class="section">
            <p style="text-align: center; color: #666; font-size: 14px;">
                Report generated by ReconForge Professional 2.0<br>
                Enterprise Asset Intelligence & Discovery Platform
            </p>
        </div>
    </body>
    </html>
    """
    
    return html_template 