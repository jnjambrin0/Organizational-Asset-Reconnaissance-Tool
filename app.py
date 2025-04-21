import streamlit as st
import pandas as pd
import time
import base64
import os
from modules.asn_finder import ASNFinder
from modules.ip_analyzer import IPAnalyzer
from modules.domain_enum import DomainEnumerator
from modules.report_gen import ReportGenerator

# Set page config
st.set_page_config(
    page_title="Organizational Asset Reconnaissance Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    # Custom CSS
    st.markdown("""
    <style>
        .main-header {
            font-size: 2.5rem;
            color: #1E3A8A;
            margin-bottom: 1rem;
        }
        .sub-header {
            font-size: 1.5rem;
            color: #3B82F6;
            margin-bottom: 1rem;
        }
        .stProgress > div > div > div > div {
            background-color: #3B82F6;
        }
        .highlight {
            background-color: #F0F9FF;
            padding: 10px;
            border-radius: 5px;
            border-left: 5px solid #3B82F6;
        }
        .warning {
            background-color: #FFFBEB;
            padding: 10px;
            border-radius: 5px;
            border-left: 5px solid #F59E0B;
        }
        .info-card {
            background-color: #F8FAFC;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<h1 class="main-header">Organizational Asset Reconnaissance Tool</h1>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown('<h2 class="sub-header">Configuration</h2>', unsafe_allow_html=True)
        
        # Organization name input
        org_name = st.text_input("Organization Name (required)", help="Enter the name of the organization you want to analyze")
        
        # Base domains input
        st.markdown("### Base Domains (optional)")
        st.markdown("Enter one domain per line. If left empty, the tool will attempt to discover domains related to the organization.")
        base_domains = st.text_area("Base Domains")
        
        # Parse base domains
        if base_domains:
            base_domains = [domain.strip() for domain in base_domains.split('\n') if domain.strip()]
        else:
            base_domains = []
        
        # Advanced options
        st.markdown("### Advanced Options")
        
        max_subdomains = st.slider("Max subdomains per domain", 10, 1000, 100, help="Limit the number of subdomains to process")
        
        # Start reconnaissance button
        start_recon = st.button("Start Reconnaissance", type="primary")
        
        st.markdown("---")
        st.markdown("### About")
        st.markdown("""
        This tool automates the process of identifying digital assets belonging to an organization:
        - Autonomous Systems (ASNs)
        - IP Ranges
        - External IP Addresses
        - Cloud Providers
        - Domains and Subdomains
        """)
    
    # Main content area
    if not start_recon:
        # Show welcome message when not running reconnaissance
        st.markdown('<div class="info-card">', unsafe_allow_html=True)
        st.markdown("## Welcome to the Organizational Asset Reconnaissance Tool")
        st.markdown("""
        This tool is designed to help you discover digital assets belonging to an organization.
        
        ### Features:
        - Discover Autonomous Systems (ASNs)
        - Identify IP Ranges
        - Enumerate External IP Addresses
        - Detect Cloud Providers
        - Find Domains and Subdomains
        
        ### How to use:
        1. Enter the organization name in the sidebar (required)
        2. Optionally, provide one or more base domains
        3. Click "Start Reconnaissance" to begin the analysis
        4. The results will be displayed and can be exported in various formats
        
        ### Use cases:
        - Security assessments
        - Attack surface mapping
        - Digital footprint analysis
        - Open-source intelligence gathering
        """)
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Display sample visualization
        st.markdown('<div class="info-card">', unsafe_allow_html=True)
        st.markdown("## Sample Output")
        st.image("https://miro.medium.com/max/1400/1*0jrqkgFv3U738ndp_35k9A.png", caption="Example of a network topology visualization")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Run reconnaissance if the button is clicked and org_name is provided
    if start_recon:
        if not org_name:
            st.error("Organization name is required. Please enter an organization name in the sidebar.")
        else:
            # Initialize results container
            if 'results' not in st.session_state:
                st.session_state.results = {}
            
            # Create tabs for different sections of the reconnaissance
            tabs = st.tabs(["Process", "ASNs & IP Ranges", "Domains & Subdomains", "Visualizations", "Reports"])
            
            with tabs[0]:
                st.markdown('<h2 class="sub-header">Reconnaissance Process</h2>', unsafe_allow_html=True)
                
                # Initialize modules
                asn_finder = ASNFinder()
                ip_analyzer = IPAnalyzer()
                domain_enumerator = DomainEnumerator()
                report_generator = ReportGenerator()
                
                # Main progress bar
                main_progress = st.progress(0, text="Starting reconnaissance...")
                
                # Step 1: Find ASNs
                st.markdown("### Step 1: Finding Autonomous Systems (ASNs)")
                asn_progress = st.empty()
                asn_progress.info("Searching for ASNs associated with the organization...")
                
                asns = asn_finder.find_asns_by_org(org_name)
                
                if asns:
                    asn_progress.success(f"Found {len(asns)} ASNs associated with {org_name}")
                else:
                    asn_progress.warning(f"No ASNs found for {org_name}")
                
                st.session_state.results['asns'] = asns
                main_progress.progress(0.2, text="ASN discovery completed")
                
                # Step 2: Get IP ranges for each ASN
                st.markdown("### Step 2: Finding IP Ranges")
                ip_ranges_progress = st.empty()
                ip_ranges_container = st.container()
                
                if asns:
                    ip_ranges_progress.info("Finding IP ranges for the discovered ASNs...")
                    
                    ip_ranges = []
                    for i, asn in enumerate(asns):
                        ip_ranges_container.text(f"Processing ASN {asn['ASN']} ({i+1}/{len(asns)})...")
                        asn_ranges = asn_finder.get_ip_ranges_for_asn(asn['ASN'])
                        ip_ranges.extend(asn_ranges)
                    
                    if ip_ranges:
                        ip_ranges_progress.success(f"Found {len(ip_ranges)} IP ranges")
                    else:
                        ip_ranges_progress.warning("No IP ranges found for the discovered ASNs")
                else:
                    ip_ranges_progress.info("Skipping IP range discovery as no ASNs were found")
                    ip_ranges = []
                
                st.session_state.results['ip_ranges'] = ip_ranges
                main_progress.progress(0.4, text="IP range discovery completed")
                
                # Step 3: Enumerate domains and subdomains
                st.markdown("### Step 3: Enumerating Domains and Subdomains")
                domain_progress = st.empty()
                domain_progress.info("Starting domain and subdomain enumeration...")
                
                # Create a progress bar for domain enumeration
                domains_progress_bar = st.progress(0, text="Processing domains...")
                
                # Enumerate domains and subdomains
                domain_results = domain_enumerator.enumerate_domains(base_domains, org_name, domains_progress_bar)
                
                if domain_results['domains'] or domain_results['subdomains']:
                    domain_progress.success(f"Found {len(domain_results['domains'])} domains and {len(domain_results['subdomains'])} subdomains")
                else:
                    domain_progress.warning("No domains or subdomains found")
                
                st.session_state.results['domains'] = domain_results['domains']
                st.session_state.results['subdomains'] = domain_results['subdomains']
                main_progress.progress(0.6, text="Domain enumeration completed")
                
                # Step 4: Analyze cloud providers
                st.markdown("### Step 4: Analyzing Cloud Providers")
                cloud_progress = st.empty()
                cloud_progress.info("Analyzing cloud providers...")
                
                # Analyze IPs to identify cloud providers
                cloud_providers = {}
                
                # Process domains
                for domain in domain_results['domains']:
                    for ip in domain['ips']:
                        provider = ip_analyzer.detect_cloud_provider(ip)
                        if provider != "Unknown":
                            cloud_providers[provider] = cloud_providers.get(provider, 0) + 1
                
                # Process subdomains
                for i, subdomain in enumerate(domain_results['subdomains']):
                    # Add cloud provider information to each subdomain
                    if subdomain['ips']:
                        provider = ip_analyzer.detect_cloud_provider(subdomain['ips'][0])
                        subdomain['cloud_provider'] = provider
                        if provider != "Unknown":
                            cloud_providers[provider] = cloud_providers.get(provider, 0) + 1
                
                if cloud_providers:
                    cloud_progress.success(f"Identified {len(cloud_providers)} cloud providers")
                else:
                    cloud_progress.warning("No cloud providers identified")
                
                st.session_state.results['cloud_providers'] = cloud_providers
                main_progress.progress(0.8, text="Cloud provider analysis completed")
                
                # Step 5: Generate reports
                st.markdown("### Step 5: Generating Reports")
                report_progress = st.empty()
                report_progress.info("Generating reports...")
                
                # Generate HTML report
                html_report = report_generator.create_html_report(st.session_state.results, org_name)
                
                # Generate Markdown report
                md_report = report_generator.create_markdown_report(st.session_state.results, org_name)
                
                report_progress.success(f"Reports generated: {html_report} and {md_report}")
                main_progress.progress(1.0, text="Reconnaissance completed")
                
                # Generate visualizations
                st.session_state.visualizations = report_generator.create_visualizations(st.session_state.results)
                
                # Show completion message
                st.success(f"Reconnaissance for {org_name} completed successfully!")
            
            # Display ASNs and IP Ranges tab
            with tabs[1]:
                st.markdown('<h2 class="sub-header">ASNs & IP Ranges</h2>', unsafe_allow_html=True)
                
                # Display ASNs
                if st.session_state.results.get('asns'):
                    st.markdown("### Autonomous Systems (ASNs)")
                    
                    asn_df = pd.DataFrame(st.session_state.results['asns'])
                    st.dataframe(asn_df, use_container_width=True)
                else:
                    st.info("No ASNs found")
                
                # Display IP Ranges
                if st.session_state.results.get('ip_ranges'):
                    st.markdown("### IP Ranges")
                    
                    ip_ranges_df = pd.DataFrame(st.session_state.results['ip_ranges'])
                    st.dataframe(ip_ranges_df, use_container_width=True)
                    
                    # Add download button for IP ranges
                    csv = ip_ranges_df.to_csv(index=False)
                    b64 = base64.b64encode(csv.encode()).decode()
                    href = f'<a href="data:file/csv;base64,{b64}" download="ip_ranges.csv">Download IP Ranges as CSV</a>'
                    st.markdown(href, unsafe_allow_html=True)
                else:
                    st.info("No IP ranges found")
            
            # Display Domains and Subdomains tab
            with tabs[2]:
                st.markdown('<h2 class="sub-header">Domains & Subdomains</h2>', unsafe_allow_html=True)
                
                # Display Domains
                if st.session_state.results.get('domains'):
                    st.markdown("### Base Domains")
                    
                    domains_df = pd.DataFrame(st.session_state.results['domains'])
                    # Convert list of IPs to comma-separated string
                    domains_df['ips'] = domains_df['ips'].apply(lambda x: ', '.join(x) if x else 'No IP found')
                    st.dataframe(domains_df, use_container_width=True)
                else:
                    st.info("No base domains found")
                
                # Display Subdomains
                if st.session_state.results.get('subdomains'):
                    st.markdown("### Subdomains")
                    
                    # Create DataFrame
                    subdomains_data = []
                    for subdomain in st.session_state.results['subdomains']:
                        subdomains_data.append({
                            'subdomain': subdomain['subdomain'],
                            'ips': ', '.join(subdomain['ips']) if subdomain['ips'] else 'No IP found',
                            'cloud_provider': subdomain.get('cloud_provider', 'Unknown')
                        })
                    
                    subdomains_df = pd.DataFrame(subdomains_data)
                    st.dataframe(subdomains_df, use_container_width=True)
                    
                    # Add download button for subdomains
                    csv = subdomains_df.to_csv(index=False)
                    b64 = base64.b64encode(csv.encode()).decode()
                    href = f'<a href="data:file/csv;base64,{b64}" download="subdomains.csv">Download Subdomains as CSV</a>'
                    st.markdown(href, unsafe_allow_html=True)
                else:
                    st.info("No subdomains found")
                
                # Display Cloud Providers
                if st.session_state.results.get('cloud_providers'):
                    st.markdown("### Cloud Providers")
                    
                    cloud_df = pd.DataFrame([
                        {"Provider": provider, "Count": count}
                        for provider, count in st.session_state.results['cloud_providers'].items()
                    ])
                    st.dataframe(cloud_df, use_container_width=True)
                else:
                    st.info("No cloud providers identified")
            
            # Display Visualizations tab
            with tabs[3]:
                st.markdown('<h2 class="sub-header">Visualizations</h2>', unsafe_allow_html=True)
                
                if hasattr(st.session_state, 'visualizations'):
                    # Cloud Providers Chart
                    if 'cloud_providers_pie' in st.session_state.visualizations:
                        st.plotly_chart(st.session_state.visualizations['cloud_providers_pie'], use_container_width=True)
                    
                    # ASNs Chart
                    if 'asns_bar' in st.session_state.visualizations:
                        st.plotly_chart(st.session_state.visualizations['asns_bar'], use_container_width=True)
                    
                    # Network Map
                    if 'network_map' in st.session_state.visualizations:
                        st.markdown("### Network Relationship Map")
                        st.plotly_chart(st.session_state.visualizations['network_map'], use_container_width=True)
                else:
                    st.info("No visualizations available. Please run the reconnaissance first.")
            
            # Display Reports tab
            with tabs[4]:
                st.markdown('<h2 class="sub-header">Reports</h2>', unsafe_allow_html=True)
                
                if 'results' in st.session_state and st.session_state.results:
                    # Report download buttons
                    report_col1, report_col2 = st.columns(2)
                    
                    with report_col1:
                        st.markdown("### HTML Report")
                        if os.path.exists(html_report):
                            with open(html_report, 'r', encoding='utf-8') as f:
                                html_content = f.read()
                            
                            b64 = base64.b64encode(html_content.encode()).decode()
                            href = f'<a href="data:text/html;base64,{b64}" download="{os.path.basename(html_report)}">Download HTML Report</a>'
                            st.markdown(href, unsafe_allow_html=True)
                        else:
                            st.warning("HTML report not found")
                    
                    with report_col2:
                        st.markdown("### Markdown Report")
                        if os.path.exists(md_report):
                            with open(md_report, 'r', encoding='utf-8') as f:
                                md_content = f.read()
                            
                            b64 = base64.b64encode(md_content.encode()).decode()
                            href = f'<a href="data:text/markdown;base64,{b64}" download="{os.path.basename(md_report)}">Download Markdown Report</a>'
                            st.markdown(href, unsafe_allow_html=True)
                        else:
                            st.warning("Markdown report not found")
                    
                    # Display markdown report preview
                    st.markdown("### Report Preview")
                    with st.expander("Show Markdown Report", expanded=True):
                        if os.path.exists(md_report):
                            with open(md_report, 'r', encoding='utf-8') as f:
                                st.markdown(f.read())
                        else:
                            st.warning("Markdown report not found")
                else:
                    st.info("No reports available. Please run the reconnaissance first.")

if __name__ == "__main__":
    main()