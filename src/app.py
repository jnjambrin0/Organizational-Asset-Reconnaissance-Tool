import streamlit as st
import logging
import io
import os
from typing import Set
import pandas as pd # Import pandas
import ipaddress

from src.utils.logging_config import StringLogHandler, setup_logging as configure_logging # Import directly
from src.core.models import ReconnaissanceResult, ASN, IPRange, Domain, CloudService, Subdomain # Add models used in display functions
from src.orchestration.discovery_orchestrator import run_discovery # Restore import
from src.visualization.network_graph import generate_network_graph # Restore import

# --- Logger ---
# Setup logger for this module - adjust level as needed
logger = logging.getLogger(__name__)

# --- Data Preparation (Cached Functions) ---
@st.cache_data # Cache the result of this function
def get_asn_df(asns: Set[ASN]) -> pd.DataFrame:
    logger.debug("Preparing ASN DataFrame...")
    asn_list = [{"ASN": a.number, "Name": a.name, "Description": a.description, "Country": a.country, "Source": a.data_source} 
                for a in sorted(list(asns), key=lambda x: x.number)]
    return pd.DataFrame(asn_list)

@st.cache_data
def get_ip_range_df(ip_ranges: Set[IPRange]) -> pd.DataFrame:
    logger.debug("Preparing IP Range DataFrame...")
    # Sort by version first, then by network address
    def sort_key(ipr):
        try:
            net = ipaddress.ip_network(ipr.cidr)
            return (net.version, net)
        except ValueError:
            return (0, ipr.cidr) # Sort invalid ones first
            
    ip_list = [{"CIDR": ipr.cidr, "Version": ipr.version, "Source": ipr.data_source} 
               for ipr in sorted(list(ip_ranges), key=sort_key)]
    return pd.DataFrame(ip_list)

@st.cache_data
def get_domain_df(domains: Set[Domain]) -> pd.DataFrame:
    logger.debug("Preparing Domain DataFrame...")
    domain_list = [{"Domain": d.name, "Registrar": d.registrar, "Source": d.data_source, "Subdomains": len(d.subdomains)} 
                   for d in sorted(list(domains), key=lambda x: x.name)]
    return pd.DataFrame(domain_list)

@st.cache_data
def get_subdomain_df(domains: Set[Domain]) -> pd.DataFrame:
    logger.debug("Preparing Subdomain DataFrame...")
    all_subs = set()
    for domain in domains:
        all_subs.update(domain.subdomains)
        
    subdomain_list = [{"Subdomain": s.fqdn, "Status": s.status, "Resolved IPs": ", ".join(sorted(s.resolved_ips)) if s.resolved_ips else "N/A", "Source": s.data_source} 
                      for s in sorted(list(all_subs), key=lambda s: s.fqdn)]
    return pd.DataFrame(subdomain_list)

@st.cache_data
def get_cloud_service_df(services: Set[CloudService]) -> pd.DataFrame:
    logger.debug("Preparing Cloud Service DataFrame...")
    cloud_list = [{"Provider": s.provider, "Identifier": s.identifier, "Type": s.resource_type, "Source": s.data_source} 
                  for s in sorted(list(services), key=lambda x: (x.provider, x.identifier))]
    return pd.DataFrame(cloud_list)

# --- Pagination Helper (Using Buttons) ---
def display_paginated_dataframe(df, page_size=50, key_prefix="page"):
    """Paginates and displays a pandas DataFrame using Previous/Next buttons."""
    total_rows = len(df)
    if total_rows == 0:
        # st.info("No data found.") # Info message handled by calling function
        return
        
    total_pages = (total_rows // page_size) + (1 if total_rows % page_size > 0 else 0)
    session_key = f"{key_prefix}_current_page"

    # Initialize page number in session state if it doesn't exist
    if session_key not in st.session_state:
        st.session_state[session_key] = 1
        
    current_page = st.session_state[session_key]
    
    # Ensure current page is within bounds (can happen if data changes)
    current_page = max(1, min(current_page, total_pages))
    st.session_state[session_key] = current_page

    # Display DataFrame slice
    start_idx = (current_page - 1) * page_size
    end_idx = start_idx + page_size
    st.dataframe(df.iloc[start_idx:end_idx], use_container_width=True)

    # Pagination controls
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col1:
        if st.button("⬅️ Previous", key=f"{key_prefix}_prev", disabled=(current_page <= 1)):
            st.session_state[session_key] -= 1
            st.rerun() # Rerun to display the new page
            
    with col2:
        st.caption(f"Page {current_page}/{total_pages} (Rows {start_idx+1}-{min(end_idx, total_rows)} of {total_rows})")

    with col3:
        if st.button("Next ➡️", key=f"{key_prefix}_next", disabled=(current_page >= total_pages)):
            st.session_state[session_key] += 1
            st.rerun() # Rerun to display the new page

# --- Display Functions (Using Cached Data & New Pagination) ---
def display_asn_details(asns: Set[ASN]):
    st.subheader("🌐 Autonomous System Numbers (ASNs)")
    if asns:
        asn_df = get_asn_df(asns) # Get cached df
        # No pagination needed for ASNs typically
        st.dataframe(asn_df, use_container_width=True)
    else:
        st.info("No ASNs found.")

def display_ip_range_details(ip_ranges: Set[IPRange]):
    st.subheader("💻 IP Ranges")
    if ip_ranges:
        ip_df = get_ip_range_df(ip_ranges) # Get cached df
        display_paginated_dataframe(ip_df, page_size=100, key_prefix="ip_range")
    else:
        st.info("No IP Ranges found.")

def display_domain_details(domains: Set[Domain]):
    st.subheader("🌍 Domains & Subdomains")
    if domains:
        domain_df = get_domain_df(domains) # Get cached df
        st.dataframe(domain_df, use_container_width=True)
        
        subdomain_df = get_subdomain_df(domains) # Get cached df
        if not subdomain_df.empty:
             with st.expander(f"View All {len(subdomain_df)} Discovered Subdomains"):
                 display_paginated_dataframe(subdomain_df, page_size=50, key_prefix="subdomain") 
        else:
             st.write("No subdomains found.")
    else:
        st.info("No Domains or Subdomains found.")

def display_cloud_services(services: Set[CloudService]):
    st.subheader("☁️ Cloud Services")
    if services:
        cloud_df = get_cloud_service_df(services) # Get cached df
        display_paginated_dataframe(cloud_df, page_size=100, key_prefix="cloud")
    else:
        st.info("No Cloud Services found.")

def display_summary(result: ReconnaissanceResult):
    st.subheader("📊 Summary")
    # Use cached DFs for counts where appropriate (more efficient than iterating raw sets)
    subdomain_count = len(get_subdomain_df(result.domains)) if result.domains else 0
    cols = st.columns(5)
    cols[0].metric("ASNs", len(result.asns))
    cols[1].metric("IP Ranges", len(result.ip_ranges))
    cols[2].metric("Domains", len(result.domains))
    cols[3].metric("Subdomains", subdomain_count)
    cols[4].metric("Cloud Services", len(result.cloud_services))
    
    # Display Warnings
    if result.warnings:
        st.warning(f"⚠️ Scan completed with {len(result.warnings)} warnings:")
        with st.expander("View Warnings"):
            for warning in result.warnings:
                st.write(f"- {warning}")
    else:
        st.success("✅ Scan completed without warnings.")

def display_process_logs(log_stream: io.StringIO):
    st.subheader("⚙️ Process Logs")
    log_content = log_stream.getvalue()
    st.text_area("Logs", log_content, height=400, key="log_area")

# --- Main App ---
st.set_page_config(layout="wide", page_title="Org Reconnaissance Tool")
st.title("🏢 Organizational Asset Reconnaissance Tool")

# --- Input Form ---
with st.form("recon_form"):
    target_org = st.text_input("**Target Organization Name** (Required)", placeholder="e.g., Example Corp")
    base_domains_input = st.text_input("Base Domains (Optional, comma-separated)", placeholder="e.g., example.com, example.org")
    
    submitted = st.form_submit_button("🚀 Run Reconnaissance")
    if submitted:
        if not target_org:
            st.error("Target Organization Name is required.")
        else:
            # Process domains input
            base_domains_set = set()
            if base_domains_input:
                base_domains_set = {d.strip().lower() for d in base_domains_input.split(',') if d.strip()}
                # Basic validation could be added here
                
            # Set state to trigger scan
            st.session_state.run_scan = True
            st.session_state.target_org = target_org # Store for use in scan block
            st.session_state.base_domains = base_domains_set # Store for use in scan block
            # Use experimental_rerun to make the scan start immediately after button press
            st.rerun() # Update to st.rerun

# --- Session State Initialization ---
if 'recon_result' not in st.session_state:
    st.session_state.recon_result = None
if 'log_stream' not in st.session_state:
    st.session_state.log_stream = io.StringIO()
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False
if 'run_scan' not in st.session_state: # Initialize trigger if not present
     st.session_state.run_scan = False
if 'target_org' not in st.session_state:
     st.session_state.target_org = ""
if 'base_domains' not in st.session_state:
     st.session_state.base_domains = set()

# --- Logging Handler --- 
# Get the root logger and attach the handler to capture logs for the UI
log_capture_handler = StringLogHandler(st.session_state.log_stream)
# Check if handler already exists to avoid duplicates
if not any(isinstance(h, StringLogHandler) for h in logging.getLogger().handlers):
     logging.getLogger().addHandler(log_capture_handler)
     logger.debug("StringLogHandler added to root logger.")
# Optional: Set root logger level if needed, but specific loggers are preferred
# logging.getLogger().setLevel(logging.INFO) 

# --- Scan Execution ---
if st.session_state.get("run_scan", False):
    # Retrieve stored values
    target_org = st.session_state.target_org 
    base_domains_set = st.session_state.base_domains

    st.session_state.scan_running = True
    st.session_state.recon_result = None # Reset previous results
    st.session_state.log_stream.seek(0)
    st.session_state.log_stream.truncate(0) # Clear previous logs
    
    st.info(f"Starting reconnaissance for \"{target_org}\" with base domains: {base_domains_set}")
    
    # Configure logging for the run (might reconfigure if run multiple times)
    # Note: configure_logging now directly imported
    configure_logging(level=logging.INFO, stream_handler=log_capture_handler) # Pass handler
    
    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        status_text.text("Running discovery...")
        # Run the discovery process (now returns ReconnaissanceResult)
        result = run_discovery(
            target_organization=target_org, # Use stored value
            base_domains=base_domains_set, # Use stored value
            # Add max_workers from config/UI later
        )
        st.session_state.recon_result = result
        status_text.text("Discovery complete!")
        progress_bar.progress(100)
        st.success("Reconnaissance finished successfully!")
        
    except Exception as e:
        logger.exception("An error occurred during the reconnaissance process.")
        st.error(f"An error occurred: {e}")
        status_text.text("Error during discovery.")
        st.session_state.recon_result = None # Ensure no partial results are shown on error
    finally:
        st.session_state.scan_running = False
        st.session_state.run_scan = False # Reset trigger
        # Rerun to update display after scan finishes or errors
        st.rerun() # Update to st.rerun

# --- Display Results --- 
if st.session_state.recon_result:
    result_data = st.session_state.recon_result
    
    # Add Network Graph Tab
    tab_summary, tab_asns, tab_ips, tab_domains, tab_cloud, tab_graph, tab_process = st.tabs([
        "📊 Summary", "🌐 ASNs", "💻 IP Ranges", "🌍 Domains", "☁️ Cloud", "🕸️ Network Graph", "⚙️ Process Logs"
    ])

    with tab_summary:
        display_summary(result_data)
        # Add other summary elements here if needed
        
    with tab_asns:
        display_asn_details(result_data.asns)
        
    with tab_ips:
        display_ip_range_details(result_data.ip_ranges)
        
    with tab_domains:
        # Need to pass the result's domains here, not the function itself
        display_domain_details(result_data.domains) 
        
    with tab_cloud:
        display_cloud_services(result_data.cloud_services)
        
    with tab_graph:
        st.subheader("🕸️ Relationship Network Graph")
        graph_html_path = generate_network_graph(result_data)
        if graph_html_path:
             try:
                 with open(graph_html_path, 'r', encoding='utf-8') as f:
                     html_content = f.read()
                 st.components.v1.html(html_content, height=800, scrolling=True)
                 # Add download button for the graph
                 with open(graph_html_path, "rb") as fp:
                     st.download_button(
                         label="Download Graph HTML",
                         data=fp,
                         file_name=os.path.basename(graph_html_path),
                         mime="text/html",
                     )
             except FileNotFoundError:
                 st.error(f"Could not find generated graph file: {graph_html_path}")
             except Exception as e:
                 logger.error(f"Error displaying graph HTML: {e}")
                 st.error("Could not display the generated network graph.")
        else:
             st.warning("Network graph generation failed. Check logs for details.")
             
    with tab_process:
        display_process_logs(st.session_state.log_stream)
elif st.session_state.scan_running:
    st.info("Scan in progress...")
    # Optionally display logs even while running
    # st.subheader("⚙️ Process Logs (Live)")
    # log_content = st.session_state.log_stream.getvalue()
    # st.text_area("Logs", log_content, height=400, key="log_area_running", disabled=True)
else:
    st.info("Enter target details and click 'Run Reconnaissance' to start.")
