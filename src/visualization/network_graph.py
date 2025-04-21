"""Module for generating network graph visualizations."""

import logging
import os
from typing import Optional
from pyvis.network import Network
import ipaddress

# Add project root to path to allow sibling imports
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.core.models import ReconnaissanceResult

logger = logging.getLogger(__name__)

# Define colors/shapes for different node types
NODE_STYLE = {
    "TargetOrg": {"color": "#FF0000", "shape": "star", "size": 30},
    "ASN": {"color": "#FFA500", "shape": "triangle"},
    "Domain": {"color": "#0000FF", "shape": "dot", "size": 15},
    "IPRange": {"color": "#008000", "shape": "square", "size": 15},
    "CloudProvider": {"color": "#800080", "shape": "diamond", "size": 20}
}

def generate_network_graph(result: ReconnaissanceResult, output_dir: str = "./reports") -> Optional[str]:
    """Generates a simplified, high-level interactive HTML network graph using pyvis."""
    logger.info(f"Generating network graph for {result.target_organization}")
    
    net = Network(height="750px", width="100%", notebook=False, directed=False, cdn_resources='remote') # Use remote cdn

    # --- Add Nodes (Simplified) --- 
    nodes_added = set()
    cloud_providers_found = set() # Keep track of unique cloud providers

    # Target Organization Node
    org_node_id = result.target_organization
    net.add_node(org_node_id, label=org_node_id, title="Target Organization", **NODE_STYLE["TargetOrg"])
    nodes_added.add(org_node_id)

    # ASN Nodes
    for asn in result.asns:
        node_id = f"AS{asn.number}"
        label = f"AS{asn.number}\n{asn.name or ''}".strip()
        title = f"ASN: {asn.number}\nName: {asn.name}\nDesc: {asn.description}\nCountry: {asn.country}\nSource: {asn.data_source}"
        if node_id not in nodes_added:
             net.add_node(node_id, label=label, title=title, **NODE_STYLE["ASN"])
             nodes_added.add(node_id)
             net.add_edge(org_node_id, node_id)

    # Summarized IP Range Nodes
    ip_range_to_providers = {} # Map range CIDR to set of cloud providers
    for ipr in result.ip_ranges: # These should now be the summarized ranges
        node_id = ipr.cidr
        label = ipr.cidr
        title = f"Summarized IP Range: {ipr.cidr}\nSource: {ipr.data_source}"
        # ASN/Country info is lost in summarization
        
        if node_id not in nodes_added:
            net.add_node(node_id, label=label, title=title, **NODE_STYLE["IPRange"])
            nodes_added.add(node_id)
            # Omit direct link from ASN to summarized range for simplicity
            # Link Summarized Range to Target Org (optional, could be noisy)
            # net.add_edge(org_node_id, node_id)
            
        # Check which cloud providers this summarized range belongs to
        ip_range_to_providers[node_id] = set()
        # Re-use cloud detection logic (needs access or re-implementation here)
        # THIS REQUIRES ACCESS TO _CLOUD_IP_SETS_BY_PROVIDER from cloud_detection
        # For now, we'll link based on the CloudService objects if they exist

    # Base Domain Nodes (NO Subdomains)
    domain_to_providers = {} # Map domain name to set of cloud providers
    for dom in result.domains:
        node_id = dom.name
        label = dom.name
        title = f"Domain: {dom.name}\nRegistrar: {dom.registrar}\nSource: {dom.data_source}"
        if node_id not in nodes_added:
             net.add_node(node_id, label=label, title=title, **NODE_STYLE["Domain"])
             nodes_added.add(node_id)
             net.add_edge(org_node_id, node_id)
        domain_to_providers[node_id] = set()

    # Process Cloud Services to find links and unique providers
    for svc in result.cloud_services:
        cloud_providers_found.add(svc.provider)
        identifier_node_id = svc.identifier
        
        # Check if identifier is an IP Range or Domain/Subdomain
        if identifier_node_id in ip_range_to_providers:
            ip_range_to_providers[identifier_node_id].add(svc.provider)
        elif identifier_node_id in domain_to_providers:
             domain_to_providers[identifier_node_id].add(svc.provider)
        # Ignore links from subdomains if identifier is a subdomain FQDN

    # Add Cloud Provider Nodes
    cloud_provider_node_ids = {}
    for provider in cloud_providers_found:
        node_id = f"Cloud: {provider}"
        cloud_provider_node_ids[provider] = node_id
        if node_id not in nodes_added:
             net.add_node(node_id, label=provider, title=f"Cloud Provider: {provider}", **NODE_STYLE["CloudProvider"])
             nodes_added.add(node_id)
             # Optional: Link Cloud Provider node back to Target Org?
             # net.add_edge(org_node_id, node_id)

    # --- Add Edges (Simplified) ---

    # Link Domains to Cloud Providers
    for domain_name, providers in domain_to_providers.items():
        if domain_name in nodes_added:
            for provider in providers:
                if provider in cloud_provider_node_ids:
                    net.add_edge(domain_name, cloud_provider_node_ids[provider])

    # Link Summarized IP Ranges to Cloud Providers
    for ip_range_cidr, providers in ip_range_to_providers.items():
        if ip_range_cidr in nodes_added:
            for provider in providers:
                if provider in cloud_provider_node_ids:
                    net.add_edge(ip_range_cidr, cloud_provider_node_ids[provider])

    # Remove nodes/edges related to individual IPs and Subdomains

    # --- Generate HTML --- 
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
            
        # Generate safe filename
        safe_org_name = "".join(c if c.isalnum() else '_' for c in result.target_organization)
        filename = f"network_graph_{safe_org_name}.html"
        output_path = os.path.join(output_dir, filename)
        
        # Enable physics options for better layout initially
        net.set_options("""
        var options = {
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -50,
              "centralGravity": 0.01,
              "springLength": 100,
              "springConstant": 0.08,
              "damping": 0.4,
              "avoidOverlap": 0
            },
            "maxVelocity": 50,
            "minVelocity": 0.1,
            "solver": "forceAtlas2Based",
            "stabilization": {
              "enabled": true,
              "iterations": 1000,
              "updateInterval": 50,
              "onlyDynamicEdges": false,
              "fit": true
            },
            "timestep": 0.5,
            "adaptiveTimestep": true
          }
        }
        """)

        net.save_graph(output_path)
        logger.info(f"Network graph saved to: {output_path}")
        return output_path
    except Exception as e:
        logger.exception(f"Failed to generate or save network graph: {e}")
        return None

# Example Usage:
if __name__ == '__main__':
    # Create dummy result
    res = ReconnaissanceResult(target_organization="Graph Test Inc")
    asn1 = ASN(1, "ASN1")
    res.add_asn(asn1)
    res.add_ip_range(IPRange("1.0.0.0/24", 4, asn1))
    dom1 = Domain("test.com")
    sub1 = Subdomain("www.test.com", resolved_ips={"1.0.0.1"})
    dom1.subdomains.add(sub1)
    res.add_domain(dom1)
    res.add_cloud_service(CloudService("AWS", identifier="1.0.0.1"))

    # Generate graph
    html_path = generate_network_graph(res, output_dir="./temp_reports")
    if html_path:
        print(f"Graph generated: {html_path}")
    else:
        print("Graph generation failed.") 