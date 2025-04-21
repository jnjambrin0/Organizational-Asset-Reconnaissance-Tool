import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import datetime
import os
import ipaddress
import streamlit as st

class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def create_html_report(self, data, org_name):
        """
        Generate an HTML report from the reconnaissance data
        """
        # Create report directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        
        # Generate filename
        filename = f"reports/recon_{org_name.replace(' ', '_')}_{self.timestamp}.html"
        
        # Start building HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reconnaissance Report for {org_name}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-bottom: 20px;
                }}
                th, td {{
                    text-align: left;
                    padding: 12px;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                tr:hover {{
                    background-color: #f5f5f5;
                }}
                .summary {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .footer {{
                    margin-top: 40px;
                    text-align: center;
                    font-size: 0.8em;
                    color: #7f8c8d;
                }}
                .highlight {{
                    background-color: #ffffcc;
                }}
            </style>
        </head>
        <body>
            <h1>Reconnaissance Report for {org_name}</h1>
            <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <ul>
        """
        
        # Add summary statistics
        asn_count = len(data.get('asns', []))
        ip_ranges_count = len(data.get('ip_ranges', []))
        domains_count = len(data.get('domains', []))
        subdomains_count = len(data.get('subdomains', []))
        
        html_content += f"""
                    <li><strong>ASNs found:</strong> {asn_count}</li>
                    <li><strong>IP Ranges found:</strong> {ip_ranges_count}</li>
                    <li><strong>Base Domains:</strong> {domains_count}</li>
                    <li><strong>Subdomains found:</strong> {subdomains_count}</li>
                </ul>
            </div>
        """
        
        # Add ASN information
        if data.get('asns'):
            html_content += """
            <h2>Autonomous Systems (ASNs)</h2>
            <table>
                <thead>
                    <tr>
                        <th>ASN</th>
                        <th>Name</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for asn in data['asns']:
                html_content += f"""
                    <tr>
                        <td>{asn['ASN']}</td>
                        <td>{asn['Name']}</td>
                        <td>{asn['Source']}</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        
        # Add IP ranges information
        if data.get('ip_ranges'):
            html_content += """
            <h2>IP Ranges</h2>
            <table>
                <thead>
                    <tr>
                        <th>Prefix</th>
                        <th>Version</th>
                        <th>ASN</th>
                        <th>Name</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for ip_range in data['ip_ranges']:
                html_content += f"""
                    <tr>
                        <td>{ip_range['prefix']}</td>
                        <td>IPv{ip_range['version']}</td>
                        <td>{ip_range['asn']}</td>
                        <td>{ip_range['name']}</td>
                        <td>{ip_range['description']}</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        
        # Add Domains information
        if data.get('domains'):
            html_content += """
            <h2>Base Domains</h2>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>IP Addresses</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for domain in data['domains']:
                ips = ', '.join(domain['ips']) if domain['ips'] else 'No IP found'
                html_content += f"""
                    <tr>
                        <td>{domain['domain']}</td>
                        <td>{ips}</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        
        # Add Subdomains information
        if data.get('subdomains'):
            html_content += """
            <h2>Subdomains</h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Addresses</th>
                        <th>Cloud Provider</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for subdomain in data['subdomains']:
                ips = ', '.join(subdomain['ips']) if subdomain['ips'] else 'No IP found'
                cloud_provider = subdomain.get('cloud_provider', 'Unknown')
                html_content += f"""
                    <tr>
                        <td>{subdomain['subdomain']}</td>
                        <td>{ips}</td>
                        <td>{cloud_provider}</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        
        # Add Cloud Providers information
        if data.get('cloud_providers'):
            html_content += """
            <h2>Cloud Providers</h2>
            <table>
                <thead>
                    <tr>
                        <th>Provider</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for provider, count in data['cloud_providers'].items():
                html_content += f"""
                    <tr>
                        <td>{provider}</td>
                        <td>{count}</td>
                    </tr>
                """
            
            html_content += """
                </tbody>
            </table>
            """
        
        # Close HTML tags
        html_content += """
            <div class="footer">
                <p>This report was generated by the Organizational Asset Reconnaissance Tool.</p>
            </div>
        </body>
        </html>
        """
        
        # Write HTML content to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def create_markdown_report(self, data, org_name):
        """
        Generate a Markdown report from the reconnaissance data
        """
        # Create report directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        
        # Generate filename
        filename = f"reports/recon_{org_name.replace(' ', '_')}_{self.timestamp}.md"
        
        # Start building Markdown content
        md_content = f"""# Reconnaissance Report for {org_name}

Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary

- **ASNs found:** {len(data.get('asns', []))}
- **IP Ranges found:** {len(data.get('ip_ranges', []))}
- **Base Domains:** {len(data.get('domains', []))}
- **Subdomains found:** {len(data.get('subdomains', []))}

"""
        
        # Add ASN information
        if data.get('asns'):
            md_content += """## Autonomous Systems (ASNs)

| ASN | Name | Source |
|-----|------|--------|
"""
            
            for asn in data['asns']:
                md_content += f"| {asn['ASN']} | {asn['Name']} | {asn['Source']} |\n"
            
            md_content += "\n"
        
        # Add IP ranges information
        if data.get('ip_ranges'):
            md_content += """## IP Ranges

| Prefix | Version | ASN | Name | Description |
|--------|---------|-----|------|-------------|
"""
            
            for ip_range in data['ip_ranges']:
                md_content += f"| {ip_range['prefix']} | IPv{ip_range['version']} | {ip_range['asn']} | {ip_range['name']} | {ip_range['description']} |\n"
            
            md_content += "\n"
        
        # Add Domains information
        if data.get('domains'):
            md_content += """## Base Domains

| Domain | IP Addresses |
|--------|--------------|
"""
            
            for domain in data['domains']:
                ips = ', '.join(domain['ips']) if domain['ips'] else 'No IP found'
                md_content += f"| {domain['domain']} | {ips} |\n"
            
            md_content += "\n"
        
        # Add Subdomains information
        if data.get('subdomains'):
            md_content += """## Subdomains

| Subdomain | IP Addresses | Cloud Provider |
|-----------|--------------|----------------|
"""
            
            for subdomain in data['subdomains']:
                ips = ', '.join(subdomain['ips']) if subdomain['ips'] else 'No IP found'
                cloud_provider = subdomain.get('cloud_provider', 'Unknown')
                md_content += f"| {subdomain['subdomain']} | {ips} | {cloud_provider} |\n"
            
            md_content += "\n"
        
        # Add Cloud Providers information
        if data.get('cloud_providers'):
            md_content += """## Cloud Providers

| Provider | Count |
|----------|-------|
"""
            
            for provider, count in data['cloud_providers'].items():
                md_content += f"| {provider} | {count} |\n"
            
            md_content += "\n"
        
        # Add footer
        md_content += """---

*This report was generated by the Organizational Asset Reconnaissance Tool.*
"""
        
        # Write Markdown content to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return filename
    
    def create_visualizations(self, data):
        """
        Create visualizations for Streamlit display
        """
        visualizations = {}
        
        # 1. Cloud Providers Pie Chart
        if data.get('cloud_providers'):
            providers = list(data['cloud_providers'].keys())
            counts = list(data['cloud_providers'].values())
            
            fig = px.pie(
                names=providers,
                values=counts,
                title="Cloud Providers Distribution"
            )
            visualizations['cloud_providers_pie'] = fig
        
        # 2. ASNs Bar Chart
        if data.get('asns'):
            asn_names = [asn['Name'] for asn in data['asns']]
            asn_ids = [asn['ASN'] for asn in data['asns']]
            
            fig = px.bar(
                x=asn_names,
                y=[1] * len(asn_names),  # Just for counting
                labels={'x': 'ASN Name', 'y': 'Count'},
                title="Autonomous Systems",
                text=asn_ids
            )
            visualizations['asns_bar'] = fig
        
        # 3. Network Map (Optional, requires NetworkX and more processing)
        try:
            if data.get('domains') and data.get('subdomains'):
                # Create a graph
                G = nx.Graph()
                
                # Add organization node
                G.add_node('Organization', type='org')
                
                # Add domain nodes and connect to org
                for domain in data['domains']:
                    G.add_node(domain['domain'], type='domain')
                    G.add_edge('Organization', domain['domain'])
                    
                    # Add IP nodes for domains
                    for ip in domain['ips']:
                        G.add_node(ip, type='ip')
                        G.add_edge(domain['domain'], ip)
                
                # Add subdomain nodes and connect to parent domains
                for subdomain in data['subdomains']:
                    G.add_node(subdomain['subdomain'], type='subdomain')
                    
                    # Connect to parent domain if found
                    for domain in data['domains']:
                        if subdomain['subdomain'].endswith(f".{domain['domain']}"):
                            G.add_edge(domain['domain'], subdomain['subdomain'])
                            break
                    
                    # Add IP nodes for subdomains
                    for ip in subdomain['ips']:
                        if ip not in G:
                            G.add_node(ip, type='ip')
                        G.add_edge(subdomain['subdomain'], ip)
                
                # Convert NetworkX graph to Plotly
                pos = nx.spring_layout(G)
                
                # Node traces by type
                node_traces = {}
                for node_type in ['org', 'domain', 'subdomain', 'ip']:
                    node_traces[node_type] = go.Scatter(
                        x=[],
                        y=[],
                        text=[],
                        mode='markers',
                        hoverinfo='text',
                        marker=dict(
                            size=10,
                            color={'org': 'red', 'domain': 'blue', 'subdomain': 'green', 'ip': 'orange'}[node_type],
                        ),
                        name=node_type.capitalize()
                    )
                
                # Add nodes to traces
                for node in G.nodes():
                    node_type = G.nodes[node].get('type', 'ip')
                    x, y = pos[node]
                    node_traces[node_type]['x'] += tuple([x])
                    node_traces[node_type]['y'] += tuple([y])
                    node_traces[node_type]['text'] += tuple([node])
                
                # Edge trace
                edge_trace = go.Scatter(
                    x=[],
                    y=[],
                    line=dict(width=0.5, color='#888'),
                    hoverinfo='none',
                    mode='lines'
                )
                
                # Add edges
                for edge in G.edges():
                    x0, y0 = pos[edge[0]]
                    x1, y1 = pos[edge[1]]
                    edge_trace['x'] += tuple([x0, x1, None])
                    edge_trace['y'] += tuple([y0, y1, None])
                
                # Create figure
                fig = go.Figure(
                    data=[edge_trace] + list(node_traces.values()),
                    layout=go.Layout(
                        title='Network Relationship Map',
                        showlegend=True,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    )
                )
                
                visualizations['network_map'] = fig
            
        except Exception as e:
            st.error(f"Error creating network visualization: {str(e)}")
        
        return visualizations