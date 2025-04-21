import requests
import re
import time
from bs4 import BeautifulSoup
import streamlit as st

class ASNFinder:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def find_asns_by_org(self, org_name):
        """
        Find ASNs associated with an organization using BGP Hurricane Electric
        """
        asns = []
        
        # Method 1: Scrape BGP.HE.NET
        try:
            search_url = f"https://bgp.he.net/search?search%5Bsearch%5D={org_name}&commit=Search"
            
            response = requests.get(search_url, headers=self.headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for ASN links in the results
                asn_links = soup.select('a[href^="/AS"]')
                for link in asn_links:
                    asn = link.get('href').replace('/AS', '')
                    if asn.isdigit():  # Validate it's a numeric ASN
                        asn_data = {
                            'ASN': f"AS{asn}",
                            'Name': link.text.strip(),
                            'Source': 'BGP Hurricane Electric'
                        }
                        asns.append(asn_data)
        except Exception as e:
            st.error(f"Error querying BGP Hurricane Electric: {str(e)}")
        
        # Method 2: Try ASRank API (this is a placeholder, the actual API might require registration)
        try:
            # This is a placeholder. In a real tool, you would use ASRank API or similar
            pass
        except Exception as e:
            st.error(f"Error querying ASRank API: {str(e)}")
        
        return asns
    
    def get_ip_ranges_for_asn(self, asn):
        """
        Get IP ranges for a specific ASN
        """
        ip_ranges = []
        asn_number = asn.replace('AS', '')
        
        # Method 1: Using BGPView API
        try:
            url = f"https://api.bgpview.io/asn/{asn_number}/prefixes"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    # Process IPv4 Prefixes
                    for prefix in data.get('data', {}).get('ipv4_prefixes', []):
                        prefix_cidr = prefix.get('prefix')
                        ip_ranges.append({
                            'prefix': prefix_cidr,
                            'version': 4,
                            'source': 'BGPView',
                            'asn': asn,
                            'name': prefix.get('name', 'Unknown'),
                            'description': prefix.get('description', 'Unknown')
                        })
                    
                    # Process IPv6 Prefixes
                    for prefix in data.get('data', {}).get('ipv6_prefixes', []):
                        prefix_cidr = prefix.get('prefix')
                        ip_ranges.append({
                            'prefix': prefix_cidr,
                            'version': 6,
                            'source': 'BGPView',
                            'asn': asn,
                            'name': prefix.get('name', 'Unknown'),
                            'description': prefix.get('description', 'Unknown')
                        })
        except Exception as e:
            st.error(f"Error getting IP ranges for ASN {asn}: {str(e)}")
        
        # Method 2: Scrape BGP.HE.NET (as fallback)
        if not ip_ranges:
            try:
                url = f"https://bgp.he.net/AS{asn_number}"
                response = requests.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Parse IPv4 ranges
                    ipv4_table = soup.find('table', {'id': 'table_prefixes4'})
                    if ipv4_table:
                        rows = ipv4_table.find_all('tr')
                        for row in rows[1:]:  # Skip header row
                            cols = row.find_all('td')
                            if cols:
                                prefix = cols[0].text.strip()
                                ip_ranges.append({
                                    'prefix': prefix,
                                    'version': 4,
                                    'source': 'BGP.HE.NET',
                                    'asn': asn,
                                    'name': 'Unknown',
                                    'description': 'Scraped from Hurricane Electric'
                                })
                    
                    # Parse IPv6 ranges
                    ipv6_table = soup.find('table', {'id': 'table_prefixes6'})
                    if ipv6_table:
                        rows = ipv6_table.find_all('tr')
                        for row in rows[1:]:  # Skip header row
                            cols = row.find_all('td')
                            if cols:
                                prefix = cols[0].text.strip()
                                ip_ranges.append({
                                    'prefix': prefix,
                                    'version': 6,
                                    'source': 'BGP.HE.NET',
                                    'asn': asn,
                                    'name': 'Unknown', 
                                    'description': 'Scraped from Hurricane Electric'
                                })
            except Exception as e:
                st.error(f"Error scraping BGP.HE.NET for ASN {asn}: {str(e)}")
        
        # Add a delay to avoid rate limiting
        time.sleep(1)
        
        return ip_ranges