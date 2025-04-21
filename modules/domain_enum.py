import dns.resolver
import socket
import whois
import requests
from bs4 import BeautifulSoup
import time
import re
from concurrent.futures import ThreadPoolExecutor
import streamlit as st

class DomainEnumerator:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def verify_domain_ownership(self, domain, org_name):
        """
        Try to verify if a domain belongs to the organization
        """
        try:
            domain_info = whois.whois(domain)
            
            # Check various WHOIS fields for the org name
            org_fields = [
                'org', 'organization', 'registrant_organization', 
                'admin_organization', 'tech_organization'
            ]
            
            for field in org_fields:
                if field in domain_info and domain_info[field]:
                    value = domain_info[field]
                    if isinstance(value, list):
                        for item in value:
                            if item and org_name.lower() in item.lower():
                                return True
                    elif isinstance(value, str) and org_name.lower() in value.lower():
                        return True
            
            return False
        except Exception:
            return False
    
    def resolve_domain_to_ip(self, domain):
        """
        Resolve a domain name to its IP addresses
        """
        ips = []
        
        try:
            # Try to resolve A record (IPv4)
            answers = dns.resolver.resolve(domain, 'A')
            for answer in answers:
                ips.append(answer.address)
        except Exception:
            # If DNS resolver fails, try socket
            try:
                ip = socket.gethostbyname(domain)
                ips.append(ip)
            except Exception:
                pass
        
        return ips
    
    def get_subdomains_from_crtsh(self, domain):
        """
        Find subdomains using certificate transparency logs (crt.sh)
        """
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                # Parse JSON response
                try:
                    data = response.json()
                    
                    # Process each certificate entry
                    for cert in data:
                        name_value = cert.get('name_value', '')
                        
                        # Split by newlines and filter valid subdomains
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            
                            # Clean subdomain
                            if subdomain.startswith('*.'):
                                subdomain = subdomain[2:]
                            
                            # Validate subdomain
                            if subdomain.endswith(f'.{domain}') or subdomain == domain:
                                subdomains.add(subdomain)
                except:
                    # If JSON parsing fails, try HTML parsing
                    return self._parse_crtsh_html(domain)
        except Exception as e:
            st.warning(f"Error querying crt.sh for {domain}: {str(e)}")
        
        return list(subdomains)
    
    def _parse_crtsh_html(self, domain):
        """
        Fallback method to parse crt.sh HTML response
        """
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find the table with certificate information
                tables = soup.find_all('table')
                if len(tables) >= 2:
                    rows = tables[1].find_all('tr')
                    
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 5:
                            subdomain_cell = cells[4]
                            subdomain_text = subdomain_cell.text.strip()
                            
                            # Process each subdomain
                            for subdomain in subdomain_text.split('\n'):
                                subdomain = subdomain.strip().lower()
                                
                                # Clean subdomain
                                if subdomain.startswith('*.'):
                                    subdomain = subdomain[2:]
                                
                                # Validate subdomain
                                if subdomain.endswith(f'.{domain}') or subdomain == domain:
                                    subdomains.add(subdomain)
        except Exception as e:
            st.warning(f"Error parsing crt.sh HTML for {domain}: {str(e)}")
        
        return list(subdomains)

    def get_subdomains_from_dnsdumpster(self, domain):
        """
        Find subdomains using DNSDumpster
        """
        subdomains = set()
        
        try:
            url = f"https://dnsdumpster.com/"
            
            # First request to get CSRF token
            session = requests.Session()
            response = session.get(url, headers=self.headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'}).get('value')
                
                # Second request to perform search
                if csrf_token:
                    cookies = {'csrftoken': csrf_token}
                    data = {
                        'csrfmiddlewaretoken': csrf_token,
                        'targetip': domain
                    }
                    headers = self.headers.copy()
                    headers['Referer'] = url
                    
                    response = session.post(url, headers=headers, cookies=cookies, data=data)
                    
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Extract subdomains from the table
                        tables = soup.find_all('table', {'class': 'table'})
                        for table in tables:
                            for td in table.find_all('td', {'class': 'col-md-4'}):
                                for subdomain in td.text.split('\n'):
                                    subdomain = subdomain.strip().lower()
                                    if subdomain.endswith(f'.{domain}'):
                                        subdomains.add(subdomain)
        except Exception as e:
            st.warning(f"Error querying DNSDumpster for {domain}: {str(e)}")
        
        return list(subdomains)
    
    def get_subdomains_from_api(self, domain, org_name):
        """
        Use various APIs to find subdomains
        """
        subdomains = set()
        
        # SecurityTrails API (need an API key in production)
        try:
            # This is a placeholder - in a real tool, you would use a valid API key
            pass
        except Exception:
            pass
        
        # VirusTotal API (need an API key in production)
        try:
            # This is a placeholder - in a real tool, you would use a valid API key
            pass
        except Exception:
            pass
            
        return list(subdomains)
    
    def filter_active_subdomains(self, subdomains, max_workers=10):
        """
        Filter out inactive subdomains by checking if they resolve to an IP
        """
        active_subdomains = []
        
        def check_subdomain(subdomain):
            ips = self.resolve_domain_to_ip(subdomain)
            if ips:
                return {
                    'subdomain': subdomain,
                    'ips': ips
                }
            return None
        
        # Use ThreadPoolExecutor for concurrent checks
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(check_subdomain, subdomains))
        
        # Filter out None results (inactive subdomains)
        active_subdomains = [result for result in results if result is not None]
        
        return active_subdomains
    
    def find_related_domains(self, org_name):
        """
        Try to find domains related to the organization using search engines
        """
        domains = set()
        
        # Method 1: Using DuckDuckGo search
        try:
            search_term = f"{org_name} site"
            url = f"https://duckduckgo.com/html/?q={search_term}"
            
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract URLs from search results
                result_links = soup.select('.result__url')
                for link in result_links:
                    try:
                        href = link.text.strip()
                        # Extract domain from URL
                        domain_match = re.search(r'https?://(?:www\.)?([^/]+)', href)
                        if domain_match:
                            domain = domain_match.group(1).lower()
                            # Verify if it belongs to the organization
                            if self.verify_domain_ownership(domain, org_name):
                                domains.add(domain)
                    except Exception:
                        continue
        except Exception as e:
            st.warning(f"Error searching for domains via DuckDuckGo: {str(e)}")
        
        # Add a delay to avoid rate limiting
        time.sleep(2)
        
        return list(domains)
    
    def enumerate_domains(self, base_domains, org_name, progress_bar=None):
        """
        Main method to enumerate domains and subdomains
        """
        results = {
            'domains': [],
            'subdomains': []
        }
        
        # Step 1: If no base domains are provided, try to find some
        if not base_domains:
            st.info("No base domains provided. Attempting to discover related domains...")
            base_domains = self.find_related_domains(org_name)
            if base_domains:
                st.success(f"Discovered {len(base_domains)} related domains.")
            else:
                st.warning("No domains could be discovered automatically. Please provide at least one base domain.")
                return results
        
        # Step 2: Process each base domain
        total_domains = len(base_domains)
        
        for i, domain in enumerate(base_domains):
            # Update progress if a progress bar is provided
            if progress_bar:
                progress_bar.progress((i + 1) / total_domains, text=f"Processing domain {domain} ({i+1}/{total_domains})")
            
            # Add the base domain to results
            domain_ips = self.resolve_domain_to_ip(domain)
            results['domains'].append({
                'domain': domain,
                'ips': domain_ips
            })
            
            # Get subdomains from various sources
            st.info(f"Finding subdomains for {domain}...")
            
            # Certificate Transparency logs (crt.sh)
            crtsh_subdomains = self.get_subdomains_from_crtsh(domain)
            
            # DNSDumpster
            dnsdumpster_subdomains = self.get_subdomains_from_dnsdumpster(domain)
            
            # API sources
            api_subdomains = self.get_subdomains_from_api(domain, org_name)
            
            # Combine all subdomains
            all_subdomains = list(set(crtsh_subdomains + dnsdumpster_subdomains + api_subdomains))
            
            if all_subdomains:
                st.success(f"Found {len(all_subdomains)} potential subdomains for {domain}.")
                
                # Filter active subdomains
                st.info("Checking which subdomains are active...")
                active_subdomains = self.filter_active_subdomains(all_subdomains)
                st.success(f"Found {len(active_subdomains)} active subdomains for {domain}.")
                
                # Add active subdomains to results
                results['subdomains'].extend(active_subdomains)
            else:
                st.warning(f"No subdomains found for {domain}.")
        
        return results