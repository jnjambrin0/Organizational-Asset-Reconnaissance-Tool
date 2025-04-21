import ipaddress
from ipwhois import IPWhois
import pandas as pd

class IPAnalyzer:
    def __init__(self):
        # Define IP ranges for major cloud providers
        # This is a simplified version - in production you would use complete and up-to-date ranges
        self.cloud_ranges = {
            'AWS': [
                '3.0.0.0/8',
                '35.0.0.0/8',
                '52.0.0.0/8',
                '54.0.0.0/8',
                '18.0.0.0/8',
                '13.0.0.0/8',
            ],
            'Azure': [
                '13.64.0.0/11',
                '13.96.0.0/13',
                '13.104.0.0/14',
                '20.0.0.0/8',
                '40.64.0.0/10',
                '52.0.0.0/8',
                '104.208.0.0/13',
            ],
            'Google Cloud': [
                '34.64.0.0/10',
                '34.128.0.0/10',
                '35.184.0.0/13',
                '35.192.0.0/12',
                '35.208.0.0/12',
                '35.224.0.0/12',
                '35.240.0.0/13',
            ],
            'DigitalOcean': [
                '45.55.0.0/16',
                '104.131.0.0/16',
                '178.62.0.0/16',
                '198.199.64.0/18',
            ],
            'OVH': [
                '46.105.0.0/16',
                '51.38.0.0/16',
                '51.68.0.0/16',
                '51.75.0.0/16',
                '51.91.0.0/16',
            ],
            'Cloudflare': [
                '104.16.0.0/12',
                '172.64.0.0/13',
                '173.245.48.0/20',
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                '141.101.64.0/18',
                '108.162.192.0/18',
                '190.93.240.0/20',
                '188.114.96.0/20',
                '197.234.240.0/22',
                '198.41.128.0/17',
            ]
        }
    
    def is_ip_in_ranges(self, ip, ip_ranges):
        """
        Check if an IP is within any of the organization's known IP ranges
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for range_info in ip_ranges:
                try:
                    network = ipaddress.ip_network(range_info['prefix'])
                    if ip_obj in network:
                        return True
                except ValueError:
                    # Invalid network definition, skip it
                    continue
        except:
            # Not a valid IP
            pass
            
        return False
    
    def detect_cloud_provider(self, ip):
        """
        Attempt to identify if an IP belongs to a cloud provider
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for provider, ranges in self.cloud_ranges.items():
                for ip_range in ranges:
                    try:
                        network = ipaddress.ip_network(ip_range)
                        if ip_obj in network:
                            return provider
                    except ValueError:
                        # Invalid network definition, skip it
                        continue
            
            # If no match is found, try to get organization from WHOIS data
            try:
                whois_obj = IPWhois(ip)
                result = whois_obj.lookup_whois()
                
                # Check common cloud provider names in the WHOIS data
                common_providers = ['amazon', 'aws', 'azure', 'microsoft', 'google', 'gcp', 
                                    'digitalocean', 'linode', 'ovh', 'cloudflare', 'oracle']
                
                # Return the organization name from the WHOIS data
                if result.get('asn_description'):
                    desc = result.get('asn_description', '').lower()
                    for provider in common_providers:
                        if provider in desc:
                            return desc
                    return result.get('asn_description')
                elif result.get('nets', []) and result['nets'][0].get('description'):
                    desc = result['nets'][0].get('description', '').lower()
                    for provider in common_providers:
                        if provider in desc:
                            return desc
                    return result['nets'][0].get('description')
            except Exception:
                pass
        except:
            # Not a valid IP
            pass
            
        return "Unknown"