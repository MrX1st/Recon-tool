import requests
import sqlite3
import logging
import os
import time
import dns.resolver
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")

class SubdomainEnumerator:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_subdomain_level(self, subdomain, parent_domain):
        """Calculate subdomain level relative to parent domain"""
        # Remove parent domain from subdomain
        if subdomain.endswith(f".{parent_domain}"):
            prefix = subdomain[:-len(f".{parent_domain}")]
            if not prefix:  # Direct domain
                return 0
            return len(prefix.split('.'))
        return 0
    
    def filter_by_level(self, subdomains, parent_domain, max_level=None, min_level=None):
        """Filter subdomains by level"""
        filtered = []
        
        for subdomain in subdomains:
            level = self.get_subdomain_level(subdomain, parent_domain)
            
            if min_level is not None and level < min_level:
                continue
            if max_level is not None and level > max_level:
                continue
                
            filtered.append(subdomain)
        
        return filtered
    
    def crt_sh_subdomains(self, domain):
        """Get subdomains from certificate transparency"""
        logging.info(f"Querying crt.sh for domain: {domain}")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                logging.error(f"crt.sh returned status code {response.status_code} for {domain}")
                return []
            
            entries = response.json()
            subdomains = set()
            
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
            
            logging.info(f"Found {len(subdomains)} subdomains for {domain}")
            time.sleep(1.5)  # Rate limiting
            return sorted(subdomains)
            
        except Exception as e:
            logging.error(f"crt.sh error for domain {domain}: {e}")
            return []
    
    def get_additional_sources(self, domain):
        """Get subdomains from additional free sources"""
        subdomains = set()
        
        # Try HackerTarget (free API)
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200 and not response.text.startswith("error"):
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain.endswith(domain):
                            subdomains.add(subdomain)
            time.sleep(2)  # Rate limiting
        except Exception as e:
            logging.error(f"HackerTarget error for {domain}: {e}")
        
        return list(subdomains)
    
    def resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP and get basic info"""
        try:
            ip = socket.gethostbyname(subdomain)
            return {'subdomain': subdomain, 'ip': ip, 'resolved': True}
        except:
            return {'subdomain': subdomain, 'ip': None, 'resolved': False}

def enumerate_subdomains(domain, level_filter=None):
    """Main function to enumerate subdomains with optional level filtering"""
    enumerator = SubdomainEnumerator()
    
    # Get subdomains from multiple sources
    crt_subs = enumerator.crt_sh_subdomains(domain)
    additional_subs = enumerator.get_additional_sources(domain)
    
    # Combine and deduplicate
    all_subs = list(set(crt_subs + additional_subs))
    
    # Apply level filtering if specified
    if level_filter:
        min_level = level_filter.get('min_level')
        max_level = level_filter.get('max_level')
        all_subs = enumerator.filter_by_level(all_subs, domain, max_level, min_level)
    
    # Resolve subdomains to get IPs
    resolved_subs = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_sub = {executor.submit(enumerator.resolve_subdomain, sub): sub for sub in all_subs}
        
        for future in as_completed(future_to_sub):
            try:
                result = future.result()
                resolved_subs.append(result)
            except Exception as e:
                logging.error(f"Error resolving subdomain: {e}")
    
    return resolved_subs

def store_subdomains(subdomains_data, parent_domain):
    """Store subdomain data with additional info"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for sub_data in subdomains_data:
        subdomain = sub_data['subdomain']
        ip = sub_data['ip']
        
        c.execute("""
            INSERT OR REPLACE INTO subdomains (domain, parent_domain, ip, last_scanned)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (subdomain, parent_domain, ip))
    
    conn.commit()
    conn.close()

# Compatibility function
def crtsh_subdomains(domain):
    """Compatibility function for existing code"""
    enumerator = SubdomainEnumerator()
    return enumerator.crt_sh_subdomains(domain)
