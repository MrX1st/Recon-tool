import requests
import sqlite3
import logging
import os
import whois
from urllib.parse import urlparse
import time

logger = logging.getLogger(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")

class CompanyInfoGatherer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_whois_info(self, domain):
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': str(w.registrar) if w.registrar else '',
                'creation_date': str(w.creation_date) if w.creation_date else '',
                'expiration_date': str(w.expiration_date) if w.expiration_date else '',
                'name_servers': str(w.name_servers) if w.name_servers else '',
                'organization': str(w.org) if hasattr(w, 'org') and w.org else '',
                'country': str(w.country) if hasattr(w, 'country') and w.country else '',
                'registrant_name': str(w.name) if hasattr(w, 'name') and w.name else ''
            }
        except Exception as e:
            logger.error(f"WHOIS error for {domain}: {e}")
            return None
    
    def get_company_from_cert(self, domain):
        """Extract company information from SSL certificate"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    return {
                        'domain': domain,
                        'cert_subject_org': subject.get('organizationName', ''),
                        'cert_subject_cn': subject.get('commonName', ''),
                        'cert_issuer': issuer.get('organizationName', ''),
                        'cert_country': subject.get('countryName', ''),
                        'cert_not_after': cert.get('notAfter', ''),
                        'cert_not_before': cert.get('notBefore', '')
                    }
        except Exception as e:
            logger.error(f"Certificate info error for {domain}: {e}")
            return None
    
    def search_company_info(self, domain):
        """Search for company information from multiple sources"""
        company_data = {
            'domain': domain,
            'whois_info': self.get_whois_info(domain),
            'cert_info': self.get_company_from_cert(domain)
        }
        
        return company_data

def store_company_info(company_data):
    """Store company information in database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    domain = company_data['domain']
    whois_info = company_data.get('whois_info', {}) or {}
    cert_info = company_data.get('cert_info', {}) or {}
    
    c.execute("""
        INSERT OR REPLACE INTO company_info 
        (domain, registrar, creation_date, expiration_date, organization,
         country, cert_organization, cert_issuer, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        domain,
        whois_info.get('registrar', ''),
        whois_info.get('creation_date', ''),
        whois_info.get('expiration_date', ''),
        whois_info.get('organization', ''),
        whois_info.get('country', ''),
        cert_info.get('cert_subject_org', ''),
        cert_info.get('cert_issuer', '')
    ))
    
    conn.commit()
    conn.close()

def gather_company_information(domain):
    """Main function to gather company information"""
    gatherer = CompanyInfoGatherer()
    company_data = gatherer.search_company_info(domain)
    
    if company_data:
        store_company_info(company_data)
        return company_data
    
    return None
