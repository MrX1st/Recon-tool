import requests
import os
from dotenv import load_dotenv
import base64
import logging

load_dotenv()
logger = logging.getLogger(__name__)

class CensysClient:
    def __init__(self):
        self.api_id = os.getenv('CENSYS_API_ID', '')
        self.api_secret = os.getenv('CENSYS_API_SECRET', '')
        self.base_url = 'https://search.censys.io/api/v2'
        
        if self.api_id and self.api_secret:
            credentials = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
            self.headers = {
                'Authorization': f'Basic {credentials}',
                'Content-Type': 'application/json'
            }
        else:
            self.headers = {}
    
    def search_hosts(self, query, per_page=100):
        """Search hosts using Censys API"""
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not configured")
            return []
        
        try:
            url = f"{self.base_url}/hosts/search"
            params = {
                'q': query,
                'per_page': per_page
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return data.get('result', {}).get('hits', [])
            else:
                logger.error(f"Censys API error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Censys search error: {e}")
            return []

def search_domain_assets(domain):
    """Search for assets related to domain using Censys"""
    client = CensysClient()
    query = f"services.http.request.headers.host:{domain}"
    results = client.search_hosts(query)
    
    assets = []
    for result in results:
        ip = result.get('ip', '')
        services = result.get('services', [])
        ports = [service.get('port') for service in services if service.get('port')]
        
        if ip:
            assets.append({'ip': ip, 'ports': ports})
    
    return assets
