import requests
import logging
import time
import sqlite3
import os

logger = logging.getLogger(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")

class GeolocationService:
    def __init__(self):
        self.session = requests.Session()
        # Using IP-API.com which is free for non-commercial use
        self.ip_api_url = "http://ip-api.com/json/{}"
        
    def get_ip_location(self, ip):
        """Get geolocation data for IP address"""
        try:
            url = self.ip_api_url.format(ip)
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': data.get('country', ''),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', ''),
                        'organization': data.get('org', ''),
                        'timezone': data.get('timezone', ''),
                        'as_number': data.get('as', '')
                    }
            
            # Rate limiting for free API
            time.sleep(1.5)
            return None
            
        except Exception as e:
            logger.error(f"Geolocation error for IP {ip}: {e}")
            return None
    
    def bulk_geolocate(self, ip_list):
        """Get geolocation data for multiple IPs"""
        results = []
        
        for ip in ip_list:
            location_data = self.get_ip_location(ip)
            if location_data:
                results.append(location_data)
        
        return results

def store_geolocation_data(location_data_list):
    """Store geolocation data in database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for data in location_data_list:
        c.execute("""
            INSERT OR REPLACE INTO geolocation 
            (ip, country, country_code, region, city, latitude, longitude, 
             isp, organization, timezone, as_number, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            data['ip'], data['country'], data['country_code'],
            data['region'], data['city'], data['latitude'], data['longitude'],
            data['isp'], data['organization'], data['timezone'], data['as_number']
        ))
    
    conn.commit()
    conn.close()

def get_ip_geolocation(ip):
    """Get geolocation for single IP"""
    geo_service = GeolocationService()
    location_data = geo_service.get_ip_location(ip)
    
    if location_data:
        store_geolocation_data([location_data])
        return location_data
    
    return None
