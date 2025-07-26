import schedule
import time
import logging
import sqlite3
import os

# Import the correct functions from your modules based on your current ip_discovery.py
from scanner.ip_discovery import multi_source_search, store_assets
from scanner.subdomain_enum import enumerate_subdomains, store_subdomains
from scanner.geolocation import GeolocationService, store_geolocation_data
from scanner.company_info import gather_company_information
from scanner.vulnerability_scanner import scan_for_vulnerabilities, store_vulnerability_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Adjust DB_PATH to match your existing project structure (two levels up + /data/assets.db)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")

DOMAINS = ['goldapple.ru', 'goldapple.kz', 'goldapple.by', 'goldapple.qa', 'goldapple.ae']

def automated_asset_discovery():
    """Automated asset discovery for all domains"""
    logger.info("Starting automated asset discovery")
    
    geo_service = GeolocationService()  # Reuse single instance per scan
    
    for domain in DOMAINS:
        try:
            logger.info(f"Discovering assets for {domain}")
            assets = multi_source_search(domain)  # Use correct discovery function
            store_assets(assets)  # store_assets does NOT accept domain argument currently
            
            # Get geolocation data for discovered IPs
            if assets:
                ips = [asset['ip'] for asset in assets if asset.get('ip')]
                if ips:
                    geo_data = geo_service.bulk_geolocate(ips)
                    if geo_data:
                        store_geolocation_data(geo_data)
            
            logger.info(f"Completed asset discovery for {domain}: {len(assets)} assets found")
            
        except Exception as e:
            logger.error(f"Error in asset discovery for {domain}: {e}")

def automated_subdomain_enumeration():
    """Automated subdomain enumeration for all domains"""
    logger.info("Starting automated subdomain enumeration")
    
    geo_service = GeolocationService()  # Reuse single instance per scan
    
    for domain in DOMAINS:
        try:
            logger.info(f"Enumerating subdomains for {domain}")
            level_filter = {'min_level': 3, 'max_level': 4}
            subdomains = enumerate_subdomains(domain, level_filter)
            store_subdomains(subdomains, domain)  # expects domain as argument
            
            resolved_ips = [sub['ip'] for sub in subdomains if sub.get('ip')]
            if resolved_ips:
                geo_data = geo_service.bulk_geolocate(resolved_ips)
                if geo_data:
                    store_geolocation_data(geo_data)
            
            logger.info(f"Completed subdomain enumeration for {domain}: {len(subdomains)} subdomains found")
            
        except Exception as e:
            logger.error(f"Error in subdomain enumeration for {domain}: {e}")

def automated_company_info_gathering():
    """Automated company information gathering"""
    logger.info("Starting automated company information gathering")
    
    for domain in DOMAINS:
        try:
            logger.info(f"Gathering company info for {domain}")
            company_info = gather_company_information(domain)
            if company_info:
                logger.info(f"Completed company info gathering for {domain}")
            
        except Exception as e:
            logger.error(f"Error in company info gathering for {domain}: {e}")

def automated_vulnerability_scan():
    """Automated vulnerability scanning"""
    logger.info("Starting automated vulnerability scanning")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute("""
            SELECT a.ip, GROUP_CONCAT(p.port) as ports
            FROM assets a
            JOIN ports p ON a.id = p.asset_id
            GROUP BY a.ip
        """)
        assets = c.fetchall()
    except Exception as e:
        logger.error(f"Error fetching assets for vulnerability scanning: {e}")
        assets = []
    finally:
        conn.close()
    
    for ip, ports_str in assets:
        try:
            if ports_str:
                ports = [int(p) for p in ports_str.split(',')]
                logger.info(f"Scanning vulnerabilities for {ip}")
                
                vuln_results = scan_for_vulnerabilities(ip, ports)
                if vuln_results:
                    store_vulnerability_data(vuln_results)
                    
        except Exception as e:
            logger.error(f"Error in vulnerability scanning for {ip}: {e}")

def run_full_automated_scan():
    """Run complete automated scan"""
    logger.info("Starting full automated security scan")
    
    automated_asset_discovery()
    time.sleep(30)
    
    automated_subdomain_enumeration()
    time.sleep(30)
    
    automated_company_info_gathering()
    time.sleep(30)
    
    automated_vulnerability_scan()
    
    logger.info("Completed full automated security scan")

def main():
    logger.info("Starting automated perimeter security scanner scheduler")
    
    # Schedule scans
    schedule.every().day.at("02:00").do(run_full_automated_scan)  # Daily full scan at 2 AM
    schedule.every().week.do(automated_company_info_gathering)    # Weekly company info update
    
    # Run initial scan immediately on startup
    logger.info("Running initial scan...")
    run_full_automated_scan()
    
    while True:
        schedule.run_pending()
        time.sleep(3600)  # Check pending jobs every hour

if __name__ == "__main__":
    main()
