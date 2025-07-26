import socket
import dns.resolver
import requests
import time
import logging
import os
import sqlite3

from .discovery_aggregator import aggregate_asset_discovery

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "assets.db")


def get_ips_from_dns(domain):
    """Get IPs from DNS A and AAAA records"""
    ips = set()
    try:
        for qtype in ['A', 'AAAA']:
            answers = dns.resolver.resolve(domain, qtype)
            for rdata in answers:
                ips.add(str(rdata))
        logger.info(f"DNS lookup found {len(ips)} IPs for domain {domain}")
    except Exception as e:
        logger.error(f"DNS resolution error for {domain}: {e}")
    return list(ips)


def get_ips_from_crt_sh(domain):
    """Get IPs by resolving subdomains discovered from crt.sh certificate transparency logs"""
    ips = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            certs = response.json()
            for cert in certs:
                names = cert.get('name_value', '')
                for subdomain in names.split('\n'):
                    subdomain = subdomain.strip().lstrip('*.')
                    if subdomain.endswith(domain):
                        try:
                            ip = socket.gethostbyname(subdomain)
                            ips.add(ip)
                        except Exception:
                            # Could not resolve this subdomain
                            pass
            # Be kind to crt.sh servers
            time.sleep(1)
        logger.info(f"crt.sh lookup found {len(ips)} IPs for domain {domain}")
    except Exception as e:
        logger.error(f"crt.sh lookup error for {domain}: {e}")
    return list(ips)


def multi_source_search(domain):
    """
    Comprehensive asset discovery function combining:
    - DNS A and AAAA record IPs
    - crt.sh resolved IPs from subdomains
    - Multi-source API aggregated assets

    Returns a de-duplicated, normalized list of assets:
    [{'ip': <ip_str>, 'ports': [<port_int>, ...]}, ...]
    """
    logger.info(f"Starting multi-source asset discovery for domain: {domain}")

    # Get IPs from DNS and crt.sh
    dns_ips = get_ips_from_dns(domain)
    crt_ips = get_ips_from_crt_sh(domain)
    manual_ip_set = set(dns_ips) | set(crt_ips)
    logger.info(f"Total manual IPs from DNS and crt.sh: {len(manual_ip_set)}")

    # Prepare manual assets (without port info)
    manual_assets = [{'ip': ip, 'ports': []} for ip in manual_ip_set]

    # Get assets from multi-source APIs (with IPs and ports)
    try:
        api_assets = aggregate_asset_discovery(domain)
        logger.info(f"API aggregator found {len(api_assets)} assets for domain {domain}")
    except Exception as e:
        logger.error(f"API discovery error for {domain}: {e}")
        api_assets = []

    # Combine manual and API-based assets, merge ports per IP
    combined_assets_dict = {}

    # Add manual assets first (empty ports list)
    for asset in manual_assets:
        combined_assets_dict[asset['ip']] = set(asset['ports'])

    # Merge ports from API assets
    for asset in api_assets:
        ip = asset.get('ip')
        ports = asset.get('ports', [])
        if ip in combined_assets_dict:
            combined_assets_dict[ip].update(ports)
        else:
            combined_assets_dict[ip] = set(ports)

    # Convert back to list with sorted port lists
    combined_assets = [{'ip': ip, 'ports': sorted(list(ports))} for ip, ports in combined_assets_dict.items()]

    logger.info(f"Total combined assets after merging: {len(combined_assets)}")

    return combined_assets


def store_assets(assets):
    """
    Store discovered assets and respective ports in the SQLite database.
    Expects assets as list of dicts with keys: 'ip' and 'ports' list of ints.
    """
    if not assets:
        logger.info("No assets provided to store.")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for asset in assets:
        ip = asset.get('ip')
        ports = asset.get('ports', [])

        if not ip:
            continue

        try:
            c.execute("INSERT OR IGNORE INTO assets (ip) VALUES (?)", (ip,))
            c.execute("SELECT id FROM assets WHERE ip=?", (ip,))
            asset_id = c.fetchone()[0]

            # Clear old ports for this asset
            c.execute("DELETE FROM ports WHERE asset_id=?", (asset_id,))

            # Insert new ports info
            for port in ports:
                c.execute("""
                    INSERT INTO ports (asset_id, port, protocol, service)
                    VALUES (?, ?, ?, ?)
                """, (asset_id, port, 'tcp', 'unknown'))

        except Exception as e:
            logger.error(f"Error storing asset {ip}: {e}")

    conn.commit()
    conn.close()


def scan_and_store(domain):
    """
    Convenience function to perform discovery and store results.
    Returns the list of assets.
    """
    assets = multi_source_search(domain)
    store_assets(assets)
    return assets


# For backward compatibility if needed
def shodan_search(domain):
    return multi_source_search(domain)
