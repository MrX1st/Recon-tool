from .criminalip_client import search_domain_criminalip
from .netlas_client import search_domain_netlas
from .zoomeye_client import search_assets_zoomeye
from .fofa_client import search_assets_fofa
from .urlscan_client import search_urlscan

def normalize_and_extract_assets():
    """
    Helper to parse and normalize IP + ports from each source's response.
    Return list of dicts: [{'ip': ip_str, 'ports': [ports]}]
    """
    # CriminalIP parsing
    def parse_criminalip(data):
        assets = []
        # CriminalIP returns IPs with ports in "assets" or "asset" section ? 

        # Sample structure assumption: data['results'] list of hosts with 'ip' and 'ports' keys
        hosts = data.get('results') or []
        for host in hosts:
            ip = host.get('ip')
            ports = []
            services = host.get('open_ports') or host.get('ports') or []
            if services:
                ports = [int(p) for p in services if isinstance(p, int) or (isinstance(p, str) and p.isdigit())]
            if ip:
                assets.append({'ip': ip, 'ports': ports})
        return assets

    # Netlas parsing
    def parse_netlas(data):
        assets = []
        # Netlas response under 'hosts' key? Example:
        hosts = data.get('hosts') or []
        for host in hosts:
            ip = host.get('ip')
            ports = []
            # Ports may be in 'ports' or 'services', gather port numbers
            services = host.get('services') or []
            for svc in services:
                port = svc.get('port')
                if port:
                    ports.append(int(port))
            if ip:
                assets.append({'ip': ip, 'ports': ports})
        return assets

    # ZoomEye parsing
    def parse_zoomeye(data):
        assets = []
        # Adjust to support list or dict input
        if isinstance(data, dict):
            matches = data.get('matches') or []
        elif isinstance(data, list):
            matches = data
        else:
            matches = []

        for match in matches:
            ip = match.get('ip')
            ports = match.get('ports') or []
            ports_int = []
            for p in ports:
                try:
                    ports_int.append(int(p))
                except:
                    continue
            if ip:
                assets.append({'ip': ip, 'ports': ports_int})
        return assets


    # FOFA parsing
    def parse_fofa(data):
        assets = []
        results = data.get('results') or []
        for item in results:
            # FOFA results format: [domain, ip, port]
            ip = None
            ports = []
            if len(item) >= 2:
                ip = item[1]
            if len(item) >= 3:
                port = item[2]
                try:
                    ports.append(int(port))
                except:
                    pass
            if ip:
                assets.append({'ip': ip, 'ports': ports})
        return assets

    # URLScan parsing: Usually returns website info, extract IPs from 'results'["page"]["ip"]
    def parse_urlscan(data):
        assets = []
        results = data.get('results') or []
        for item in results:
            ip = None
            # IP usually under item['page']['ip']
            page_info = item.get('page') or {}
            ip = page_info.get('ip')
            if ip:
                # Ports info unavailable here, set as empty
                assets.append({'ip': ip, 'ports': []})
        return assets

    def flatten_assets(all_assets_lists):
        """Combine multiple lists, deduplicate by IP, merge ports"""
        combined = {}
        for asset_list in all_assets_lists:
            for asset in asset_list:
                ip = asset.get('ip')
                ports = asset.get('ports', [])
                if ip in combined:
                    # Merge ports, uniquely
                    combined[ip]['ports'] = list(set(combined[ip]['ports']) | set(ports))
                else:
                    combined[ip] = {'ip': ip, 'ports': list(set(ports))}
        return list(combined.values())

    def aggregate_asset_discovery(domain):
        results = {}

        results['criminalip'] = search_domain_criminalip(domain)
        results['netlas'] = search_domain_netlas(domain)
        results['zoomeye'] = search_assets_zoomeye(domain)
        results['fofa'] = search_assets_fofa(domain)
        results['urlscan'] = search_urlscan(domain)

        # Parse and normalize
        assets_lists = [
            parse_criminalip(results.get('criminalip', {})),
            parse_netlas(results.get('netlas', {})),
            parse_zoomeye(results.get('zoomeye', {})),
            parse_fofa(results.get('fofa', {})),
            parse_urlscan(results.get('urlscan', {}))
        ]

        # Deduplicate and flatten
        normalized_assets = flatten_assets(assets_lists)
        return normalized_assets

    return aggregate_asset_discovery

# Expose function for use
aggregate_asset_discovery = normalize_and_extract_assets()
