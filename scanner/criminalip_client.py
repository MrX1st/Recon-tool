import os
import requests

CRIMINALIP_KEY = os.getenv("CRIMINALIP_API_KEY")

def search_domain_criminalip(domain):
    url = "https://api.criminalip.io/v1/domain/reports"
    headers = {"x-api-key": CRIMINALIP_KEY}
    params = {"domain": domain}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"CriminalIP error: {e}")
    return {}
