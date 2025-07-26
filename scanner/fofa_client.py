import os
import base64
import requests

FOFA_EMAIL = os.getenv("FOFA_EMAIL")
FOFA_KEY = os.getenv("FOFA_API_KEY")

def search_assets_fofa(domain, page=1, size=10):
    query = f'domain="{domain}"'
    dork = base64.b64encode(query.encode()).decode()
    url = f"https://fofa.info/api/v1/search/all?email={FOFA_EMAIL}&key={FOFA_KEY}&qbase64={dork}&page={page}&size={size}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"FOFA error: {e}")
    return {}
