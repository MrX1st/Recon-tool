import os
import requests

URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

def search_urlscan(domain):
    url = "https://urlscan.io/api/v1/search/"
    params = {"q": f"domain:{domain}"}
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"URLScan error: {e}")
    return {}
