import os
import requests

ZOOMEYE_API_KEY = os.getenv("ZOOMEYE_API_KEY")
ZOOMEYE_BASE_URL = "https://api.zoomeye.ai"

def search_assets_zoomeye(domain, page=1):
    headers = {
        "Authorization": f"JWT {ZOOMEYE_API_KEY}"
    }
    query = f"hostname:{domain}"
    url = f"{ZOOMEYE_BASE_URL}/host/search?query={query}&page={page}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"ZoomEye API error {response.status_code}: {response.text}")
        return {}
