import os
from netlas import Netlas

NETLAS_KEY = os.getenv("NETLAS_API_KEY")

def search_domain_netlas(domain):
    try:
        n = Netlas(api_key=NETLAS_KEY)
        results = n.host(domain)
        return results
    except Exception as e:
        print(f"Netlas error: {e}")
    return {}

