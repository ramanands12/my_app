# api_client.py
import requests
from typing import Optional, Dict, Any

def get_request(url: str) -> Optional[Dict[str, Any]]:
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return None
