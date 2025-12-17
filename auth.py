# auth.py
from typing import Optional, Dict, Any
from datetime import datetime
import jwt

from config import JWT_SECRET_KEY, JWT_ALGORITHM

def generate_token(payload: Dict[str, Any]) -> str:
    payload["iat"] = datetime.utcnow()
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        return None
    