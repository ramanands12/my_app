# utils.py
import hashlib
import secrets
import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
import requests
from pydantic import EmailStr
from functools import wraps
import time

# Configure logger
logger = logging.getLogger("backend")
logger.setLevel(logging.INFO)

# MSG91 & JWT Configuration
MSG91_AUTH_KEY = "YOUR_MSG91_AUTH_KEY"
MSG91_TEMPLATE_ID = "YOUR_MSG91_TEMPLATE_ID"
JWT_SECRET_KEY = "YOUR_JWT_SECRET"
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_LIFETIME = timedelta(hours=1)

# ---------------------------------------------------------
# STRING UTIL
# ---------------------------------------------------------
def capitalize_words(text: str) -> str:
    """Capitalize each word in a string."""
    return " ".join(word.capitalize() for word in text.split())

# ---------------------------------------------------------
# EMAIL VALIDATION
# ---------------------------------------------------------
def is_valid_email(email: str) -> bool:
    """Simple email validation using pydantic."""
    try:
        EmailStr.validate(email)
        return True
    except Exception:
        return False

# ---------------------------------------------------------
# JSON FILE OPERATIONS
# ---------------------------------------------------------
def read_json(file_path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Read JSON error: {e}")
        return None

def write_json(file_path: str, data: Dict[str, Any]) -> bool:
    try:
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Write JSON error: {e}")
        return False

# ---------------------------------------------------------
# TIMESTAMP
# ---------------------------------------------------------
def get_timestamp() -> str:
    """Return current UTC timestamp as string."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------------------------------------
# MATH UTILITIES
# ---------------------------------------------------------
def add_numbers(a: float, b: float) -> float:
    return a + b

def percentage(part: float, whole: float) -> float:
    try:
        return (part / whole) * 100
    except ZeroDivisionError:
        return 0.0

# ---------------------------------------------------------
# HTTP REQUEST
# ---------------------------------------------------------
def get_request(url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> Optional[dict]:
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"GET request failed: {e}")
        return None

# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------
def log(message: str):
    """Simple logging function."""
    logger.info(message)

# ---------------------------------------------------------
# Existing utils from your previous code
# ---------------------------------------------------------
def generate_otp() -> str:
    otp = str(secrets.randbelow(1000000)).zfill(6)
    logger.info(f"Generated OTP: {otp}")
    return otp

def send_otp_sms(phone_number: str, otp_code: str, purpose: str = "verification") -> Dict[str, Any]:
    try:
        url = "https://api.msg91.com/api/v5/otp"
        payload = {
            "mobile": f"91{phone_number}",
            "authkey": MSG91_AUTH_KEY,
            "template_id": MSG91_TEMPLATE_ID,
            "otp": otp_code
        }
        response = requests.post(url, params=payload)
        logger.info(f"MSG91 Response for {phone_number}: {response.text}")
        return response.json()
    except Exception as e:
        logger.error(f"MSG91 Error: {e}")
        return {"status": "fallback", "message": "MSG91 failed, fallback OTP", "otp": otp_code}

def send_otp_email(email: EmailStr, otp_code: str) -> bool:
    try:
        print("\n" + "=" * 40)
        print(f"Sending Email OTP to {email}")
        print(f"OTP: {otp_code}")
        print("=" * 40 + "\n")
        return True
    except Exception as e:
        logger.error(f"Email Error: {e}")
        return False

def generate_jwt_token(user_id: int, username: str) -> str:
    payload = {"user_id": user_id, "username": username, "iat": datetime.utcnow(),
               "exp": datetime.utcnow() + JWT_ACCESS_TOKEN_LIFETIME}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    logger.info(f"Generated JWT for {username}: {token}")
    return token

def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT token")
        return None

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(raw_password: str, hashed_password: str) -> bool:
    return hash_password(raw_password) == hashed_password

def log_login_attempt(username: str, ip: str, success: bool):
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"[LOGIN] {username} from {ip} → {status}")

def generate_random_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def safe_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    try:
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        logger.info(f"HTTP {method.upper()} {url} → {response.status_code}")
        return response
    except requests.RequestException as e:
        logger.error(f"HTTP {method.upper()} {url} ERROR: {e}")
        return None

def format_datetime(dt: Optional[datetime] = None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    dt = dt or datetime.utcnow()
    return dt.strftime(fmt)

def merge_dicts(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    merged = a.copy()
    merged.update(b)
    return merged

def retry(times: int = 3, delay: float = 1.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(1, times + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    logger.warning(f"Attempt {attempt}/{times} failed: {e}")
                    time.sleep(delay)
            logger.error(f"All {times} attempts failed for {func.__name__}")
            raise last_exception
        return wrapper
    return decorator
# Example usage of retry decorator
@retry(times=5, delay=2.0)
def unstable_function():

    if secrets.randbelow(2) == 0:
        raise ValueError("Random failure occurred!")
    return "Success!"


