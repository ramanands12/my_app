# utils.py
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
import requests
from pydantic import EmailStr

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
# GENERATE OTP
# ---------------------------------------------------------
def generate_otp() -> str:
    """Generate a secure 6-digit OTP."""
    otp = str(secrets.randbelow(1000000)).zfill(6)
    logger.info(f"Generated OTP: {otp}")
    return otp


# ---------------------------------------------------------
# SEND OTP USING MSG91
# ---------------------------------------------------------
def send_otp_sms(phone_number: str, otp_code: str, purpose: str = "verification") -> Dict[str, Any]:
    """
    Send OTP using MSG91 API.
    phone_number: without country code
    """
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

        return {
            "status": "fallback",
            "message": "MSG91 failed, fallback OTP",
            "otp": otp_code
        }


# ---------------------------------------------------------
# SEND OTP VIA EMAIL
# ---------------------------------------------------------
def send_otp_email(email: EmailStr, otp_code: str) -> bool:
    """
    Dummy email sender function.
    In production integrate Gmail/SMTP/AWS SES.
    """
    try:
        print("\n" + "=" * 40)
        print(f"Sending Email OTP to {email}")
        print(f"OTP: {otp_code}")
        print("=" * 40 + "\n")

        return True

    except Exception as e:
        logger.error(f"Email Error: {e}")
        return False


# ---------------------------------------------------------
# GENERATE JWT TOKEN
# ---------------------------------------------------------
def generate_jwt_token(user_id: int, username: str) -> str:
    """
    Generate a JWT token for authentication.
    """
    payload = {
        "user_id": user_id,
        "username": username,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + JWT_ACCESS_TOKEN_LIFETIME,
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    logger.info(f"Generated JWT for {username}: {token}")
    return token


# ---------------------------------------------------------
# VERIFY JWT TOKEN
# ---------------------------------------------------------
def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token and return payload.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None

    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT token")
        return None


# ---------------------------------------------------------
# PASSWORD HASHING
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(raw_password: str, hashed_password: str) -> bool:
    """Verify SHA256 hashed password."""
    return hash_password(raw_password) == hashed_password


# ---------------------------------------------------------
# LOG LOGIN ATTEMPT
# ---------------------------------------------------------
def log_login_attempt(username: str, ip: str, success: bool):
    """Log login activity."""
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"[LOGIN] {username} from {ip} → {status}")

