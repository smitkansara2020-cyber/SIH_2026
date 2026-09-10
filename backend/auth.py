from passlib.context import CryptContext
import re
import secrets
import hashlib


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )


def validate_password(password: str):

    if len(password) < 10:
        return False, "Password must be at least 10 characters long"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"

    increasing = "0123456789"
    decreasing = "9876543210"

    for i in range(len(increasing) - 1):
        if increasing[i:i+2] in password:
            return False, "Password must not contain consecutive numbers"

    for i in range(len(decreasing) - 1):
        if decreasing[i:i+2] in password:
            return False, "Password must not contain consecutive numbers"

    return True, "Password is valid"


def generate_otp():

    return str(
        secrets.randbelow(900000) + 100000
    )


def hash_otp(otp: str):

    return hashlib.sha256(
        otp.encode()
    ).hexdigest()