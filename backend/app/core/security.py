import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from passlib.context import CryptContext

from app.core.config import settings

# Load cryptographic secrets and parameters from environment / settings
SECRET_KEY: str = settings.SECRET_KEY
ALGORITHM: str = getattr(settings, "ALGORITHM", os.getenv("JWT_ALGORITHM", "HS256"))
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
    getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
)

# Password hashing context using passlib with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored bcrypt hash.
    Safely handles invalid or malformed hashes by returning False.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt before database persistence.
    """
    return pwd_context.hash(password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Encodes and signs a JWT access token including expiration and issued-at claims.
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": now_utc,
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(
    token: str,
    verify_exp: bool = True,
) -> Dict[str, Any]:
    """
    Decodes and validates a signed JWT access token.
    Raises jwt.ExpiredSignatureError if the token has expired.
    Raises jwt.InvalidTokenError for invalid signatures or malformed tokens.
    """
    options = {"verify_exp": verify_exp}
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options=options)
