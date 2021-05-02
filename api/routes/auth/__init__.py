import logging
from typing import Optional
from datetime import datetime, timedelta
import uuid
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from api.conf import config

router = APIRouter()
logger = logging.getLogger(__name__)
SECRET_KEY = config["JWT_PRIVATE_KEY"]
PUBLIC_KEY = config["JWT_PUBLIC_KEY"]
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 120


def example_user_validator(username: str, password: str):
    if username == "test" and password == "password":
        return {"username": username, "fullname": "Test User", "groups": ["Admins", "Testuser"]}
    else:
        return False


class AccessRefreshToken(BaseModel):
    access_token: str
    refresh_token: str


class AccessToken(BaseModel):
    access_token: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


async def get_jwt_payload(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=ALGORITHM)
        if payload.get("sub") is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return payload


jwt_claims = {
    "sub": "",  # the username
    "user_claims": {},  # everything user related
    "exp": 0,  # expiry datetime
    "type": "access",  # access or refresh
    "jti": ""  # unique token identifier to revoke tokens. Generated with uuid.uuid4()
}


@router.post("/login", response_model=AccessRefreshToken)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login to get an access and refresh token for later authentication.
    """
    user = example_user_validator(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_data = jwt_claims.copy()
    access_token_data["sub"] = user["username"]
    access_token_data["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token_data["jti"] = str(uuid.uuid4())

    refresh_token_data = jwt_claims.copy()
    refresh_token_data["sub"] = user["username"]
    refresh_token_data["exp"] = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token_data["type"] = "refresh"
    refresh_token_data["jti"] = str(uuid.uuid4())

    return AccessRefreshToken(
        access_token=jwt.encode(access_token_data, SECRET_KEY, algorithm=ALGORITHM),
        refresh_token=jwt.encode(refresh_token_data, SECRET_KEY, algorithm=ALGORITHM)
    )


@router.get("/refresh", response_model=AccessToken)
async def generate_new_refesh_key(payload: dict = Depends(get_jwt_payload)):
    """
    Get a new access token with a valid refresh token.
    """
    if payload["type"] != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You gave the access key, but we need the refresh key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # <- Your token revocation code should be here!

    access_token_data = jwt_claims.copy()
    access_token_data["sub"] = payload["sub"]
    access_token_data["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token_data["jti"] = str(uuid.uuid4())

    return AccessToken(access_token=jwt.encode(access_token_data, SECRET_KEY, algorithm=ALGORITHM))


@router.get("/check_auth", response_model=dict)
async def check_token_for_username(payload: dict = Depends(get_jwt_payload)):
    """
    Get all jwt user claims. That's how a protected endpoint should look like.
    """
    return payload

