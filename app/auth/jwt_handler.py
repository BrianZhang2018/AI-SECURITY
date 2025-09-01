"""
JWT Authentication Handler for Secure AI Banking System
Implements secure token management and role-based access control
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
import os
from .models import User, UserRole, TokenData, ROLE_PERMISSIONS

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_secret_key_change_in_production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a plaintext password"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with user data and expiration
    
    Args:
        data: User data to encode in token
        expires_delta: Custom expiration time
    
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> TokenData:
    """
    Verify and decode a JWT token
    
    Args:
        token: JWT token string
        
    Returns:
        TokenData object with user information
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")
        
        if username is None or user_id is None or role is None:
            raise credentials_exception
            
        token_data = TokenData(
            username=username,
            user_id=user_id,
            role=UserRole(role),
            permissions=ROLE_PERMISSIONS[UserRole(role)],
            account_ids=payload.get("account_ids", [])
        )
        return token_data
        
    except JWTError:
        raise credentials_exception

def check_permissions(token_data: TokenData, required_permission: str) -> bool:
    """
    Check if user has required permission for AI operations
    
    Args:
        token_data: Decoded token data
        required_permission: Permission to check
        
    Returns:
        Boolean indicating if user has permission
    """
    permissions = token_data.permissions
    
    permission_map = {
        "query_accounts": permissions.can_query_accounts,
        "access_transactions": permissions.can_access_transactions,
        "view_aggregated_data": permissions.can_view_aggregated_data,
        "monitor_security": permissions.can_monitor_security,
    }
    
    return permission_map.get(required_permission, False)

# Mock user database for demo purposes
DEMO_USERS_DB = {
    "customer1": {
        "id": "cust_001",
        "username": "customer1",
        "email": "customer1@securebank.com",
        "hashed_password": get_password_hash("password123"),
        "role": UserRole.CUSTOMER,
        "permissions": ROLE_PERMISSIONS[UserRole.CUSTOMER],
        "account_ids": ["acc_001", "acc_002"],
        "branch_code": "SF001",
        "is_active": True
    },
    "admin1": {
        "id": "admin_001", 
        "username": "admin1",
        "email": "admin1@securebank.com",
        "hashed_password": get_password_hash("admin123"),
        "role": UserRole.ADMIN,
        "permissions": ROLE_PERMISSIONS[UserRole.ADMIN],
        "account_ids": [],
        "branch_code": "SF001",
        "is_active": True
    },
    "security1": {
        "id": "sec_001",
        "username": "security1", 
        "email": "security1@securebank.com",
        "hashed_password": get_password_hash("security123"),
        "role": UserRole.SECURITY,
        "permissions": ROLE_PERMISSIONS[UserRole.SECURITY],
        "account_ids": [],
        "branch_code": "SF001",
        "is_active": True
    }
}

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate user with username and password
    
    Args:
        username: Username to authenticate
        password: Plaintext password
        
    Returns:
        User data if authentication successful, None otherwise
    """
    user = DEMO_USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get user data by username"""
    return DEMO_USERS_DB.get(username)