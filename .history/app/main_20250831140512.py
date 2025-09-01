"""
SecureBank AI Assistant - Main Application
Demonstrates AI security best practices for banking use case
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from datetime import timedelta
import uvicorn
import os
from dotenv import load_dotenv

# Import authentication components
from app.auth.models import LoginRequest, Token, UserRole
from app.auth.jwt_handler import authenticate_user, create_access_token, verify_token, ACCESS_TOKEN_EXPIRE_MINUTES

# Load environment variables
load_dotenv()

# Initialize FastAPI with security headers
app = FastAPI(
    title="SecureBank AI Assistant",
    description="Secure AI-powered banking assistant with OWASP LLM Top 10 protections",
    version="1.0.0",
    docs_url="/docs" if os.getenv("DEMO_MODE") == "true" else None,
    redoc_url="/redoc" if os.getenv("DEMO_MODE") == "true" else None
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.securebank.local"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend origin
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.get("/")
async def root():
    return {
        "message": "SecureBank AI Assistant API", 
        "status": "secure",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "security": "enabled"}

# Authentication endpoints
@app.post("/auth/login", response_model=Token)
async def login(login_data: LoginRequest):
    """
    Authenticate user and return JWT token
    Demonstrates secure authentication for banking AI system
    """
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "user_id": user["id"],
            "role": user["role"].value,
            "account_ids": user["account_ids"]
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user_role": user["role"],
        "permissions": user["permissions"]
    }

# Security bearer token dependency
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency to get current authenticated user from JWT token
    """
    token = credentials.credentials
    token_data = verify_token(token)
    return token_data

@app.get("/auth/me")
async def get_current_user_info(current_user = Depends(get_current_user)):
    """
    Get current authenticated user information
    Useful for testing authentication
    """
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "role": current_user.role,
        "permissions": current_user.permissions,
        "account_ids": current_user.account_ids
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8000, 
        reload=True,
        log_level="info"
    )