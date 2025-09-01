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

# Import AI security components
from app.ai_security.prompt_injection import detect_prompt_injection, is_safe_prompt, get_injection_stats
from app.ai_security.content_filter import filter_ai_output, is_output_safe, get_content_filter_stats
from app.models.schemas import (
    ChatRequest, ChatResponse, SecurityAnalysis, SecurityLevel,
    SecurityTestRequest, SecurityTestResponse, SecurityDashboard,
    BankingQuery, BankingResponse, SecurityError
)

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

# AI Security Endpoints
@app.post("/ai/chat", response_model=ChatResponse)
async def secure_ai_chat(chat_request: ChatRequest, current_user = Depends(get_current_user)):
    """
    Secure AI chat endpoint with prompt injection protection and content filtering
    Demonstrates OWASP LLM Top 10 security controls
    """
    user_context = {
        "user_id": current_user.user_id,
        "role": current_user.role.value,
        "account_ids": current_user.account_ids
    }
    
    # Step 1: Detect prompt injection
    injection_result = detect_prompt_injection(chat_request.message, user_context)
    
    if injection_result["is_injection"]:
        # Block request if injection detected
        security_analysis = SecurityAnalysis(
            is_safe=False,
            threat_level=injection_result["threat_level"],
            security_score=100 - injection_result["severity_score"],
            detected_issues=[p["description"] for p in injection_result["detected_patterns"]],
            recommendations=injection_result["recommendations"]
        )
        
        return ChatResponse(
            response="Request blocked due to security concerns. Please rephrase your question.",
            security_level=SecurityLevel.BLOCKED,
            security_analysis=security_analysis,
            filtered=True,
            redactions_made=["prompt_injection_detected"],
            user_role=current_user.role.value
        )
    
    # Step 2: Generate AI response (simplified for demo)
    # In a real implementation, this would call the local LLM
    ai_response = generate_banking_response(chat_request.message, user_context)
    
    # Step 3: Filter AI output
    filter_result = filter_ai_output(
        ai_response, 
        current_user.role.value, 
        current_user.account_ids
    )
    
    if filter_result["should_block"]:
        security_level = SecurityLevel.BLOCKED
        final_response = "Response contains sensitive information and has been blocked."
    elif filter_result["redactions_made"]:
        security_level = SecurityLevel.FILTERED
        final_response = filter_result["filtered_content"]
    else:
        security_level = SecurityLevel.SAFE
        final_response = filter_result["filtered_content"]
    
    # Step 4: Create security analysis
    security_analysis = SecurityAnalysis(
        is_safe=not filter_result["should_block"],
        threat_level=injection_result["threat_level"],
        security_score=max(0, 100 - injection_result["severity_score"]),
        detected_issues=[],
        recommendations=[]
    )
    
    return ChatResponse(
        response=final_response,
        security_level=security_level,
        security_analysis=security_analysis,
        filtered=len(filter_result["redactions_made"]) > 0,
        redactions_made=[r["type"] for r in filter_result["redactions_made"]],
        user_role=current_user.role.value
    )

def generate_banking_response(message: str, user_context: Dict) -> str:
    """
    Generate banking AI response (simplified demo implementation)
    In Phase 2b, this will integrate with local LLM (Ollama)
    """
    user_role = user_context["role"]
    account_ids = user_context.get("account_ids", [])
    
    # Simple rule-based responses for demo
    message_lower = message.lower()
    
    if "balance" in message_lower:
        if user_role == "customer":
            return f"Your current account balance for account {account_ids[0] if account_ids else 'XXXX'} is $2,547.83 as of today."
        elif user_role == "admin":
            return "Average account balance across all customers is $15,240.50 with standard deviation of $8,330.20."
        else:
            return "Balance monitoring: 15,847 accounts monitored, 3 flagged for unusual activity."
    
    elif "transaction" in message_lower:
        if user_role == "customer":
            return f"Recent transactions for account {account_ids[0] if account_ids else 'XXXX'}: ATM withdrawal $100 on 08/30, Online purchase $45.67 on 08/29, Direct deposit $2,500 on 08/28."
        elif user_role == "admin":
            return "Transaction volume: 89,540 transactions processed today, $12.5M total volume."
        else:
            return "Transaction monitoring: 2 suspicious patterns detected, fraud team notified."
    
    elif "fraud" in message_lower or "security" in message_lower:
        if user_role == "customer":
            return "No suspicious activity detected on your accounts. All transactions appear normal."
        elif user_role == "admin":
            return "Current fraud detection rate: 0.03% false positives, 97.8% accuracy in threat identification."
        else:
            return "Security status: 15 potential threats investigated today, 3 confirmed fraudulent activities blocked."
    
    else:
        return "I'm here to help with your banking questions. You can ask about account balances, transactions, or security concerns."

@app.post("/ai/security-test", response_model=SecurityTestResponse)
async def test_prompt_injection(test_request: SecurityTestRequest, current_user = Depends(get_current_user)):
    """
    Test prompt injection detection system
    Useful for security validation and demonstration
    """
    # Only allow admin and security roles to run security tests
    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to run security tests"
        )
    
    test_results = []
    passed_tests = 0
    
    user_context = {
        "user_id": current_user.user_id,
        "role": test_request.user_role,
        "account_ids": []
    }
    
    for prompt in test_request.test_prompts:
        injection_result = detect_prompt_injection(prompt, user_context)
        
        if not injection_result["is_injection"]:
            passed_tests += 1
        
        test_results.append({
            "prompt": prompt,
            "is_injection": injection_result["is_injection"],
            "threat_level": injection_result["threat_level"],
            "severity_score": injection_result["severity_score"],
            "detected_patterns": injection_result["detected_patterns"],
            "recommendations": injection_result["recommendations"]
        })
    
    total_tests = len(test_request.test_prompts)
    failed_tests = total_tests - passed_tests
    overall_score = int((passed_tests / total_tests) * 100) if total_tests > 0 else 0
    
    return SecurityTestResponse(
        total_tests=total_tests,
        passed_tests=passed_tests,
        failed_tests=failed_tests,
        test_results=test_results,
        overall_security_score=overall_score,
        summary=f"Security test completed: {passed_tests}/{total_tests} prompts passed security validation"
    )

@app.get("/ai/security-dashboard", response_model=SecurityDashboard)
async def get_security_dashboard(current_user = Depends(get_current_user)):
    """
    Get AI security monitoring dashboard
    Available to admin and security roles only
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to access security dashboard"
        )
    
    # Get statistics from security modules
    injection_stats = get_injection_stats()
    filter_stats = get_content_filter_stats()
    
    # Combine statistics for dashboard
    total_requests = injection_stats.get("total_attempts", 0) + 100  # Demo data
    blocked_requests = injection_stats.get("total_attempts", 0)
    filtered_responses = filter_stats.get("total_filtered", 0)
    
    return SecurityDashboard(
        total_requests=total_requests,
        blocked_requests=blocked_requests,
        filtered_responses=filtered_responses,
        injection_attempts=injection_stats.get("total_attempts", 0),
        threat_levels=injection_stats.get("threat_levels", {}),
        recent_events=[],  # Would be populated from actual event log
        uptime_hours=24.0,  # Demo data
        security_score=95  # Demo data
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8000, 
        reload=True,
        log_level="info"
    )