"""
Pydantic models for AI Security API endpoints
Defines request/response schemas for banking AI assistant
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

class AIRequestType(str, Enum):
    """Types of AI requests supported"""
    CHAT = "chat"
    QUESTION = "question"
    ANALYSIS = "analysis"
    SUMMARY = "summary"

class SecurityLevel(str, Enum):
    """Security levels for AI responses"""
    SAFE = "safe"
    FILTERED = "filtered"
    BLOCKED = "blocked"

# AI Chat Models
class ChatRequest(BaseModel):
    """Request model for AI chat interactions"""
    message: str = Field(..., min_length=1, max_length=2000, description="User message to AI")
    request_type: AIRequestType = Field(default=AIRequestType.CHAT, description="Type of AI request")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context for AI")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "What's my account balance?",
                "request_type": "question",
                "context": {"account_focus": "primary"}
            }
        }

class SecurityAnalysis(BaseModel):
    """Security analysis results for AI interactions"""
    is_safe: bool = Field(..., description="Whether the interaction is safe")
    threat_level: str = Field(..., description="Detected threat level")
    security_score: int = Field(..., ge=0, le=100, description="Security score (0-100)")
    detected_issues: List[str] = Field(default=[], description="List of detected security issues")
    recommendations: List[str] = Field(default=[], description="Security recommendations")

class ChatResponse(BaseModel):
    """Response model for AI chat interactions"""
    response: str = Field(..., description="AI response content")
    security_level: SecurityLevel = Field(..., description="Security level of response")
    security_analysis: SecurityAnalysis = Field(..., description="Security analysis results")
    filtered: bool = Field(default=False, description="Whether content was filtered")
    redactions_made: List[str] = Field(default=[], description="Types of redactions made")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    user_role: str = Field(..., description="User role for context")
    
    class Config:
        schema_extra = {
            "example": {
                "response": "Your current account balance is [BALANCE-REDACTED] as of today.",
                "security_level": "filtered",
                "security_analysis": {
                    "is_safe": True,
                    "threat_level": "low",
                    "security_score": 85,
                    "detected_issues": [],
                    "recommendations": []
                },
                "filtered": True,
                "redactions_made": ["balance_disclosure"],
                "user_role": "customer"
            }
        }

# Security Testing Models
class SecurityTestRequest(BaseModel):
    """Request model for security testing"""
    test_prompts: List[str] = Field(..., min_items=1, description="List of prompts to test")
    test_type: str = Field(default="prompt_injection", description="Type of security test")
    user_role: str = Field(default="customer", description="User role for testing context")

class SecurityTestResult(BaseModel):
    """Individual security test result"""
    prompt: str = Field(..., description="Tested prompt")
    is_injection: bool = Field(..., description="Whether prompt injection was detected")
    threat_level: str = Field(..., description="Detected threat level")
    severity_score: int = Field(..., description="Severity score")
    detected_patterns: List[Dict] = Field(default=[], description="Detected malicious patterns")
    recommendations: List[str] = Field(default=[], description="Security recommendations")

class SecurityTestResponse(BaseModel):
    """Response model for security testing"""
    total_tests: int = Field(..., description="Total number of tests performed")
    passed_tests: int = Field(..., description="Number of tests that passed security")
    failed_tests: int = Field(..., description="Number of tests that failed security")
    test_results: List[SecurityTestResult] = Field(..., description="Individual test results")
    overall_security_score: int = Field(..., description="Overall security score")
    summary: str = Field(..., description="Summary of test results")

# Monitoring Models
class SecurityEvent(BaseModel):
    """Security event model for monitoring"""
    event_id: str = Field(..., description="Unique event identifier")
    event_type: str = Field(..., description="Type of security event")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    user_id: str = Field(..., description="User who triggered the event")
    user_role: str = Field(..., description="User's role")
    severity: str = Field(..., description="Event severity level")
    description: str = Field(..., description="Event description")
    metadata: Dict[str, Any] = Field(default={}, description="Additional event metadata")

class SecurityDashboard(BaseModel):
    """Security monitoring dashboard data"""
    total_requests: int = Field(..., description="Total AI requests processed")
    blocked_requests: int = Field(..., description="Number of blocked requests")
    filtered_responses: int = Field(..., description="Number of filtered responses")
    injection_attempts: int = Field(..., description="Number of injection attempts detected")
    threat_levels: Dict[str, int] = Field(..., description="Count by threat level")
    recent_events: List[SecurityEvent] = Field(..., description="Recent security events")
    uptime_hours: float = Field(..., description="System uptime in hours")
    security_score: int = Field(..., description="Overall system security score")

# Banking-Specific Models
class BankingQuery(BaseModel):
    """Banking-specific query model"""
    query: str = Field(..., description="Banking question or request")
    account_context: Optional[List[str]] = Field(default=None, description="Account IDs for context")
    query_category: Optional[str] = Field(default=None, description="Category of banking query")
    
    class Config:
        schema_extra = {
            "example": {
                "query": "Show me my recent transactions",
                "account_context": ["acc_001"],
                "query_category": "transaction_inquiry"
            }
        }

class BankingResponse(BaseModel):
    """Banking-specific response model"""
    answer: str = Field(..., description="Banking query response")
    data_sources: List[str] = Field(..., description="Data sources used for response")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Response confidence score")
    compliance_notes: List[str] = Field(default=[], description="Compliance and regulatory notes")
    account_scope: List[str] = Field(default=[], description="Accounts referenced in response")
    
    class Config:
        schema_extra = {
            "example": {
                "answer": "Here are your recent transactions for account ending in 1234...",
                "data_sources": ["account_transactions", "public_banking_info"],
                "confidence_score": 0.95,
                "compliance_notes": ["Response limited to user's own accounts per banking regulations"],
                "account_scope": ["acc_001"]
            }
        }

# Admin Models
class UserSecurityProfile(BaseModel):
    """User security profile for admin monitoring"""
    user_id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    role: str = Field(..., description="User role")
    total_requests: int = Field(..., description="Total AI requests made")
    blocked_requests: int = Field(..., description="Number of blocked requests")
    injection_attempts: int = Field(..., description="Number of injection attempts")
    last_activity: datetime = Field(..., description="Last activity timestamp")
    risk_score: int = Field(..., ge=0, le=100, description="User risk score")
    flagged_activities: List[str] = Field(default=[], description="List of flagged activities")

class SystemSecurityReport(BaseModel):
    """Comprehensive system security report"""
    report_id: str = Field(..., description="Report identifier")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation time")
    time_period: str = Field(..., description="Time period covered by report")
    total_users: int = Field(..., description="Total active users")
    total_requests: int = Field(..., description="Total AI requests")
    security_incidents: int = Field(..., description="Number of security incidents")
    top_threats: List[str] = Field(..., description="Most common threat types")
    user_profiles: List[UserSecurityProfile] = Field(..., description="User security profiles")
    recommendations: List[str] = Field(..., description="Security recommendations")
    compliance_status: str = Field(..., description="Overall compliance status")

# Error Models
class SecurityError(BaseModel):
    """Security-related error response"""
    error_type: str = Field(..., description="Type of security error")
    message: str = Field(..., description="Error message")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    user_id: Optional[str] = Field(default=None, description="User who encountered error")
    recommendations: List[str] = Field(default=[], description="Recommended actions")

class ValidationError(BaseModel):
    """Input validation error"""
    field: str = Field(..., description="Field that failed validation")
    error: str = Field(..., description="Validation error message")
    provided_value: Optional[str] = Field(default=None, description="Value that was provided")