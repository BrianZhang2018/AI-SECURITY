"""
Authentication Models for Secure AI Banking System
Defines user roles and permissions for banking AI assistant
"""

from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Optional
from datetime import datetime

class UserRole(str, Enum):
    """Banking user roles with different AI access levels"""
    CUSTOMER = "customer"          # Can query own account data
    ADMIN = "admin"               # Can access aggregated data
    SECURITY = "security"         # Full monitoring access
    
class UserPermissions(BaseModel):
    """Granular permissions for AI system access"""
    can_query_accounts: bool = False
    can_access_transactions: bool = False
    can_view_aggregated_data: bool = False
    can_monitor_security: bool = False
    max_tokens_per_hour: int = 100
    allowed_data_sources: List[str] = []

class User(BaseModel):
    """User model with banking context"""
    id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Username for authentication")
    email: str = Field(..., description="User email address")
    role: UserRole = Field(..., description="User role determining access level")
    permissions: UserPermissions = Field(..., description="Specific permissions")
    account_ids: List[str] = Field(default=[], description="Associated bank account IDs")
    branch_code: Optional[str] = Field(None, description="Bank branch code")
    is_active: bool = Field(True, description="Account status")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TokenData(BaseModel):
    """JWT token payload data"""
    username: Optional[str] = None
    user_id: str
    role: UserRole
    permissions: UserPermissions
    account_ids: List[str] = []
    exp: Optional[datetime] = None

class LoginRequest(BaseModel):
    """Login request payload"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class Token(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user_role: UserRole
    permissions: UserPermissions

# Default permissions by role
ROLE_PERMISSIONS = {
    UserRole.CUSTOMER: UserPermissions(
        can_query_accounts=True,
        can_access_transactions=True,
        can_view_aggregated_data=False,
        can_monitor_security=False,
        max_tokens_per_hour=50,
        allowed_data_sources=["own_accounts", "public_banking_info"]
    ),
    UserRole.ADMIN: UserPermissions(
        can_query_accounts=True,
        can_access_transactions=True,
        can_view_aggregated_data=True,
        can_monitor_security=False,
        max_tokens_per_hour=200,
        allowed_data_sources=["all_accounts", "aggregated_data", "public_banking_info"]
    ),
    UserRole.SECURITY: UserPermissions(
        can_query_accounts=True,
        can_access_transactions=True,
        can_view_aggregated_data=True,
        can_monitor_security=True,
        max_tokens_per_hour=500,
        allowed_data_sources=["all_accounts", "security_logs", "audit_trails", "public_banking_info"]
    )
}