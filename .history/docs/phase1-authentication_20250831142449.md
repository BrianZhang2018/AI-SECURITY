# SecureBank AI Assistant - Phase 1: JWT Authentication

## 🎯 Overview

This project demonstrates **AI security best practices** for a banking environment, specifically built to showcase skills for AI Security Specialist roles. Phase 1 implements a robust JWT authentication system with role-based access control (RBAC) for different banking user types.

## 🏗️ Architecture

```
SecureBank AI Assistant
├── Authentication Layer (JWT + RBAC)
├── API Security (Headers + Middleware)
├── Role-based Permissions
└── Banking User Context
```

## 🔐 Security Features

### 1. JWT Authentication
- **Stateless tokens** for microservices architecture
- **Role-based claims** embedded in JWT payload
- **Configurable expiration** (30 minutes default)
- **Secure secret management** via environment variables

### 2. Role-Based Access Control (RBAC)
- **Customer Role**: Access to own account data only
- **Admin Role**: Aggregated banking data access
- **Security Role**: Full monitoring and audit capabilities

### 3. API Security
- **Security headers**: XSS protection, clickjacking prevention
- **CORS configuration** for frontend integration
- **Trusted host middleware** for domain validation
- **Bearer token authentication** for all protected endpoints

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- pip package manager

### Installation
```bash
# Clone and navigate to project
cd ai-security

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your JWT secret key

# Start the server
PYTHONPATH=/Users/brianzhang/ai/ai-security uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### API Endpoints
```
GET  /                 # API status
GET  /health           # Health check
POST /auth/login       # User authentication
GET  /auth/me          # Current user info (requires JWT)
```

## 🧪 Testing Authentication

### 1. Login as Customer
```bash
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "customer1", "password": "password123"}'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user_role": "customer",
  "permissions": {
    "can_query_accounts": true,
    "can_access_transactions": true,
    "can_view_aggregated_data": false,
    "can_monitor_security": false,
    "max_tokens_per_hour": 50,
    "allowed_data_sources": ["own_accounts", "public_banking_info"]
  }
}
```

### 2. Validate JWT Token
```bash
curl -X GET "http://127.0.0.1:8000/auth/me" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 3. Test Different Roles
```bash
# Admin user (broader access)
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -d '{"username": "admin1", "password": "admin123"}'

# Security user (full monitoring)
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -d '{"username": "security1", "password": "security123"}'
```

## 👥 Demo Users

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `customer1` | `password123` | Customer | Own accounts only |
| `admin1` | `admin123` | Admin | Aggregated data access |
| `security1` | `security123` | Security | Full monitoring access |

## 🔄 Authentication Process Flow

### High-Level Authentication Flow
```
[Client] → [Login Request] → [FastAPI] → [JWT Handler] → [Response with JWT]
   ↓                                                           ↓
[Store JWT] ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ←
   ↓
[Subsequent API Calls with Bearer Token]
   ↓
[JWT Validation] → [Role-based Access Control] → [Protected Resource]
```

### Detailed Step-by-Step Process

#### 1. User Login Flow
```
Step 1: Client Login Request
┌─────────────────┐    POST /auth/login     ┌─────────────────┐
│     Client      │ ────────────────────→   │   FastAPI App   │
│  (curl/browser) │  {username, password}   │   (main.py)     │
└─────────────────┘                         └─────────────────┘
                                                     │
                                                     ▼
Step 2: Authentication Validation              ┌─────────────────┐
                                               │  JWT Handler    │
                                               │ authenticate_   │
                                               │   user()        │
                                               └─────────────────┘
                                                     │
                                                     ▼
Step 3: Password Verification                  ┌─────────────────┐
                                               │ bcrypt.verify() │
                                               │ Hash Comparison │
                                               └─────────────────┘
                                                     │
                                              ✅ Valid / ❌ Invalid
                                                     │
Step 4: JWT Token Generation                        ▼
┌─────────────────┐                          ┌─────────────────┐
│   JWT Token     │ ←─────────────────────── │ create_access_  │
│ + User Claims   │    if valid user         │   token()       │
│ + Permissions   │                          │                 │
└─────────────────┘                          └─────────────────┘
                                                     │
Step 5: Response to Client                          ▼
┌─────────────────┐                          ┌─────────────────┐
│     Client      │ ←────────────────────── │   Response      │
│ Stores JWT      │   {access_token,         │ {token, role,   │
│ for future use  │    role, permissions}    │  permissions}   │
└─────────────────┘                          └─────────────────┘
```

#### 2. Protected API Access Flow
```
Step 1: API Request with JWT
┌─────────────────┐    GET /auth/me         ┌─────────────────┐
│     Client      │ ────────────────────→   │   FastAPI App   │
│                 │  Authorization: Bearer  │                 │
└─────────────────┘      <JWT_TOKEN>        └─────────────────┘
                                                     │
Step 2: JWT Validation                              ▼
                                               ┌─────────────────┐
                                               │ get_current_    │
                                               │   user()        │
                                               │ (dependency)    │
                                               └─────────────────┘
                                                     │
Step 3: Token Verification                          ▼
                                               ┌─────────────────┐
                                               │ verify_token()  │
                                               │ • Decode JWT    │
                                               │ • Check expiry  │
                                               │ • Verify sig    │
                                               └─────────────────┘
                                                     │
Step 4: Role-based Access Control                  ▼
                                               ┌─────────────────┐
                                               │ check_          │
                                               │ permissions()   │
                                               │ • Role check    │
                                               │ • Resource auth │
                                               └─────────────────┘
                                                     │
Step 5: Return Protected Data                       ▼
┌─────────────────┐                          ┌─────────────────┐
│     Client      │ ←────────────────────── │ Protected       │
│ Receives user   │   {user_id, role,        │ Resource Data   │
│ information     │    permissions, ...}     │                 │
└─────────────────┘                          └─────────────────┘
```

### Security Validation Points

#### Authentication Security Checks
```
1. Input Validation
   ├── Username: string validation
   ├── Password: minimum length check
   └── Request format: JSON structure

2. Password Security
   ├── bcrypt hash comparison
   ├── Constant-time comparison
   └── No timing attack vulnerability

3. JWT Generation
   ├── Secure random secret key
   ├── HS256 algorithm (HMAC-SHA256)
   ├── Short expiration (30 minutes)
   └── Role-based claims inclusion
```

#### Authorization Security Checks
```
1. Token Validation
   ├── JWT signature verification
   ├── Expiration time check
   ├── Algorithm validation
   └── Required claims presence

2. Role-based Access Control
   ├── User role extraction
   ├── Permission matrix lookup
   ├── Resource-specific authorization
   └── Account-scoped data access

3. Security Headers
   ├── X-Content-Type-Options: nosniff
   ├── X-Frame-Options: DENY
   ├── X-XSS-Protection: 1; mode=block
   └── Strict-Transport-Security
```

### Error Handling Flow

#### Authentication Failures
```
Invalid Credentials → HTTP 401 → {"detail": "Incorrect username or password"}
Missing Token      → HTTP 401 → {"detail": "Could not validate credentials"}
Expired Token      → HTTP 401 → {"detail": "Could not validate credentials"}
Invalid Token      → HTTP 401 → {"detail": "Could not validate credentials"}
```

#### Security Benefits
- **Consistent error messages** (prevent user enumeration)
- **No sensitive information leakage** in error responses
- **Proper HTTP status codes** for different failure types
- **Rate limiting ready** (structure supports middleware addition)

### Banking-Specific Considerations

#### User Role Hierarchy
```
Security Role (highest privilege)
    ├── Full monitoring access
    ├── Security logs & audit trails
    ├── All account data access
    └── 500 tokens/hour limit

Admin Role (management privilege)
    ├── Aggregated data access
    ├── Cross-account analytics
    ├── Administrative functions
    └── 200 tokens/hour limit

Customer Role (limited privilege)
    ├── Own account data only
    ├── Personal transaction history
    ├── Public banking information
    └── 50 tokens/hour limit
```

#### Compliance Alignment
- **SOX Requirements**: User attribution for all actions
- **PCI-DSS**: Secure authentication for payment data access
- **Banking Regulations**: Role-based access to sensitive data
- **Audit Trail**: Every JWT contains user identification

## 🛡️ Security Considerations

### JWT Token Structure
```json
{
  "sub": "customer1",           // Username
  "user_id": "cust_001",        // Internal user ID
  "role": "customer",           // User role
  "account_ids": ["acc_001"],   // Associated accounts
  "exp": 1756665427            // Expiration timestamp
}
```

### Permission Matrix
| Action | Customer | Admin | Security |
|--------|----------|-------|----------|
| Query own accounts | ✅ | ✅ | ✅ |
| Access transactions | ✅ | ✅ | ✅ |
| View aggregated data | ❌ | ✅ | ✅ |
| Monitor security | ❌ | ❌ | ✅ |
| Max tokens/hour | 50 | 200 | 500 |

## 🎯 Interview Talking Points

### Why JWT for Banking AI?
1. **Audit Trail**: Every AI query linked to specific user/role
2. **Granular Permissions**: Role-based AI capability restrictions
3. **Stateless Scale**: Supports microservices architecture
4. **Compliance**: Meets SOX/PCI-DSS user attribution requirements

### Security Design Decisions
1. **Short-lived tokens** (30 min) reduce compromise risk
2. **Role-based data sources** prevent privilege escalation
3. **Token rate limiting** prevents abuse
4. **Secure headers** protect against web vulnerabilities

### Banking Context
- **Account-scoped access** prevents cross-customer data leakage
- **Branch-aware permissions** for geographical compliance
- **Hierarchical roles** mirror banking organizational structure

## 📁 Project Structure
```
app/
├── main.py                    # FastAPI application entry point
├── auth/
│   ├── __init__.py           # Package initialization
│   ├── models.py             # Pydantic models for auth
│   └── jwt_handler.py        # JWT creation/validation logic
├── ai_security/              # [Phase 2] AI security controls
├── rag/                      # [Phase 2] Secure RAG system
└── models/                   # [Phase 2] API schemas
```

## 🔧 Configuration

### Environment Variables (.env)
```bash
# JWT Configuration
JWT_SECRET_KEY=your_super_secret_key_here
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Security Settings
RATE_LIMIT_PER_MINUTE=10
CONTENT_FILTER_ENABLED=true

# Demo Mode
DEMO_MODE=true
BANK_NAME=SecureBank
```

## 🚧 Next Phase

**Phase 2: AI Security Controls**
- Secure RAG implementation
- Prompt injection protection
- Content filtering and validation
- OWASP LLM Top 10 compliance

## 📖 Technical References

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Banking API Security Best Practices](https://owasp.org/www-project-api-security/)

---

**Built for AI Security Interview Preparation** 🎯
*Demonstrates enterprise-grade authentication patterns for AI-powered banking systems*