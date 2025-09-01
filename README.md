# SecureBank AI Assistant

A comprehensive AI security demonstration project showcasing enterprise-grade security controls for banking AI systems.

## Phase 1: ✅ JWT Authentication & RBAC
- Secure user authentication with role-based access control
- Banking-specific user roles (customer/admin/security)
- JWT token management with proper security headers

## Phase 2: 🚧 AI Security Controls (Coming Next)
- Secure RAG implementation for banking documents
- Prompt injection protection and detection
- Content filtering and output validation
- OWASP LLM Top 10 compliance testing

## Phase 3: 🚧 Advanced Security Features (Planned)
- Security monitoring and alerting
- Threat modeling documentation
- Compliance reporting (NIST AI RMF)

## Quick Start
```bash
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

See [Phase 1 Documentation](./docs/phase1-authentication.md) for detailed implementation guide.

## Demo Credentials
- Customer: `customer1` / `password123`
- Admin: `admin1` / `admin123` 
- Security: `security1` / `security123`

---
*Built for AI Security Specialist interview preparation*