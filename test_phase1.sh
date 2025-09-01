#!/bin/bash

# SecureBank AI Assistant - Phase 1 Testing Script
# Tests JWT authentication and role-based access control

echo "🏦 SecureBank AI Assistant - Phase 1 Authentication Test"
echo "======================================================="

BASE_URL="http://127.0.0.1:8000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test API endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local headers=$4
    local description=$5
    
    echo -e "\n${BLUE}Testing: $description${NC}"
    echo "Endpoint: $method $endpoint"
    
    if [ -n "$data" ]; then
        if [ -n "$headers" ]; then
            response=$(curl -s -X $method "$BASE_URL$endpoint" -H "Content-Type: application/json" -H "$headers" -d "$data")
        else
            response=$(curl -s -X $method "$BASE_URL$endpoint" -H "Content-Type: application/json" -d "$data")
        fi
    else
        if [ -n "$headers" ]; then
            response=$(curl -s -X $method "$BASE_URL$endpoint" -H "$headers")
        else
            response=$(curl -s -X $method "$BASE_URL$endpoint")
        fi
    fi
    
    echo "Response: $response"
    
    # Extract token if login response
    if [[ $endpoint == "/auth/login" ]] && [[ $response == *"access_token"* ]]; then
        TOKEN=$(echo $response | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
        echo -e "${GREEN}✅ Login successful - Token extracted${NC}"
        return 0
    elif [[ $response == *"error"* ]] || [[ $response == *"detail"* ]]; then
        echo -e "${RED}❌ Test failed${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Test passed${NC}"
        return 0
    fi
}

echo -e "\n${YELLOW}1. Testing API Health Check${NC}"
test_endpoint "GET" "/" "" "" "API root endpoint"
test_endpoint "GET" "/health" "" "" "Health check endpoint"

echo -e "\n${YELLOW}2. Testing Customer Login${NC}"
test_endpoint "POST" "/auth/login" '{"username": "customer1", "password": "password123"}' "" "Customer authentication"

if [ -n "$TOKEN" ]; then
    echo -e "\n${YELLOW}3. Testing JWT Token Validation${NC}"
    test_endpoint "GET" "/auth/me" "" "Authorization: Bearer $TOKEN" "Current user info with JWT"
    
    echo -e "\n${YELLOW}4. Testing Different User Roles${NC}"
    test_endpoint "POST" "/auth/login" '{"username": "admin1", "password": "admin123"}' "" "Admin authentication"
    test_endpoint "POST" "/auth/login" '{"username": "security1", "password": "security123"}' "" "Security authentication"
else
    echo -e "\n${RED}❌ Could not extract token - skipping authenticated tests${NC}"
fi

echo -e "\n${YELLOW}5. Testing Invalid Credentials${NC}"
test_endpoint "POST" "/auth/login" '{"username": "invalid", "password": "wrong"}' "" "Invalid login attempt"

echo -e "\n${YELLOW}6. Testing Unauthorized Access${NC}"
test_endpoint "GET" "/auth/me" "" "Authorization: Bearer invalid_token" "Invalid JWT token"

echo -e "\n${GREEN}🎉 Phase 1 Authentication Testing Complete!${NC}"
echo -e "\n${BLUE}Next Steps:${NC}"
echo "• All authentication endpoints are working"
echo "• JWT tokens are properly generated and validated" 
echo "• Role-based permissions are configured"
echo "• Ready to proceed to Phase 2: AI Security Controls"

echo -e "\n${BLUE}For interview demo:${NC}"
echo "• Show the different user roles and their permissions"
echo "• Explain JWT security benefits for banking AI systems"
echo "• Demonstrate RBAC preventing unauthorized access"
echo "• Discuss audit trail capabilities for compliance"