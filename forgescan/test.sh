```bash
#!/bin/bash

echo "🧪 ForgeScan Quick Test"
echo "======================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test 1: Services
echo "1️⃣  Checking if services are running..."
if docker-compose ps | grep -q "Up"; then
  echo -e "${GREEN}✅ Services running${NC}"
else
  echo -e "${RED}❌ Services not running${NC}"
  echo "Run: docker-compose up -d"
  exit 1
fi

# Test 2: Backend
echo ""
echo "2️⃣  Testing backend API..."
if curl -s http://localhost:8000/health | grep -q "healthy"; then
  echo -e "${GREEN}✅ Backend healthy${NC}"
else
  echo -e "${RED}❌ Backend not responding${NC}"
fi

# Test 3: Frontend
echo ""
echo "3️⃣  Testing frontend..."
if curl -s http://localhost:3000 > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Frontend running${NC}"
else
  echo -e "${RED}❌ Frontend not responding${NC}"
fi

# Test 4: Database
echo ""
echo "4️⃣  Testing database..."
if docker-compose exec -T db psql -U forgescan -d forgescan -c "SELECT 1" > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Database connected${NC}"
else
  echo -e "${RED}❌ Database connection failed${NC}"
fi

# Test 5: Login
echo ""
echo "5️⃣  Testing login..."
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@forgescan.com","password":"TestPassword123!"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null)

if [ ! -z "$TOKEN" ]; then
  echo -e "${GREEN}✅ Login successful${NC}"
  
  # Test 6: Create Scan
  echo ""
  echo "6️⃣  Testing scan creation..."
  SCAN=$(curl -s -X POST http://localhost:8000/api/v1/scans \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"scanner_type":"web","target":"https://example.com","options":{"depth":1}}')
  
  if echo "$SCAN" | grep -q "id"; then
    echo -e "${GREEN}✅ Scan creation works${NC}"
  else
    echo -e "${RED}❌ Scan creation failed${NC}"
  fi
else
  echo -e "${RED}❌ Login failed${NC}"
fi

echo ""
echo "================================"
echo "🎉 Tests complete!"
echo ""
echo "Access the app:"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000/docs"
echo ""
echo "Login with:"
echo "  Email:    test@forgescan.com"
echo "  Password: TestPassword123!"