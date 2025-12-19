from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
resp = client.post('/api/v1/auth/login', json={'email': 'test@example.com', 'password': 'TestPassword123!'})
print('status', resp.status_code)
try:
    print('json', resp.json())
except Exception:
    print('text', resp.text)
