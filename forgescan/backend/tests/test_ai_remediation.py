# tests/test_ai_remediation.py
"""
AI remediation feature tests
Tests: GPT-4 integration, fix suggestions, code generation
"""

import pytest
from unittest.mock import patch, AsyncMock

class TestAIRemediation:
    """Test AI-powered remediation"""
    
    @pytest.mark.asyncio
    @patch('openai.ChatCompletion.acreate')
    async def test_get_ai_remediation(self, mock_openai, client, auth_headers, test_user, db_session):
        """Test AI generates remediation suggestions"""
        
        # Mock OpenAI response
        mock_openai.return_value = AsyncMock()
        mock_openai.return_value.choices = [
            type('obj', (object,), {
                'message': type('obj', (object,), {
                    'content': '''
                    Here's how to fix the XSS vulnerability:
                    
                    1. Sanitize user input using DOMPurify
                    2. Use textContent instead of innerHTML
                    3. Example code:
                    
                    ```javascript
                    const sanitized = DOMPurify.sanitize(userInput);
                    element.textContent = sanitized;
                    ```
                    '''
                })()
            })()
        ]
        
        # Create a finding first
        from app.db.models.finding import Finding
        finding = Finding(
            tenant_id=test_user.tenant_id,
            scan_id=uuid4(),
            title="Cross-Site Scripting (XSS)",
            severity="high",
            category="xss",
            description="XSS vulnerability in search parameter"
        )
        db_session.add(finding)
        await db_session.commit()
        
        # Get AI remediation
        response = client.get(
            f"/api/v1/findings/{finding.id}/ai-remediation",
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "remediation_steps" in data
        assert "code_example" in data
        assert "DOMPurify" in data["code_example"]
    
    @pytest.mark.asyncio
    async def test_ai_remediation_rate_limit(self, client, auth_headers):
        """Test AI remediation respects rate limits"""
        
        # Make multiple requests
        for i in range(10):
            response = client.get(
                f"/api/v1/findings/some-id/ai-remediation",
                headers=auth_headers
            )
        
        # 11th request should be rate limited
        response = client.get(
            f"/api/v1/findings/some-id/ai-remediation",
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

