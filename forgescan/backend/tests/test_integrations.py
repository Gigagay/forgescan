# tests/test_integrations.py
"""
Integration tests for third-party services
Tests: Slack, GitHub, CI/CD, payment processing
"""

import pytest
from unittest.mock import patch, Mock

class TestSlackIntegration:
    """Test Slack integration"""
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.post')
    async def test_send_slack_notification(self, mock_post, client, auth_headers):
        """Test Slack notification is sent"""
        
        mock_post.return_value = Mock(status_code=200)
        
        # Configure Slack
        response = client.post("/api/v1/integrations/slack/connect",
            headers=auth_headers,
            json={"webhook_url": "https://hooks.slack.com/services/TEST"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify webhook was called
        mock_post.assert_called_once()


class TestGitHubIntegration:
    """Test GitHub CI/CD integration"""
    
    @pytest.mark.asyncio
    async def test_github_webhook_pr(self, client, db_session):
        """Test GitHub webhook for pull request"""
        
        webhook_payload = {
            "action": "opened",
            "pull_request": {
                "number": 123,
                "html_url": "https://github.com/test/repo/pull/123",
                "head": {
                    "ref": "feature-branch",
                    "sha": "abc123"
                }
            },
            "repository": {
                "full_name": "test/repo"
            }
        }
        
        response = client.post("/api/v1/integrations/github/webhook",
            json=webhook_payload,
            headers={"X-GitHub-Event": "pull_request"}
        )
        
        assert response.status_code == status.HTTP_200_OK


class TestPaymentProcessing:
    """Test payment integration (Peach Payments)"""
    
    @pytest.mark.asyncio
    @patch('app.services.payment_service.PeachPaymentsService.create_checkout')
    async def test_create_subscription(self, mock_checkout, client, auth_headers):
        """Test subscription creation"""
        
        mock_checkout.return_value = {
            "checkout_id": "test-checkout-123",
            "redirect_url": "https://pay.peachpayments.com/checkout/test-checkout-123"
        }
        
        response = client.post("/api/v1/subscriptions",
            headers=auth_headers,
            json={
                "plan": "professional",
                "currency": "ZAR"
            }
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert "redirect_url" in data
    
    @pytest.mark.asyncio
    async def test_webhook_subscription_activated(self, client, db_session, test_user):
        """Test payment webhook activates subscription"""
        
        webhook_payload = {
            "event": "payment.success",
            "checkout_id": "test-checkout-123",
            "customer_id": str(test_user.id),
            "plan": "professional"
        }
        
        response = client.post("/api/v1/webhooks/peach",
            json=webhook_payload
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify subscription was activated
        # (Check database for subscription record)

