# backend/app/core/sso.py
"""
SAML 2.0 and OAuth 2.0 SSO integration
Support for Okta, Azure AD, Google Workspace
"""

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from authlib.integrations.starlette_client import OAuth

class SSOService:
    """Enterprise SSO integration"""
    
    def __init__(self):
        self.oauth = OAuth()
        
        # Google Workspace
        self.oauth.register(
            name='google',
            client_id=os.environ['GOOGLE_CLIENT_ID'],
            client_secret=os.environ['GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'}
        )
        
        # Microsoft Azure AD
        self.oauth.register(
            name='microsoft',
            client_id=os.environ['AZURE_CLIENT_ID'],
            client_secret=os.environ['AZURE_CLIENT_SECRET'],
            server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'}
        )
    
    async def init_saml_auth(self, request) -> OneLogin_Saml2_Auth:
        """Initialize SAML authentication"""
        saml_settings = {
            'sp': {
                'entityId': f'{os.environ["APP_URL"]}/saml/metadata',
                'assertionConsumerService': {
                    'url': f'{os.environ["APP_URL"]}/saml/acs',
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                },
            },
            'idp': {
                'entityId': os.environ['SAML_IDP_ENTITY_ID'],
                'singleSignOnService': {
                    'url': os.environ['SAML_IDP_SSO_URL'],
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'x509cert': os.environ['SAML_IDP_CERT']
            }
        }
        
        return OneLogin_Saml2_Auth(request, saml_settings)

# Database model
class SSOConfig(Base):
    tenant_id = Column(String(100), ForeignKey('tenants.id'))
    provider = Column(String(50))  # google, microsoft, okta, saml
    config = Column(JSON)
    enabled = Column(Boolean, default=True)

@router.get("/auth/sso/{provider}")
async def sso_login(provider: str, request: Request):
    """Initiate SSO login"""
    oauth = OAuth()
    redirect_uri = f"{os.environ['APP_URL']}/auth/sso/{provider}/callback"
    return await oauth.create_client(provider).authorize_redirect(request, redirect_uri)