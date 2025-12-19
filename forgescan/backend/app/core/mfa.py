# backend/app/core/mfa.py
"""
TOTP-based MFA using pyotp
"""

import pyotp
import qrcode
from io import BytesIO
import base64

class MFAService:
    """Handle MFA enrollment and verification"""
    
    def generate_secret(self, user_email: str) -> dict:
        """Generate MFA secret for user"""
        secret = pyotp.random_base32()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name='ForgeScan'
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'secret': secret,
            'qr_code': qr_code,
            'backup_codes': self.generate_backup_codes()
        }
    
    def verify_token(self, secret: str, token: str) -> bool:
        """Verify MFA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 30s drift
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes"""
        return [
            pyotp.random_base32()[:8] for _ in range(count)
        ]

# Database model
class User(Base):
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret_encrypted = Column(Text)
    backup_codes_encrypted = Column(JSON)
    last_mfa_used = Column(DateTime)

# API endpoint
@router.post("/mfa/setup")
async def setup_mfa(current_user: User = Depends(get_current_user)):
    """Setup MFA for user"""
    mfa = MFAService()
    mfa_data = mfa.generate_secret(current_user.email)
    
    # Encrypt and store secret
    current_user.mfa_secret_encrypted = encrypt(mfa_data['secret'])
    current_user.backup_codes_encrypted = [
        encrypt(code) for code in mfa_data['backup_codes']
    ]
    
    return {
        'qr_code': mfa_data['qr_code'],
        'backup_codes': mfa_data['backup_codes']
    }

@router.post("/auth/login-mfa")
async def login_with_mfa(
    email: str,
    password: str,
    mfa_token: str,
    db: Session = Depends(get_db)
):
    """Login with MFA verification"""
    user = authenticate_user(email, password)
    
    if user.mfa_enabled:
        secret = decrypt(user.mfa_secret_encrypted)
        if not MFAService().verify_token(secret, mfa_token):
            raise HTTPException(401, "Invalid MFA token")
    
    return generate_token(user)