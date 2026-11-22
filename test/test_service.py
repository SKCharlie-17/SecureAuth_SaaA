
import bcrypt

from server.database import db
from secureauth import SecureAuth


def password_verifier(user, password):
    stored_hash = user.get("password_hash")

    if not stored_hash:
        return False

    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


auth = SecureAuth(
    db=db,
    password_verifier=password_verifier
)

print("[PASS] SecureAuth service initialized")

print("[PASS] MongoDB adapter:", auth.database is not None)
print("[PASS] Face engine:", auth.face_engine is not None)
print("[PASS] Authentication core:", auth.authentication is not None)
print("[PASS] QR manager:", auth.qr is not None)
print("[PASS] Password fallback:", auth.password is not None)

print("\nAll SecureAuth components initialized successfully!")
