
import bcrypt
import uuid

from datetime import datetime, timezone
from getpass import getpass

from server.database import db
from secureauth.database import MongoAdapter
from secureauth.core import PasswordFallback


database = MongoAdapter(db)
database.initialize()

# Create a temporary test account using the host app's password format
test_password = "SecureAuthTest123!"

password_hash = bcrypt.hashpw(
    test_password.encode("utf-8"),
    bcrypt.gensalt()
).decode("utf-8")

test_user = {
    "full_name": "SecureAuth Test",
    "username": f"secureauth_test_{uuid.uuid4().hex[:8]}",
    "email": f"{uuid.uuid4().hex}@example.com",
    "password_hash": password_hash,
    "created_at": datetime.now(timezone.utc)
}

result = database.users.insert_one(test_user)
user_id = result.inserted_id

# Simulate three failed face attempts in SecureAuth's collection
database.auth_attempts.update_one(
    {"user_id": user_id},
    {
        "$set": {
            "face_failed_attempts": 3,
            "password_fallback_failures": 0
        }
    },
    upsert=True
)

# Reuse the host application's bcrypt verification logic
def password_verifier(user, password):
    stored_hash = user.get("password_hash")

    if not stored_hash:
        return False

    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


fallback = PasswordFallback(
    database=database,
    password_verifier=password_verifier
)

try:
    print("Testing incorrect passwords...")

    for attempt in range(1, 6):
        response = fallback.verify(user_id, "WrongPassword123!")

        print(f"Attempt {attempt}: {response}")

    assert response["success"] is False
    assert response["locked"] is True

    print("[PASS] Five-attempt password lockout works!")

finally:
    database.auth_attempts.delete_one({"user_id": user_id})
    database.users.delete_one({"_id": user_id})
    print("Temporary test account cleaned up.")