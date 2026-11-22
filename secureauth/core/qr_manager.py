
import secrets
import hashlib

from datetime import datetime, timezone


class QRManager:

    def __init__(self, database):
        self.database = database

    def generate_credential(self, user_id):

        # Generate a cryptographically random token
        token = secrets.token_urlsafe(32)

        # Store only the token hash
        token_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        now = datetime.now(timezone.utc)

        self.database.credentials.insert_one({
            "user_id": user_id,
            "credential_hash": token_hash,
            "status": "active",
            "created_at": now
        })

        # Return raw token only once
        return {
            "success": True,
            "token": token,
            "message": "QR credential generated successfully."
        }

    def verify_credential(self, token):

        if not token:
            return None

        token_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        credential = self.database.credentials.find_one({
            "credential_hash": token_hash,
            "status": "active"
        })

        if credential is None:
            return None

        return credential["user_id"]

    def revoke_credential(self, token):

        token_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        result = self.database.credentials.update_one(
            {
                "credential_hash": token_hash,
                "status": "active"
            },
            {
                "$set": {
                    "status": "revoked",
                    "revoked_at": datetime.now(timezone.utc)
                }
            }
        )

        return result.modified_count == 1
