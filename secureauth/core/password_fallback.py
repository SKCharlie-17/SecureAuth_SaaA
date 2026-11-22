
from datetime import datetime, timezone


class PasswordFallback:

    def __init__(
        self,
        database,
        password_verifier,
        max_face_attempts=3,
        max_password_attempts=5
    ):

        if not callable(password_verifier):
            raise ValueError(
                "A password verification callback is required."
            )

        self.database = database
        self.password_verifier = password_verifier
        self.max_face_attempts = max_face_attempts
        self.max_password_attempts = max_password_attempts

    def verify(self, user_id, password):

        attempts = self.database.auth_attempts.find_one({
            "user_id": user_id
        })

        if attempts is None:
            return {
                "success": False,
                "message": "No authentication attempts found."
            }

        if attempts.get("face_failed_attempts", 0) < self.max_face_attempts:
            return {
                "success": False,
                "message": "Face fallback is not available yet."
            }

        if attempts.get("password_fallback_failures", 0) >= self.max_password_attempts:
            return {
                "success": False,
                "locked": True,
                "message": "Password fallback is locked."
            }

        user = self.database.users.find_one({
            "_id": user_id
        })

        if user is None:
            return {
                "success": False,
                "message": "User not found."
            }

        if not self.password_verifier(user, password):

            now = datetime.now(timezone.utc)

            self.database.auth_attempts.update_one(
                {"user_id": user_id},
                {
                    "$inc": {
                        "password_fallback_failures": 1
                    },
                    "$set": {
                        "updated_at": now
                    }
                }
            )

            updated = self.database.auth_attempts.find_one({
                "user_id": user_id
            })

            failures = updated.get(
                "password_fallback_failures", 0
            )

            return {
                "success": False,
                "locked": failures >= self.max_password_attempts,
                "failed_attempts": failures,
                "attempts_remaining": max(
                    0,
                    self.max_password_attempts - failures
                ),
                "message": "Incorrect password."
            }

        self.database.auth_attempts.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "face_failed_attempts": 0,
                    "password_fallback_failures": 0,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

        self.database.auth_logs.insert_one({
            "user_id": user_id,
            "method": "password_fallback",
            "status": "success",
            "timestamp": datetime.now(timezone.utc)
        })

        return {
            "success": True,
            "message": "Password verification successful."
        }
