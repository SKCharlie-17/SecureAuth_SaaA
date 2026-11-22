
from datetime import datetime, timezone

import numpy as np


class AuthenticationCore:

    def __init__(
        self,
        database,
        face_engine,
        face_threshold=0.363,
        max_face_attempts=3
    ):

        self.database = database
        self.face_engine = face_engine

        # Experimental threshold. Must be calibrated before production.
        self.face_threshold = face_threshold
        self.max_face_attempts = max_face_attempts

    def _log(self, user_id, method, status):

        self.database.auth_logs.insert_one({
            "user_id": user_id,
            "method": method,
            "status": status,
            "timestamp": datetime.now(timezone.utc)
        })

    def enroll_face(self, user_id, image_path):

        # Confirm that the user belongs to the host application.
        user = self.database.users.find_one({
            "_id": user_id
        })

        if user is None:
            raise ValueError("User does not exist.")

        # Extract face embedding.
        embedding = self.face_engine.extract_face_embedding(
            image_path
        )

        now = datetime.now(timezone.utc)

        # Store SecureAuth's face record.
        self.database.face_data.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "embedding": embedding,
                    "status": "active",
                    "updated_at": now
                },
                "$setOnInsert": {
                    "created_at": now
                }
            },
            upsert=True
        )

        # Reset previous failed attempts.
        self.database.auth_attempts.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "face_failed_attempts": 0,
                    "updated_at": now
                }
            },
            upsert=True
        )

        self._log(user_id, "face_enrollment", "success")

        return {
            "success": True,
            "message": "Face enrollment successful."
        }

    def verify_face(self, user_id, image_path):

        # Confirm host application user.
        user = self.database.users.find_one({
            "_id": user_id
        })

        if user is None:
            raise ValueError("User does not exist.")

        # Retrieve enrolled face.
        stored_face = self.database.face_data.find_one({
            "user_id": user_id,
            "status": "active"
        })

        if stored_face is None:
            raise ValueError("No active face enrollment found.")

        # Extract submitted face embedding.
        submitted_embedding = np.asarray(
            self.face_engine.extract_face_embedding(image_path),
            dtype=np.float32
        )

        enrolled_embedding = np.asarray(
            stored_face["embedding"],
            dtype=np.float32
        )

        # Calculate cosine similarity.
        denominator = (
            np.linalg.norm(submitted_embedding)
            * np.linalg.norm(enrolled_embedding)
        )

        if denominator == 0:
            raise ValueError("Invalid face embedding.")

        similarity = float(np.clip(
            np.dot(submitted_embedding, enrolled_embedding)
            / denominator,
            -1.0,
            1.0
        ))

        matched = similarity >= self.face_threshold

        now = datetime.now(timezone.utc)

        if matched:

            # Reset failed attempts.
            self.database.auth_attempts.update_one(
                {"user_id": user_id},
                {
                    "$set": {
                        "face_failed_attempts": 0,
                        "updated_at": now
                    }
                },
                upsert=True
            )

            self._log(user_id, "face_authentication", "success")

            return {
                "success": True,
                "similarity": similarity,
                "message": "Face verification successful."
            }

        # Record failed attempt.
        self.database.auth_attempts.update_one(
            {"user_id": user_id},
            {
                "$inc": {
                    "face_failed_attempts": 1
                },
                "$set": {
                    "updated_at": now
                }
            },
            upsert=True
        )

        attempts = self.database.auth_attempts.find_one({
            "user_id": user_id
        })

        failed_attempts = attempts["face_failed_attempts"]

        self._log(user_id, "face_authentication", "failed")

        return {
            "success": False,
            "similarity": similarity,
            "failed_attempts": failed_attempts,
            "attempts_remaining": max(
                0,
                self.max_face_attempts - failed_attempts
            ),
            "fallback_available": (
                failed_attempts >= self.max_face_attempts
            ),
            "message": "Face verification failed."
        }
