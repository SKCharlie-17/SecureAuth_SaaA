
import bcrypt
import uuid

from datetime import datetime, timezone
from flask import Flask

from server.database import db

from secureauth import SecureAuth

from secureauth.integrations import create_auth_blueprint

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

app = Flask(__name__)
app.register_blueprint(create_auth_blueprint(auth))

client = app.test_client()


# Create two temporary test accounts
test_password = "SecureAuthTest123!"

def create_test_user():
    unique_id = uuid.uuid4().hex

    user = {
        "full_name": "SecureAuth Test",
        "username": f"secureauth_test_{unique_id}",
        "email": f"{unique_id}@example.com",
        "password_hash": bcrypt.hashpw(
            test_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8"),
        "created_at": datetime.now(timezone.utc)
    }

    result = auth.database.users.insert_one(user)
    user_id = result.inserted_id

    auth.database.auth_attempts.update_one(
        {"user_id": user_id},
        {
            "$set": {
                "face_failed_attempts": 3,
                "password_fallback_failures": 0
            }
        },
        upsert=True
    )

    return user_id


correct_user_id = create_test_user()
wrong_user_id = create_test_user()


try:
        # TEST 0: Unauthorized operations are rejected
    print("\nTesting authorization protection...")

    # QR generation without authorization callback
    response = client.post(
        "/secureauth/qr/generate",
        json={
            "user_id": str(correct_user_id)
        }
    )

    print("QR generation:", response.status_code, response.get_json())

    assert response.status_code == 403

    # Face enrollment without authorization callback
    from io import BytesIO

    response = client.post(
        "/secureauth/face/enroll",
        data={
            "user_id": str(correct_user_id),
            "image": (
                BytesIO(b"test image"),
                "test.jpg"
            )
        },
        content_type="multipart/form-data"
    )

    print("Face enrollment:", response.status_code, response.get_json())

    assert response.status_code == 403

    print("[PASS] Unauthorized operations rejected!")

        # TEST: Authorized QR generation
    print("\nTesting authorized QR generation...")

    def allow_test_user(user_id, action):
        return (
            str(user_id) == str(correct_user_id)
            and action == "generate_qr"
        )

    authorized_app = Flask(__name__)

    authorized_app.register_blueprint(
        create_auth_blueprint(
            auth,
            authorize_user=allow_test_user
        )
    )

    authorized_client = authorized_app.test_client()

    response = authorized_client.post(
        "/secureauth/qr/generate",
        json={
            "user_id": str(correct_user_id)
        }
    )

    print(
        "Authorized QR generation:",
        response.status_code,
        response.get_json()
    )

    assert response.status_code == 201

    qr_token = response.get_json()["token"]

        # TEST: QR authentication callback
    print("\nTesting QR authentication callback...")

    callback_results = []

    def qr_login_callback(user_id):
        callback_results.append(str(user_id))

    callback_app = Flask(__name__)

    callback_app.register_blueprint(
        create_auth_blueprint(
            auth,
            on_qr_authenticated=qr_login_callback
        )
    )

    callback_client = callback_app.test_client()

    response = callback_client.post(
        "/secureauth/qr/verify",
        json={
            "token": qr_token
        }
    )

    print(
        "QR verification:",
        response.status_code,
        response.get_json()
    )

    assert response.status_code == 200
    assert callback_results == [str(correct_user_id)]

    print("[PASS] QR authentication callback executed!")

        # TEST: QR callback failure
    print("\nTesting QR callback failure handling...")

    def failing_qr_callback(user_id):
        raise RuntimeError("Simulated session creation failure")

    failure_app = Flask(__name__)

    failure_app.register_blueprint(
        create_auth_blueprint(
            auth,
            on_qr_authenticated=failing_qr_callback
        )
    )

    failure_client = failure_app.test_client()

    response = failure_client.post(
        "/secureauth/qr/verify",
        json={
            "token": qr_token
        }
    )

    print(
        "Failed callback response:",
        response.status_code,
        response.get_json()
    )

    assert response.status_code == 500
    assert response.get_json()["authenticated"] is False

    print("[PASS] Callback failure handled safely!")

    print("[PASS] Authorized QR generation works!")

        # TEST: Different user must be rejected
    response = authorized_client.post(
        "/secureauth/qr/generate",
        json={
            "user_id": str(wrong_user_id)
        }
    )

    print(
        "Unauthorized different user:",
        response.status_code,
        response.get_json()
    )

    assert response.status_code == 403

    print("[PASS] Different user rejected!")

    # TEST 1: Correct password
    print("\nTesting correct password...")

    response = client.post(
        "/secureauth/password/verify",
        json={
            "user_id": str(correct_user_id),
            "password": test_password
        }
    )

    print(response.status_code, response.get_json())

    assert response.status_code == 200
    assert response.get_json()["success"] is True

    print("[PASS] Correct password accepted!")

    # TEST 2: Five incorrect password attempts
    print("\nTesting incorrect passwords and lockout...")

    for attempt in range(1, 6):

        response = client.post(
            "/secureauth/password/verify",
            json={
                "user_id": str(wrong_user_id),
                "password": "WrongPassword123!"
            }
        )

        result = response.get_json()

        print(f"Attempt {attempt}: {response.status_code} {result}")

    assert response.status_code == 403
    assert result["locked"] is True

    print("[PASS] Five-attempt lockout works through Flask!")

finally:
    if "qr_token" in locals():
        auth.qr.revoke_credential(qr_token)
    # Clean up temporary test records
    for user_id in [correct_user_id, wrong_user_id]:
        auth.database.auth_attempts.delete_one(
            {"user_id": user_id}
        )
        auth.database.auth_logs.delete_many(
            {"user_id": user_id}
        )
        auth.database.users.delete_one(
            {"_id": user_id}
        )

    print("\nTemporary test accounts cleaned up.")
