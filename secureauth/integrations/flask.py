
from flask import Blueprint, request, jsonify
from pathlib import Path
from bson import ObjectId
import tempfile
import os


def create_auth_blueprint(
    secure_auth,
    url_prefix="/secureauth",
    authorize_user=None,
    on_qr_authenticated=None
):
    auth_bp = Blueprint(
        "secureauth",
        __name__,
        url_prefix=url_prefix
    )

    # AUTHORIZATION
    def is_authorized(user_id, action):
        if authorize_user is None:
            return False

        try:
            return authorize_user(user_id, action) is True
        except Exception:
            return False

    # Convert string IDs into MongoDB ObjectIds when possible
    def normalize_user_id(user_id):
        try:
            return ObjectId(user_id)
        except Exception:
            return user_id

    # Validate uploaded image extension
    def validate_image(image):
        extension = Path(
            image.filename or ""
        ).suffix.lower()

        if extension not in {".jpg", ".jpeg", ".png"}:
            return None

        return extension

    # HOME / HEALTH CHECK
    @auth_bp.route("/", methods=["GET"])
    def home():
        return jsonify({
            "message": "SecureAuth integration is running"
        }), 200

    # FACE ENROLLMENT
    @auth_bp.route("/face/enroll", methods=["POST"])
    def enroll_face():
        user_id = request.form.get("user_id")
        image = request.files.get("image")

        if not user_id or not image:
            return jsonify({
                "error": "User ID and face image are required"
            }), 400

        user_id = normalize_user_id(user_id)

        if not is_authorized(user_id, "enroll_face"):
            return jsonify({
                "error": "Unauthorized to enroll face for this user"
            }), 403

        extension = validate_image(image)

        if not extension:
            return jsonify({
                "error": "Only JPG, JPEG and PNG images are allowed"
            }), 400

        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                suffix=extension,
                delete=False
            ) as temp_file:
                temp_path = temp_file.name
                image.save(temp_path)

            result = secure_auth.authentication.enroll_face(
                user_id,
                temp_path
            )

            return jsonify(result), 200

        except ValueError as error:
            return jsonify({
                "error": str(error)
            }), 400

        except Exception as error:
            print("SecureAuth enrollment error:", error)

            return jsonify({
                "error": "Face enrollment failed"
            }), 500

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    # FACE VERIFICATION
    @auth_bp.route("/face/verify", methods=["POST"])
    def verify_face():
        user_id = request.form.get("user_id")
        image = request.files.get("image")

        if not user_id or not image:
            return jsonify({
                "error": "User ID and face image are required"
            }), 400

        user_id = normalize_user_id(user_id)

        extension = validate_image(image)

        if not extension:
            return jsonify({
                "error": "Only JPG, JPEG and PNG images are allowed"
            }), 400

        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                suffix=extension,
                delete=False
            ) as temp_file:
                temp_path = temp_file.name
                image.save(temp_path)

            result = secure_auth.authentication.verify_face(
                user_id,
                temp_path
            )

            status_code = (
                200 if result["success"] else 401
            )

            return jsonify(result), status_code

        except ValueError as error:
            return jsonify({
                "error": str(error)
            }), 400

        except Exception as error:
            print("SecureAuth verification error:", error)

            return jsonify({
                "error": "Face verification failed"
            }), 500

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    # GENERATE QR CREDENTIAL
    @auth_bp.route("/qr/generate", methods=["POST"])
    def generate_qr():
        data = request.get_json(silent=True)

        if not data or not data.get("user_id"):
            return jsonify({
                "error": "User ID is required"
            }), 400

        user_id = normalize_user_id(data["user_id"])

        if not is_authorized(user_id, "generate_qr"):
            return jsonify({
                "error": "Unauthorized to generate QR credentials for this user"
            }), 403

        try:
            result = secure_auth.qr.generate_credential(user_id)

            return jsonify(result), 201

        except Exception as error:
            print("QR generation error:", error)

            return jsonify({
                "error": "QR credential generation failed"
            }), 500

    # VERIFY QR CREDENTIAL
    @auth_bp.route("/qr/verify", methods=["POST"])
    def verify_qr():
        data = request.get_json(silent=True)

        if not data or not data.get("token"):
            return jsonify({
                "error": "QR credential is required"
            }), 400

        try:
            user_id = secure_auth.qr.verify_credential(
                data["token"]
            )

            if user_id is None:
                return jsonify({
                    "authenticated": False,
                    "error": "Invalid or revoked QR credential"
                }), 401

            # Notify the host application after successful verification
            if on_qr_authenticated is not None:
                try:
                    on_qr_authenticated(user_id)

                except Exception:
                    print("QR authentication callback failed")

                    return jsonify({
                        "authenticated": False,
                        "error": "QR authentication could not be completed"
                    }), 500

            return jsonify({
                "authenticated": True,
                "user_id": str(user_id),
                "message": "QR credential verified"
            }), 200

        except Exception as error:
            print("QR verification error:", error)

            return jsonify({
                "error": "QR verification failed"
            }), 500

    # PASSWORD FALLBACK AUTHENTICATION
    @auth_bp.route("/password/verify", methods=["POST"])
    def verify_password():
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "error": "Invalid JSON request"
            }), 400

        user_id = data.get("user_id")
        password = data.get("password")

        if not user_id or not password:
            return jsonify({
                "error": "User ID and password are required"
            }), 400

        user_id = normalize_user_id(user_id)

        try:
            result = secure_auth.password.verify(
                user_id,
                password
            )

            if result["success"]:
                return jsonify(result), 200

            if result.get("locked"):
                return jsonify(result), 403

            message = result.get("message", "")

            if message in {
                "Face fallback is not available yet.",
                "No authentication attempts found.",
                "User not found."
            }:
                return jsonify(result), 403

            return jsonify(result), 401

        except Exception as error:
            print("Password fallback error:", error)

            return jsonify({
                "error": "Password verification failed"
            }), 500

    return auth_bp
