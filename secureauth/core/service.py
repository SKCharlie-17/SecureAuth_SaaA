
from secureauth.database import MongoAdapter
from secureauth.core.face_engine import FaceEngine
from secureauth.core.authentication import AuthenticationCore
from secureauth.core.qr_manager import QRManager
from secureauth.core.password_fallback import PasswordFallback


class SecureAuth:

    def __init__(
        self,
        db,
        password_verifier,
        users_collection="users",
        face_threshold=0.363,
        max_face_attempts=3,
        max_password_attempts=5
    ):

        self.database = MongoAdapter(
            db,
            users_collection=users_collection
        )

        self.database.initialize()

        self.face_engine = FaceEngine()

        self.authentication = AuthenticationCore(
            database=self.database,
            face_engine=self.face_engine,
            face_threshold=face_threshold,
            max_face_attempts=max_face_attempts
        )

        self.qr = QRManager(
            database=self.database
        )

        self.password = PasswordFallback(
            database=self.database,
            password_verifier=password_verifier,
            max_face_attempts=max_face_attempts,
            max_password_attempts=max_password_attempts
        )
