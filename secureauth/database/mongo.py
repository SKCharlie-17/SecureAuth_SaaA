
from pymongo.database import Database


class MongoAdapter:

    def __init__(
        self,
        db: Database,
        users_collection="users"
    ):

        if db is None:
            raise ValueError("A MongoDB database instance is required.")

        self.db = db

        # Host application's existing user collection
        self.users = db[users_collection]

        # SecureAuth's own collections
        self.credentials = db["secureauth_credentials"]
        self.face_data = db["secureauth_face_data"]
        self.auth_logs = db["secureauth_auth_logs"]
        self.security_alerts = db["secureauth_security_alerts"]
        self.trusted_devices = db["secureauth_trusted_devices"]
        self.auth_attempts = db["secureauth_auth_attempts"]

    def initialize(self):

        # Unique credential hashes
        self.credentials.create_index(
            "credential_hash",
            unique=True
        )

        # One active face record per user
        self.face_data.create_index(
            "user_id",
            unique=True
        )

        # Authentication log lookup
        self.auth_logs.create_index("user_id")

        # Security alert lookup
        self.security_alerts.create_index("user_id")

        # Trusted device lookup
        self.trusted_devices.create_index("user_id")

        # Authentication attempt lookup
        self.auth_attempts.create_index("user_id",unique=True)

        return True
