
from server.database import db

from secureauth.core import FaceEngine, AuthenticationCore
from secureauth.database import MongoAdapter


def test_secureauth():

    print("\nTesting SecureAuth...\n")

    # 1. Initialize database adapter
    database = MongoAdapter(db)
    database.initialize()

    print("[PASS] MongoDB adapter initialized")

    # 2. Initialize face engine
    face_engine = FaceEngine()

    print("[PASS] YuNet and SFace models loaded")

    # 3. Initialize authentication core
    auth = AuthenticationCore(
        database=database,
        face_engine=face_engine
    )

    print("[PASS] Authentication core initialized")

    print("\nAll component initialization tests passed!")


if __name__ == "__main__":
    test_secureauth()
