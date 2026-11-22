
from server.database import db

from secureauth.core import FaceEngine, AuthenticationCore
from secureauth.database import MongoAdapter


USERNAME = input("Enter test account username: ")
IMAGE_PATH = r"test.jpeg"


def main():

    database = MongoAdapter(db)
    database.initialize()

    user = database.users.find_one({
        "username": USERNAME
    })

    if user is None:
        print("Test user not found.")
        return

    user_id = user["_id"]

    face_engine = FaceEngine()

    auth = AuthenticationCore(
        database=database,
        face_engine=face_engine
    )

    print("\nEnrolling face...")

    enrollment = auth.enroll_face(
        user_id,
        IMAGE_PATH
    )

    print(enrollment)

    print("\nVerifying face...")

    result = auth.verify_face(
        user_id,
        IMAGE_PATH
    )

    print(result)


if __name__ == "__main__":
    main()
