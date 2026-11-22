from server.database import db

from secureauth.core import FaceEngine, AuthenticationCore
from secureauth.database import MongoAdapter

USERNAME = input("Test username: ")
IMAGE_PATH = r"failed.jpg"


database = MongoAdapter(db)
database.initialize()

user = database.users.find_one({"username": USERNAME})

if user is None:
    print("User not found.")
    raise SystemExit

auth = AuthenticationCore(
    database=database,
    face_engine=FaceEngine()
)

for attempt in range(1, 4):

    print(f"\nAttempt {attempt}")

    result = auth.verify_face(
        user["_id"],
        IMAGE_PATH
    )

    print(result)