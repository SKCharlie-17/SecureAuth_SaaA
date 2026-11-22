
from server.database import db

from secureauth.core import QRManager
from secureauth.database import MongoAdapter


def main():

    database = MongoAdapter(db)
    database.initialize()

    # Find an existing test user
    username = input("Enter test username: ")

    user = database.users.find_one({
        "username": username
    })

    if user is None:
        print("User not found.")
        return

    qr = QRManager(database)

    # 1. Generate credential
    print("\nGenerating QR credential...")

    result = qr.generate_credential(user["_id"])

    token = result["token"]

    print(result["message"])
    print("Token generated:", bool(token))

    # 2. Verify credential
    print("\nVerifying credential...")

    verified_user_id = qr.verify_credential(token)

    print("Credential valid:", verified_user_id == user["_id"])

    # 3. Revoke credential
    print("\nRevoking credential...")

    revoked = qr.revoke_credential(token)

    print("Revocation successful:", revoked)

    # 4. Verify revoked credential
    print("\nTesting revoked credential...")

    verified_user_id = qr.verify_credential(token)

    print("Credential rejected:", verified_user_id is None)


if __name__ == "__main__":
    main()
