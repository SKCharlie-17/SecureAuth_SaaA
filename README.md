
# SecureAuth

A modular Python authentication library that provides face recognition, QR-based credentials, and password fallback authentication.

## Features

- Face enrollment and verification using OpenCV YuNet and SFace.
- QR credential generation, verification, and revocation.
- Password fallback through a host application's password verification function.
- MongoDB integration using an existing database connection.
- Flask Blueprint integration for REST API endpoints.

## imp- read line 56 :-D

## Requirements

- Python 3.10+
- MongoDB
- OpenCV
- NumPy
- PyMongo

## Installation

Install the core package:

```bash
pip install secureauth
```

For Flask integration:

```bash
pip install "secureauth[flask]"
```

## Basic Usage

```python
from pymongo import MongoClient
from secureauth import SecureAuth

client = MongoClient("mongodb://localhost:27017/")
db = client["YourApplication"]

def password_verifier(user, password):
    # Replace with your application's password verification logic.
    return False

auth = SecureAuth(
    db=db,
    password_verifier=password_verifier
)
```
## password verifier here is to be replaced with the  host applications actual password checking logic before authentication can work


## Flask Integration

```python
from flask import Flask
from secureauth.integrations import create_auth_blueprint

app = Flask(__name__)

auth_blueprint = create_auth_blueprint(auth)

app.register_blueprint(auth_blueprint)

if __name__ == "__main__":
    app.run(debug=True)
```

The integration provides endpoints for:

- Face enrollment
- Face verification
- QR credential generation
- QR credential verification
- Password fallback verification

The default URL prefix is `/secureauth`.

## Database

SecureAuth uses the MongoDB database supplied by the host application.

It does not create a separate MongoDB connection or manage the host application's passwords.

It creates its own collections for credentials, face data, authentication logs, security alerts, trusted devices, and authentication attempts.

## Security Considerations

- The host application is responsible for user sessions and authorization.
- Face enrollment and QR credential generation must be protected by the host application.
- Password verification must be implemented by the host application.
- Face recognition does not currently include liveness detection or anti-spoofing.
- The default face similarity threshold requires further calibration.
- Additional security hardening is required before production deployment.

## Project Status

Version: 0.1.0

This project is under active development.
