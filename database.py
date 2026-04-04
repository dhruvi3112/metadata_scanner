import os
import json
import sys
import firebase_admin
from firebase_admin import credentials, firestore
import pyrebase
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# Initialize Firebase Admin for Firestore (Backend Database)
# This will log a warning if initialized twice, so we check first
if not firebase_admin._apps:
    try:
        # Try env var first (for Render deployment), fall back to file (for local dev)
        firebase_creds_json = os.environ.get("FIREBASE_CREDENTIALS")
        if firebase_creds_json:
            print("[database.py] Loading Firebase credentials from FIREBASE_CREDENTIALS env var", file=sys.stderr)
            cred_dict = json.loads(firebase_creds_json)
            cred = credentials.Certificate(cred_dict)
        else:
            cert_path = os.path.join(BASE_DIR, "firebase_credentials.json")
            print(f"[database.py] Loading Firebase credentials from file: {cert_path}", file=sys.stderr)
            if not os.path.exists(cert_path):
                print(f"[database.py] ERROR: Firebase credentials file not found at {cert_path}", file=sys.stderr)
                print("[database.py] Set the FIREBASE_CREDENTIALS environment variable with the JSON content", file=sys.stderr)
                sys.exit(1)
            cred = credentials.Certificate(cert_path)
        firebase_admin.initialize_app(cred)
        print("[database.py] Firebase Admin initialized successfully", file=sys.stderr)
    except Exception as e:
        print(f"[database.py] ERROR initializing Firebase: {e}", file=sys.stderr)
        sys.exit(1)

db = firestore.client()

# Initialize Pyrebase for Firebase Auth
firebase_config = {
    "apiKey": os.environ.get("FIREBASE_API_KEY"),
    "authDomain": "metadata-scanner.firebaseapp.com",
    "projectId": "metadata-scanner",
    "databaseURL": "", # Not using realtime DB
    "storageBucket": "metadata-scanner.appspot.com"
}
firebase = pyrebase.initialize_app(firebase_config)
auth = firebase.auth()

def close_db(e=None):
    # Firestore client does not require manual closing per request like SQLite
    pass