import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
import pyrebase
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# Initialize Firebase Admin for Firestore (Backend Database)
# This will log a warning if initialized twice, so we check first
if not firebase_admin._apps:
    # Try env var first (for Render deployment), fall back to file (for local dev)
    firebase_creds_json = os.environ.get("FIREBASE_CREDENTIALS")
    if firebase_creds_json:
        cred_dict = json.loads(firebase_creds_json)
        cred = credentials.Certificate(cred_dict)
    else:
        cert_path = os.path.join(BASE_DIR, "firebase_credentials.json")
        cred = credentials.Certificate(cert_path)
    firebase_admin.initialize_app(cred)

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