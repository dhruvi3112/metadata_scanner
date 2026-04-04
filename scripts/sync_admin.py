import sys
import os

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import db
from firebase_admin import auth

email = "dhruvipanchal847@gmail.com"
username = "Dhruvi"

try:
    user = auth.get_user_by_email(email)
    print(f"Found Firebase Auth user: {user.uid}")
    
    # Ensure they exist in Firestore
    doc_ref = db.collection("users").document(user.uid)
    doc = doc_ref.get()
    
    if not doc.exists:
        doc_ref.set({
            "username": username,
            "email": email,
            "role": "admin",
            "email_verified": True
        })
        print("Created Firestore document for existing user!")
    else:
        print("Firestore document already exists for this user.")
        
except auth.UserNotFoundError:
    print("User not found in Firebase Auth either. They can safely register.")
except Exception as e:
    print(f"Error: {e}")
