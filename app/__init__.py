import os
from flask import Flask
from dotenv import load_dotenv
from app.routes import routes
from app.auth import auth_bp
from database import close_db

# Load .env file for SMTP configuration
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

    app.register_blueprint(routes)
    app.register_blueprint(auth_bp)
    app.teardown_appcontext(close_db)

    return app