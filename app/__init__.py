import os
from flask import Flask
from dotenv import load_dotenv
from app.routes import routes
from app.auth import auth
from database import close_db

# Load .env file for SMTP configuration
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "1234")

    app.register_blueprint(routes)
    app.register_blueprint(auth)
    app.teardown_appcontext(close_db)

    return app