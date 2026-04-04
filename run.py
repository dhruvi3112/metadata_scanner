from flask import Flask
from app.routes import routes
from app import create_app

app = create_app()

if __name__ == "__main__":
    import os
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=debug,
        use_reloader=False
    )
