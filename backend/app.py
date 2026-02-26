import pymysql
pymysql.install_as_MySQLdb()

from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask, jsonify
from config import Config
from extensions import db, jwt, cors

# Import blueprints
from routes.general import general_bp
from routes.auth import auth_bp
from routes.files import files_bp
from routes.admin import admin_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    from extensions import bcrypt # Import locally if needed or just use extensions
    bcrypt.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001"]}})

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(files_bp, url_prefix='/api/files')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(general_bp, url_prefix='/api')

    @app.route("/")
    def index():
        return jsonify({
            "message": "Intelligent DLP System API is running",
            "status": "ok",
            "version": "1.0.0"
        }), 200

    # Global Error Handlers
    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(401)
    def handle_401(e):
        return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(403)
    def handle_403(e):
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(500)
    def handle_500(e):
        return jsonify({"error": "Internal server error"}), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        # Log the actual error for debugging
        app.logger.error(f"Global Exception: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)