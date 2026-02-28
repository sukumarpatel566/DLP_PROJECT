import os
import pymysql
pymysql.install_as_MySQLdb()

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify
from config import Config
from extensions import db, jwt, bcrypt
from flask_cors import CORS

# Import blueprints
from routes.general import general_bp
from routes.auth import auth_bp
from routes.files import files_bp
from routes.admin import admin_bp
from routes.users import users_bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ==============================
    # FILE UPLOAD SETTINGS
    # ==============================
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

    upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')

    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    app.config['UPLOAD_FOLDER'] = upload_folder

    # ==============================
    # INITIALIZE EXTENSIONS
    # ==============================
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # ==============================
    # ENABLE CORS (FIXED)
    # ==============================
    CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

    # ==============================
    # REGISTER BLUEPRINTS
    # ==============================
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(files_bp, url_prefix='/api/files')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(general_bp, url_prefix='/api')
    
    # ==============================
    # SERVE STATIC UPLOADS
    # ==============================
    from flask import send_from_directory
    @app.route('/uploads/<path:filename>')
    def uploaded_file(filename):
        return send_from_directory('uploads', filename)

    # ==============================
    # HEALTH CHECK ROUTE
    # ==============================
    @app.route("/")
    def index():
        return jsonify({
            "success": True,
            "message": "Intelligent DLP System API is running",
            "status": "ok",
            "version": "1.0.0"
        }), 200

    # ==============================
    # GLOBAL ERROR HANDLERS
    # ==============================

    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"success": False, "message": "Resource not found"}), 404

    @app.errorhandler(401)
    def handle_401(e):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    @app.errorhandler(403)
    def handle_403(e):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    @app.errorhandler(413)
    def handle_413(e):
        return jsonify({"success": False, "message": "File too large (Max 16MB)"}), 413

    @app.errorhandler(500)
    def handle_500(e):
        app.logger.error(f"Internal Server Error: {str(e)}")
        return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error(f"Global Exception: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Unexpected error occurred",
            "error": str(e)
        }), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)