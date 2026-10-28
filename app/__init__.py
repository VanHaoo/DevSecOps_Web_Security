import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_name=None):
    """Application factory pattern."""
    app = Flask(__name__, instance_relative_config=True)

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Default configuration
    app.config['SECRET_KEY'] = os.environ.get(
        'SECRET_KEY', 'dev-secret-key-change-in-production'
    )
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 'sqlite:///app.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Override with test config if provided
    if config_name == 'testing':
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SECRET_KEY'] = 'test-secret-key'

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Vui lòng đăng nhập để truy cập trang này.'
    login_manager.login_message_category = 'warning'

    # Register blueprints
    from app.blueprints.main.routes import main_bp
    from app.blueprints.auth.routes import auth_bp
    from app.blueprints.products.routes import products_bp
    from app.blueprints.admin.routes import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(products_bp, url_prefix='/products')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Create database tables
    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    return app
