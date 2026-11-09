"""Blueprints package aggregating all modular Flask route controllers."""
from app.blueprints.main import main_bp
from app.blueprints.auth import auth_bp
from app.blueprints.products import products_bp
from app.blueprints.admin import admin_bp

__all__ = ['main_bp', 'auth_bp', 'products_bp', 'admin_bp']
