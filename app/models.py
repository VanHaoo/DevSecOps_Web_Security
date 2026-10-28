from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


def utcnow():
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


from app import db, login_manager


class User(UserMixin, db.Model):
    """User model with role-based access control."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    def set_password(self, password):
        """Hash and store password securely."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Product(db.Model):
    """Product model."""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=True)
    stock = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self):
        return f'<Product {self.name}>'


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return db.session.get(User, int(user_id))
