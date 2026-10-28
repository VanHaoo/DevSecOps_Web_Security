"""Shared test fixtures using in-memory SQLite database."""
import pytest
from app import create_app, db as _db
from app.models import User, Product


@pytest.fixture(scope='function')
def app():
    """Create application for testing with in-memory database."""
    app = create_app('testing')
    yield app


@pytest.fixture(scope='function')
def db(app):
    """Provide a clean database for each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app, db):
    """Provide a test client."""
    return app.test_client()


@pytest.fixture(scope='function')
def admin_user(db):
    """Create an admin user."""
    user = User(username='admin', email='admin@test.com', is_admin=True)
    user.set_password('Admin@123456')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope='function')
def regular_user(db):
    """Create a regular user."""
    user = User(username='testuser', email='test@test.com', is_admin=False)
    user.set_password('Test@123456')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope='function')
def sample_product(db):
    """Create a sample product."""
    product = Product(
        name='Test Product',
        description='A test product for testing',
        price=100000,
        category='Test',
        stock=10
    )
    db.session.add(product)
    db.session.commit()
    return product


def login(client, username, password):
    """Helper function to log in a user."""
    return client.post('/auth/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


def logout(client):
    """Helper function to log out."""
    return client.get('/auth/logout', follow_redirects=True)
