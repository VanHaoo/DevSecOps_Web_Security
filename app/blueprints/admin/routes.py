from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from app import db
from app.models import Product, User
from app.forms import ProductForm

admin_bp = Blueprint('admin', __name__, template_folder='../../templates/admin')


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/')
@admin_required
def dashboard():
    """Admin dashboard."""
    product_count = Product.query.count()
    user_count = User.query.count()
    return render_template(
        'admin/dashboard.html',
        product_count=product_count,
        user_count=user_count
    )


@admin_bp.route('/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    """Add a new product."""
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            category=form.category.data,
            stock=form.stock.data,
            image_url=form.image_url.data
        )
        db.session.add(product)
        db.session.commit()
        flash('Thêm sản phẩm thành công!', 'success')
        return redirect(url_for('admin.dashboard'))
    return render_template('admin/product_form.html', form=form, title='Thêm sản phẩm')


@admin_bp.route('/products/<int:product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    """Edit an existing product."""
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.category = form.category.data
        product.stock = form.stock.data
        product.image_url = form.image_url.data
        db.session.commit()
        flash('Cập nhật sản phẩm thành công!', 'success')
        return redirect(url_for('admin.dashboard'))
    return render_template('admin/product_form.html', form=form, title='Sửa sản phẩm')


@admin_bp.route('/products/<int:product_id>/delete', methods=['POST'])
@admin_required
def delete_product(product_id):
    """Delete a product."""
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    db.session.delete(product)
    db.session.commit()
    flash('Xóa sản phẩm thành công!', 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/users')
@admin_required
def user_list():
    """List all users."""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)
