from flask import Blueprint, render_template, request, abort
from app.models import Product

products_bp = Blueprint('products', __name__, template_folder='../../templates/products')


@products_bp.route('/')
def product_list():
    """Display all products with optional search."""
    query = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()

    products_query = Product.query

    if query:
        products_query = products_query.filter(
            Product.name.ilike(f'%{query}%') |
            Product.description.ilike(f'%{query}%')
        )

    if category:
        products_query = products_query.filter_by(category=category)

    products = products_query.order_by(Product.created_at.desc()).all()

    # Get distinct categories for filter
    categories = db.session.query(Product.category).filter(
        Product.category.isnot(None),
        Product.category != ''
    ).distinct().all()
    categories = [c[0] for c in categories]

    return render_template(
        'products/list.html',
        products=products,
        query=query,
        categories=categories,
        selected_category=category
    )


@products_bp.route('/<int:product_id>')
def product_detail(product_id):
    """Display product details."""
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    return render_template('products/detail.html', product=product)


# Import db at module level for category query
from app import db  # noqa: E402
