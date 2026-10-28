from flask import Blueprint, jsonify, render_template

main_bp = Blueprint('main', __name__, template_folder='../../templates/main')


@main_bp.route('/')
def index():
    """Home page."""
    return render_template('main/index.html')


@main_bp.route('/health')
def health():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'DevSecOps Web Security Lab'
    }), 200
