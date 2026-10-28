from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User
from app.forms import RegistrationForm, LoginForm, ProfileForm

auth_bp = Blueprint('auth', __name__, template_folder='../../templates/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Đăng nhập thành công!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
        flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'danger')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('Đã đăng xuất.', 'info')
    return redirect(url_for('main.index'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """View and update user profile."""
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        # Check if email changed and not taken by another user
        if form.email.data != current_user.email:
            existing = User.query.filter_by(email=form.email.data).first()
            if existing:
                flash('Email đã được sử dụng bởi tài khoản khác.', 'danger')
                return render_template('auth/profile.html', form=form)
        current_user.email = form.email.data
        db.session.commit()
        flash('Cập nhật thông tin thành công!', 'success')
        return redirect(url_for('auth.profile'))

    return render_template('auth/profile.html', form=form)
