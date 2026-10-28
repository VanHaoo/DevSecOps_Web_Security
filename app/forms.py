from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, TextAreaField,
    FloatField, IntegerField, EmailField
)
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo, ValidationError,
    NumberRange, Optional
)
from app.models import User


class RegistrationForm(FlaskForm):
    """User registration form with validation."""
    username = StringField('Tên đăng nhập', validators=[
        DataRequired(message='Vui lòng nhập tên đăng nhập.'),
        Length(min=3, max=80, message='Tên đăng nhập phải từ 3-80 ký tự.')
    ])
    email = EmailField('Email', validators=[
        DataRequired(message='Vui lòng nhập email.'),
        Email(message='Email không hợp lệ.')
    ])
    password = PasswordField('Mật khẩu', validators=[
        DataRequired(message='Vui lòng nhập mật khẩu.'),
        Length(min=8, message='Mật khẩu phải có ít nhất 8 ký tự.')
    ])
    confirm_password = PasswordField('Xác nhận mật khẩu', validators=[
        DataRequired(message='Vui lòng xác nhận mật khẩu.'),
        EqualTo('password', message='Mật khẩu xác nhận không khớp.')
    ])
    submit = SubmitField('Đăng ký')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Tên đăng nhập đã tồn tại.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email đã được sử dụng.')


class LoginForm(FlaskForm):
    """User login form."""
    username = StringField('Tên đăng nhập', validators=[
        DataRequired(message='Vui lòng nhập tên đăng nhập.')
    ])
    password = PasswordField('Mật khẩu', validators=[
        DataRequired(message='Vui lòng nhập mật khẩu.')
    ])
    submit = SubmitField('Đăng nhập')


class ProfileForm(FlaskForm):
    """User profile update form."""
    email = EmailField('Email', validators=[
        DataRequired(message='Vui lòng nhập email.'),
        Email(message='Email không hợp lệ.')
    ])
    submit = SubmitField('Cập nhật')


class ProductForm(FlaskForm):
    """Product create/edit form."""
    name = StringField('Tên sản phẩm', validators=[
        DataRequired(message='Vui lòng nhập tên sản phẩm.'),
        Length(max=200, message='Tên sản phẩm không quá 200 ký tự.')
    ])
    description = TextAreaField('Mô tả', validators=[
        Optional(),
        Length(max=2000, message='Mô tả không quá 2000 ký tự.')
    ])
    price = FloatField('Giá (VNĐ)', validators=[
        DataRequired(message='Vui lòng nhập giá.'),
        NumberRange(min=0, message='Giá phải lớn hơn hoặc bằng 0.')
    ])
    category = StringField('Danh mục', validators=[
        Optional(),
        Length(max=100, message='Danh mục không quá 100 ký tự.')
    ])
    stock = IntegerField('Số lượng tồn kho', validators=[
        DataRequired(message='Vui lòng nhập số lượng.'),
        NumberRange(min=0, message='Số lượng phải lớn hơn hoặc bằng 0.')
    ])
    image_url = StringField('URL hình ảnh', validators=[
        Optional(),
        Length(max=500)
    ])
    submit = SubmitField('Lưu')
