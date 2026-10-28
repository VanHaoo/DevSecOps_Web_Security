"""Seed database with sample data for testing."""
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import User, Product


def seed_database():
    """Populate database with sample admin, users, and products."""
    app = create_app()

    with app.app_context():
        # Skip if data already exists
        if User.query.first():
            print("Database already seeded. Skipping.")
            return

        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True
        )
        admin.set_password('Admin@123456')
        db.session.add(admin)

        # Create sample users
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('User@123456')
        db.session.add(user1)

        user2 = User(username='user2', email='user2@example.com')
        user2.set_password('User@123456')
        db.session.add(user2)

        # Create sample products
        products = [
            Product(
                name='Laptop Dell XPS 15',
                description='Laptop cao cấp với màn hình OLED 15.6 inch, Intel Core i7, 16GB RAM, 512GB SSD. Thiết kế mỏng nhẹ, hiệu năng mạnh mẽ phù hợp cho lập trình và đồ họa.',
                price=35000000,
                category='Laptop',
                stock=15,
                image_url='https://placehold.co/400x300/0d6efd/white?text=Dell+XPS+15'
            ),
            Product(
                name='iPhone 15 Pro Max',
                description='Điện thoại thông minh Apple với chip A17 Pro, camera 48MP, màn hình Super Retina XDR 6.7 inch. Khung titanium, bền bỉ và nhẹ.',
                price=34990000,
                category='Điện thoại',
                stock=25,
                image_url='https://placehold.co/400x300/198754/white?text=iPhone+15+Pro'
            ),
            Product(
                name='Samsung Galaxy S24 Ultra',
                description='Flagship Android với bút S Pen tích hợp, camera 200MP, màn hình Dynamic AMOLED 6.8 inch. Tích hợp Galaxy AI.',
                price=31990000,
                category='Điện thoại',
                stock=20,
                image_url='https://placehold.co/400x300/6f42c1/white?text=Galaxy+S24'
            ),
            Product(
                name='MacBook Air M3',
                description='Laptop mỏng nhẹ với chip Apple M3, 8GB RAM, 256GB SSD, màn hình Liquid Retina 13.6 inch. Thời lượng pin lên đến 18 giờ.',
                price=27990000,
                category='Laptop',
                stock=10,
                image_url='https://placehold.co/400x300/dc3545/white?text=MacBook+Air'
            ),
            Product(
                name='Tai nghe Sony WH-1000XM5',
                description='Tai nghe chống ồn cao cấp với âm thanh Hi-Res, thời lượng pin 30 giờ, kết nối Bluetooth 5.2. Thiết kế nhẹ nhàng, thoải mái.',
                price=8490000,
                category='Phụ kiện',
                stock=30,
                image_url='https://placehold.co/400x300/ffc107/dark?text=Sony+XM5'
            ),
            Product(
                name='iPad Pro M4 11 inch',
                description='Máy tính bảng chuyên nghiệp với chip M4, màn hình Ultra Retina XDR, hỗ trợ Apple Pencil Pro. Mỏng nhất từ trước đến nay.',
                price=28990000,
                category='Máy tính bảng',
                stock=12,
                image_url='https://placehold.co/400x300/20c997/white?text=iPad+Pro'
            ),
            Product(
                name='Bàn phím cơ Keychron K8 Pro',
                description='Bàn phím cơ không dây với switch Gateron, hỗ trợ QMK/VIA, kết nối Bluetooth và USB-C. Layout TKL, đèn RGB.',
                price=2490000,
                category='Phụ kiện',
                stock=40,
                image_url='https://placehold.co/400x300/0dcaf0/dark?text=Keychron+K8'
            ),
            Product(
                name='Màn hình LG UltraFine 27 inch 4K',
                description='Màn hình IPS 4K UHD với HDR400, độ phủ màu 95% DCI-P3, USB-C 96W. Phù hợp cho thiết kế và lập trình.',
                price=12990000,
                category='Màn hình',
                stock=8,
                image_url='https://placehold.co/400x300/6610f2/white?text=LG+4K+Monitor'
            ),
        ]

        db.session.add_all(products)
        db.session.commit()

        print(f"Seeded database with:")
        print(f"  - {User.query.count()} users (admin: admin/Admin@123456)")
        print(f"  - {Product.query.count()} products")


if __name__ == '__main__':
    seed_database()
