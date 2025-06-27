from main import init_database, app

if __name__ == '__main__':
    with app.app_context():
        init_database()
        print("База данных инициализирована!")
        print("Тестовый пользователь: test@example.com / password123")
        print("Модератор: moderator@moderator.moderator / moderator")
        print("Администратор: admin@admin.admin / admin") 