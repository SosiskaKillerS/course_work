import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    
    # Получаем DATABASE_URL из переменных окружения
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # Если DATABASE_URL не задан, используем Railway
    if not DATABASE_URL:
        # Для локальной разработки используем PUBLIC_URL
        if os.environ.get('FLASK_ENV') == 'development':
            DATABASE_URL = "postgresql://postgres:RDKfrkCYOuTROuupbuGiURnAwpXacgEF@shinkansen.proxy.rlwy.net:27165/railway"
        else:
            # Для production используем PUBLIC_URL (так как Render не может подключиться к internal)
            DATABASE_URL = "postgresql://postgres:RDKfrkCYOuTROuupbuGiURnAwpXacgEF@shinkansen.proxy.rlwy.net:27165/railway"
    
    # Для Railway PostgreSQL (если URL начинается с postgres://)
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1) 