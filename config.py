import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    
    # Для локальной разработки используем PUBLIC_URL, для production - внутренний URL
    if os.environ.get('FLASK_ENV') == 'development':
        DATABASE_URL = os.environ.get('DATABASE_URL') or "postgresql://postgres:RDKfrkCYOuTROuupbuGiURnAwpXacgEF@shinkansen.proxy.rlwy.net:27165/railway"
    else:
        DATABASE_URL = os.environ.get('DATABASE_URL') or "postgresql://postgres:RDKfrkCYOuTROuupbuGiURnAwpXacgEF@postgres.railway.internal:5432/railway"
    
    # Для Railway PostgreSQL (если URL начинается с postgres://)
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1) 