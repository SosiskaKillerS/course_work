from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, FloatField, BooleanField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey, Table
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from functools import wraps
import os
from flask_wtf.file import FileField, FileAllowed
import uuid
from werkzeug.utils import secure_filename

# Создаем Flask приложение
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

# Настройка базы данных
DATABASE_URL = "postgresql://postgres:1231@localhost:5434/kinoservice_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Junction tables for many-to-many relationships
movie_actors = Table('movie_actors', Base.metadata,
    Column('movie_id', Integer, ForeignKey('movies.id', ondelete='CASCADE'), primary_key=True),
    Column('actor_id', Integer, ForeignKey('actors.id', ondelete='CASCADE'), primary_key=True)
)

movie_genres = Table('movie_genres', Base.metadata,
    Column('movie_id', Integer, ForeignKey('movies.id', ondelete='CASCADE'), primary_key=True),
    Column('genre_id', Integer, ForeignKey('genres.id', ondelete='CASCADE'), primary_key=True)
)

# Модели базы данных
class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    
    # Отношения
    users = relationship('User', back_populates='role')

class User(UserMixin, Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    hash_password = Column(String(255), nullable=False)
    subscription = Column(String(20), default='free')
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Связи
    role_id = Column(Integer, ForeignKey('roles.id'), default=1)
    
    # Отношения
    role = relationship('Role', back_populates='users')
    reviews = relationship('Review', back_populates='user', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.hash_password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.hash_password, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Director(Base):
    __tablename__ = 'directors'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    
    # Отношения
    movies = relationship('Movie', back_populates='director')

class Actor(Base):
    __tablename__ = 'actors'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    
    # Отношения
    movies = relationship('Movie', secondary=movie_actors, back_populates='actors')

class Genre(Base):
    __tablename__ = 'genres'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    
    # Отношения
    movies = relationship('Movie', secondary=movie_genres, back_populates='genres')

class Movie(Base):
    __tablename__ = 'movies'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    year = Column(Integer)
    poster_path = Column(String(500))
    rating = Column(Float, default=0.0)
    
    # Связи
    director_id = Column(Integer, ForeignKey('directors.id'))
    
    # Отношения
    director = relationship('Director', back_populates='movies')
    genres = relationship('Genre', secondary=movie_genres, back_populates='movies')
    actors = relationship('Actor', secondary=movie_actors, back_populates='movies')
    reviews = relationship('Review', back_populates='movie', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Movie {self.title}>'

class Review(Base):
    __tablename__ = 'reviews'
    
    id = Column(Integer, primary_key=True)
    rating = Column(Float, nullable=False)
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Связи
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    movie_id = Column(Integer, ForeignKey('movies.id'), nullable=False)
    
    # Отношения
    user = relationship('User', back_populates='reviews')
    movie = relationship('Movie', back_populates='reviews')
    
    def __repr__(self):
        return f'<Review {self.user.username} -> {self.movie.title}>'

# Формы
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[
        DataRequired(message='Имя пользователя обязательно'),
        Length(min=3, max=50, message='Имя должно быть от 3 до 50 символов')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email обязателен'),
        Email(message='Введите корректный email'),
        Length(max=255, message='Email слишком длинный')
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message='Пароль обязателен'),
        Length(min=6, message='Пароль должен быть не менее 6 символов')
    ])
    confirm_password = PasswordField('Подтвердите пароль', validators=[
        DataRequired(message='Подтвердите пароль'),
        EqualTo('password', message='Пароли должны совпадать')
    ])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class MovieForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(min=1, max=200)])
    description = TextAreaField('Описание', validators=[DataRequired(), Length(min=10, max=1000)])
    year = IntegerField('Год', validators=[Optional(), NumberRange(min=1888, max=2025)])
    poster_file = FileField('Загрузить постер', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Только изображения!')])
    director_id = SelectField('Режиссёр', coerce=int, validators=[Optional()])
    new_director = StringField('или добавить нового', validators=[Optional(), Length(max=100)])
    genres = SelectMultipleField('Жанры', coerce=int, validators=[Optional()])
    new_genres = StringField('или добавить новые жанры (через запятую)', validators=[Optional(), Length(max=200)])
    actors_ids = SelectMultipleField('Актеры', coerce=int, validators=[Optional()])
    new_actors = StringField('или добавить новых (через запятую)', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Сохранить')

class ReviewForm(FlaskForm):
    rating = FloatField('Рейтинг', validators=[
        DataRequired(message='Рейтинг обязателен'),
        NumberRange(min=1.0, max=10.0, message='Рейтинг должен быть от 1 до 10')
    ])
    comment = TextAreaField('Комментарий', validators=[
        Optional(),
        Length(max=1000, message='Комментарий слишком длинный')
    ])
    submit = SubmitField('Оставить отзыв')

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему для доступа к этой странице.'

@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    try:
        return db.get(User, int(user_id))  # Используем db.get() вместо db.query().get()
    finally:
        db.close()

# Декоратор для проверки роли
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            db = SessionLocal()
            try:
                user_role = db.query(Role).filter_by(id=current_user.role_id).first()
                if user_role and user_role.name in allowed_roles:
                    return f(*args, **kwargs)
                else:
                    flash('У вас нет прав для выполнения этого действия!', 'danger')
                    return redirect(url_for('index'))
            finally:
                db.close()
        return decorated_function
    return decorator

# Функция инициализации базы данных
def init_database():
    """Инициализация базы данных с тестовыми данными"""
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        # Проверяем, есть ли уже данные
        if db.query(Role).first():
            print("База данных уже инициализирована!")
            return
        
        # Создаем роли
        roles = [
            Role(name='user'),
            Role(name='moderator'),
            Role(name='admin')
        ]
        db.add_all(roles)
        db.commit()
        
        # Создаем тестового пользователя
        test_user = User(
            username='testuser',
            email='test@example.com',
            hash_password=generate_password_hash('password123'),
            subscription='free',
            role_id=1
        )
        db.add(test_user)
        
        # Создаем модератора
        moderator = User(
            username='moderator',
            email='moderator@moderator.moderator',
            hash_password=generate_password_hash('moderator'),
            subscription='pro',
            role_id=2
        )
        db.add(moderator)
        
        # Создаем администратора
        admin = User(
            username='admin',
            email='admin@admin.admin',
            hash_password=generate_password_hash('admin'),
            subscription='pro',
            role_id=3
        )
        db.add(admin)
        db.commit()
        
        # Создаем режиссеров
        directors = [
            Director(name='Кристофер Нолан'),
            Director(name='Квентин Тарантино'),
            Director(name='Стивен Спилберг'),
            Director(name='Джеймс Кэмерон'),
            Director(name='Питер Джексон')
        ]
        db.add_all(directors)
        db.commit()
        
        # Создаем актеров
        actors = [
            Actor(name='Леонардо ДиКаприо'),
            Actor(name='Том Хэнкс'),
            Actor(name='Морган Фриман'),
            Actor(name='Кейт Уинслет'),
            Actor(name='Элайджа Вуд'),
            Actor(name='Иэн МакКеллен'),
            Actor(name='Вигго Мортенсен'),
            Actor(name='Джонни Депп'),
            Actor(name='Брэд Питт'),
            Actor(name='Анджелина Джоли')
        ]
        db.add_all(actors)
        db.commit()
        
        # Создаем жанры
        genres = [
            Genre(name='Драма'),
            Genre(name='Боевик'),
            Genre(name='Комедия'),
            Genre(name='Ужасы'),
            Genre(name='Фантастика'),
            Genre(name='Триллер'),
            Genre(name='Детектив'),
            Genre(name='Приключения'),
            Genre(name='Романтика'),
            Genre(name='Документальный')
        ]
        db.add_all(genres)
        db.commit()
        
        # Создаем фильмы
        movies = [
            Movie(
                title='Побег из Шоушенка',
                description='История о надежде и дружбе в тюрьме',
                year=1994,
                poster_path='/static/images/superbad.jpg',
                rating=9.3,
                director_id=1
            ),
            Movie(
                title='Крёстный отец',
                description='Эпическая сага о семье Корлеоне',
                year=1972,
                poster_path='/static/images/superbad.jpg',
                rating=9.2,
                director_id=2
            ),
            Movie(
                title='Тёмный рыцарь',
                description='Бэтмен против Джокера в Готэм-сити',
                year=2008,
                poster_path='/static/images/superbad.jpg',
                rating=9.0,
                director_id=1
            ),
            Movie(
                title='Властелин колец: Возвращение короля',
                description='Финальная часть эпической трилогии',
                year=2003,
                poster_path='/static/images/superbad.jpg',
                rating=8.9,
                director_id=5
            ),
            Movie(
                title='Титаник',
                description='История любви на фоне трагедии',
                year=1997,
                poster_path='/static/images/superbad.jpg',
                rating=7.9,
                director_id=4
            )
        ]
        db.add_all(movies)
        db.commit()
        
        # Добавляем связи фильмов с жанрами и актерами
        movie1 = db.query(Movie).filter_by(title='Побег из Шоушенка').first()
        movie1.genres = [db.query(Genre).filter_by(name='Драма').first()]
        movie1.actors = [db.query(Actor).filter_by(name='Морган Фриман').first()]
        
        movie2 = db.query(Movie).filter_by(title='Крёстный отец').first()
        movie2.genres = [db.query(Genre).filter_by(name='Драма').first()]
        movie2.actors = [db.query(Actor).filter_by(name='Аль Пачино').first()]
        
        movie3 = db.query(Movie).filter_by(title='Тёмный рыцарь').first()
        movie3.genres = [db.query(Genre).filter_by(name='Боевик').first(), db.query(Genre).filter_by(name='Драма').first()]
        movie3.actors = [db.query(Actor).filter_by(name='Кристиан Бейл').first()]
        
        movie4 = db.query(Movie).filter_by(title='Властелин колец: Возвращение короля').first()
        movie4.genres = [db.query(Genre).filter_by(name='Фантастика').first(), db.query(Genre).filter_by(name='Приключения').first()]
        movie4.actors = [db.query(Actor).filter_by(name='Элайджа Вуд').first(), db.query(Actor).filter_by(name='Иэн МакКеллен').first()]
        
        movie5 = db.query(Movie).filter_by(title='Титаник').first()
        movie5.genres = [db.query(Genre).filter_by(name='Драма').first(), db.query(Genre).filter_by(name='Романтика').first()]
        movie5.actors = [db.query(Actor).filter_by(name='Леонардо ДиКаприо').first(), db.query(Actor).filter_by(name='Кейт Уинслет').first()]
        
        db.commit()
        
        print("База данных успешно инициализирована!")
        print("Тестовый пользователь: test@example.com / password123")
        print("Модератор: moderator@moderator.moderator / moderator")
        print("Администратор: admin@admin.admin / admin")
        
    except Exception as e:
        print(f"Ошибка при инициализации: {e}")
        db.rollback()
    finally:
        db.close()

# Маршруты
@app.route('/')
def index():
    """Главная страница - показывает все фильмы, поддерживает поиск и фильтрацию по актёрам, режиссёрам и жанрам"""
    db = SessionLocal()
    try:
        search = request.args.get('search', '').strip()
        selected_genres = request.args.getlist('genre')
        selected_actors = request.args.getlist('actor')
        selected_directors = request.args.getlist('director')

        # Получаем все жанры, актёров, режиссёров для фильтров
        all_genres = db.query(Genre).order_by(Genre.name).all()
        all_actors = db.query(Actor).order_by(Actor.name).all()
        all_directors = db.query(Director).order_by(Director.name).all()

        # Базовый запрос
        query = db.query(Movie)
        if search:
            query = query.filter(Movie.title.ilike(f'%{search}%'))
        if selected_genres:
            query = query.join(Movie.genres).filter(Genre.id.in_(selected_genres))
        if selected_actors:
            query = query.join(Movie.actors).filter(Actor.id.in_(selected_actors))
        if selected_directors:
            query = query.filter(Movie.director_id.in_(selected_directors))
        movies = query.distinct().all()

        return render_template(
            'index.html',
            movies=movies,
            search=search,
            all_genres=all_genres,
            all_actors=all_actors,
            all_directors=all_directors,
            selected_genres=[int(g) for g in selected_genres],
            selected_actors=[int(a) for a in selected_actors],
            selected_directors=[int(d) for d in selected_directors],
        )
    finally:
        db.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация пользователя"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            # Проверяем, существует ли пользователь
            existing_user = db.query(User).filter(
                (User.email == form.email.data) | (User.username == form.username.data)
            ).first()
            
            if existing_user:
                flash('Пользователь с таким email или именем уже существует!', 'danger')
                return render_template('register.html', form=form)
            
            # Создаем нового пользователя
            user = User(
                username=form.username.data,
                email=form.email.data,
                hash_password=generate_password_hash(form.password.data),
                subscription='free',
                role_id=1  # Роль "user"
            )
            
            db.add(user)
            db.commit()
            
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.rollback()
            flash('Ошибка при регистрации. Попробуйте еще раз.', 'danger')
        finally:
            db.close()
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Вход пользователя"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            user = db.query(User).filter_by(email=form.email.data).first()
            
            # Для админа и модератора сравниваем пароль напрямую
            if user and user.email in ["admin@admin.admin", "moderator@moderator.moderator"]:
                if user.hash_password == form.password.data:
                    login_user(user)
                    flash('Вы успешно вошли в систему!', 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('index'))
                else:
                    flash('Неверный email или пароль!', 'danger')
            # Для остальных — стандартная проверка
            elif user and user.check_password(form.password.data):
                login_user(user)
                flash('Вы успешно вошли в систему!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Неверный email или пароль!', 'danger')
        finally:
            db.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Выход пользователя"""
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/movie/<int:movie_id>')
@login_required
def movie_detail(movie_id):
    """Детальная страница фильма - только для пользователей с подпиской pro"""
    db = SessionLocal()
    try:
        movie = db.query(Movie).filter_by(id=movie_id).first()
        if not movie:
            flash('Фильм не найден!', 'danger')
            return redirect(url_for('index'))
        
        # Проверка подписки
        if current_user.subscription != 'pro':
            return render_template('movie_detail.html', movie=movie, reviews=None, review_form=None, subscription_required=True)
        
        reviews = db.query(Review).filter_by(movie_id=movie_id).all()
        review_form = ReviewForm()
        return render_template('movie_detail.html', movie=movie, reviews=reviews, review_form=review_form, subscription_required=False)
    finally:
        db.close()

@app.route('/profile')
@login_required
def profile():
    """Профиль пользователя"""
    return render_template('profile.html')

@app.route('/add_review/<int:movie_id>', methods=['POST'])
@login_required
def add_review(movie_id):
    """Добавление отзыва к фильму"""
    form = ReviewForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            # Проверяем, не оставлял ли пользователь уже отзыв
            existing_review = db.query(Review).filter_by(
                user_id=current_user.id, 
                movie_id=movie_id
            ).first()
            
            if existing_review:
                flash('Вы уже оставляли отзыв к этому фильму!', 'warning')
                return redirect(url_for('movie_detail', movie_id=movie_id))
            
            review = Review(
                user_id=current_user.id,
                movie_id=movie_id,
                rating=form.rating.data,
                comment=form.comment.data
            )
            
            db.add(review)
            db.commit()
            
            # Пересчитываем средний рейтинг фильма
            all_reviews = db.query(Review).filter_by(movie_id=movie_id).all()
            if all_reviews:
                avg_rating = sum([r.rating for r in all_reviews]) / len(all_reviews)
            else:
                avg_rating = 0.0
            movie = db.query(Movie).filter_by(id=movie_id).first()
            movie.rating = avg_rating
            db.commit()
            
            flash('Отзыв успешно добавлен!', 'success')
            
        except Exception as e:
            db.rollback()
            flash('Ошибка при добавлении отзыва.', 'danger')
        finally:
            db.close()
    
    return redirect(url_for('movie_detail', movie_id=movie_id))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Смена пароля пользователя"""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')
    
    if not current_password or not new_password or not confirm_new_password:
        flash('Все поля обязательны для заполнения!', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_new_password:
        flash('Новые пароли не совпадают!', 'danger')
        return redirect(url_for('profile'))
    
    if len(new_password) < 6:
        flash('Новый пароль должен быть не менее 6 символов!', 'danger')
        return redirect(url_for('profile'))
    
    # Проверяем, что новый пароль отличается от текущего
    if current_password == new_password:
        flash('Новый пароль должен отличаться от текущего!', 'danger')
        return redirect(url_for('profile'))
    
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(id=current_user.id).first()
        
        if not user.check_password(current_password):
            flash('Текущий пароль неверен!', 'danger')
            return redirect(url_for('profile'))
        
        user.set_password(new_password)
        db.commit()
        
        flash('Пароль успешно изменен!', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Ошибка при смене пароля. Попробуйте еще раз.', 'danger')
    finally:
        db.close()
    
    return redirect(url_for('profile'))

@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    """Смена имени пользователя"""
    new_username = request.form.get('new_username')
    
    if not new_username:
        flash('Имя пользователя обязательно!', 'danger')
        return redirect(url_for('profile'))
    
    if len(new_username) < 3 or len(new_username) > 50:
        flash('Имя пользователя должно быть от 3 до 50 символов!', 'danger')
        return redirect(url_for('profile'))
    
    db = SessionLocal()
    try:
        # Проверяем, не занято ли имя пользователя
        existing_user = db.query(User).filter_by(username=new_username).first()
        if existing_user and existing_user.id != current_user.id:
            flash('Пользователь с таким именем уже существует!', 'danger')
            return redirect(url_for('profile'))
        
        user = db.query(User).filter_by(id=current_user.id).first()
        user.username = new_username
        db.commit()
        
        flash('Имя пользователя успешно изменено!', 'success')
        
    except Exception as e:
        db.rollback()
        flash('Ошибка при смене имени пользователя. Попробуйте еще раз.', 'danger')
    finally:
        db.close()
    
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    """Удаление аккаунта пользователя"""
    delete_password = request.form.get('delete_password')
    delete_confirm = request.form.get('delete_confirm')
    
    if not delete_password or not delete_confirm:
        flash('Все поля обязательны для заполнения!', 'danger')
        return redirect(url_for('profile'))
    
    if delete_confirm != 'УДАЛИТЬ':
        flash('Для подтверждения введите "УДАЛИТЬ"!', 'danger')
        return redirect(url_for('profile'))
    
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(id=current_user.id).first()
        
        if not user.check_password(delete_password):
            flash('Пароль неверен!', 'danger')
            return redirect(url_for('profile'))
        
        # Удаляем пользователя (все связанные данные удалятся каскадно)
        db.delete(user)
        db.commit()
        
        logout_user()
        flash('Ваш аккаунт был успешно удален.', 'info')
        return redirect(url_for('index'))
        
    except Exception as e:
        db.rollback()
        flash('Ошибка при удалении аккаунта. Попробуйте еще раз.', 'danger')
    finally:
        db.close()
    
    return redirect(url_for('profile'))

@app.route('/change_subscription', methods=['POST'])
@login_required
def change_subscription():
    new_subscription = request.form.get('subscription', 'pro')
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(id=current_user.id).first()
        user.subscription = new_subscription
        db.commit()
        flash('Подписка успешно обновлена!', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при обновлении подписки.', 'danger')
    finally:
        db.close()
    return redirect(url_for('profile'))

@app.route('/delete_review/<int:review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    db = SessionLocal()
    try:
        review = db.query(Review).filter_by(id=review_id, user_id=current_user.id).first()
        if not review:
            flash('Отзыв не найден или у вас нет прав для удаления.', 'danger')
            return redirect(request.referrer or url_for('index'))
        movie_id = review.movie_id
        db.delete(review)
        db.commit()
        # Пересчёт рейтинга
        all_reviews = db.query(Review).filter_by(movie_id=movie_id).all()
        avg_rating = sum([r.rating for r in all_reviews]) / len(all_reviews) if all_reviews else 0.0
        movie = db.query(Movie).filter_by(id=movie_id).first()
        movie.rating = avg_rating
        db.commit()
        flash('Отзыв удалён.', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при удалении отзыва.', 'danger')
    finally:
        db.close()
    return redirect(request.referrer or url_for('index'))

@app.route('/edit_review/<int:review_id>', methods=['POST'])
@login_required
def edit_review(review_id):
    db = SessionLocal()
    try:
        review = db.query(Review).filter_by(id=review_id, user_id=current_user.id).first()
        if not review:
            flash('Отзыв не найден или у вас нет прав для редактирования.', 'danger')
            return redirect(request.referrer or url_for('index'))
        rating = request.form.get('rating', type=float)
        comment = request.form.get('comment', type=str)
        if rating is not None:
            review.rating = rating
        review.comment = comment
        db.commit()
        # Пересчёт рейтинга
        movie_id = review.movie_id
        all_reviews = db.query(Review).filter_by(movie_id=movie_id).all()
        avg_rating = sum([r.rating for r in all_reviews]) / len(all_reviews) if all_reviews else 0.0
        movie = db.query(Movie).filter_by(id=movie_id).first()
        movie.rating = avg_rating
        db.commit()
        flash('Отзыв обновлён.', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при редактировании отзыва.', 'danger')
    finally:
        db.close()
    return redirect(request.referrer or url_for('index'))

# --- Панель администратора ---
@app.route('/admin')
@login_required
@role_required(['admin'])
def admin_panel():
    """Панель администратора"""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        movies = db.query(Movie).all()
        reviews = db.query(Review).all()
        return render_template('admin_panel.html', users=users, movies=movies, reviews=reviews)
    finally:
        db.close()

@app.route('/admin/users')
@login_required
@role_required(['admin'])
def admin_users():
    """Управление пользователями"""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        roles = db.query(Role).all()
        return render_template('admin_users.html', users=users, roles=roles)
    finally:
        db.close()

@app.route('/admin/change_user_role/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def change_user_role(user_id):
    """Изменение роли пользователя"""
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(id=user_id).first()
        if not user:
            flash('Пользователь не найден.', 'danger')
            return redirect(url_for('admin_users'))
        
        new_role_id = request.form.get('role_id', type=int)
        if new_role_id and new_role_id in [1, 2, 3]:
            user.role_id = new_role_id
            db.commit()
            flash(f'Роль пользователя {user.username} изменена.', 'success')
        else:
            flash('Некорректная роль.', 'danger')
    except Exception as e:
        db.rollback()
        flash('Ошибка при изменении роли.', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_user(user_id):
    """Удаление пользователя"""
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(id=user_id).first()
        if not user:
            flash('Пользователь не найден.', 'danger')
            return redirect(url_for('admin_users'))
        
        if user.id == current_user.id:
            flash('Нельзя удалить самого себя.', 'danger')
            return redirect(url_for('admin_users'))
        
        db.delete(user)
        db.commit()
        flash(f'Пользователь {user.username} удален.', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при удалении пользователя.', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/add_movie', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_add_movie():
    db = SessionLocal()
    directors = db.query(Director).order_by(Director.name).all()
    actors = db.query(Actor).order_by(Actor.name).all()
    genres = db.query(Genre).order_by(Genre.name).all()
    form = MovieForm()
    form.director_id.choices = [(0, '— выберите —')] + [(d.id, d.name) for d in directors]
    form.actors_ids.choices = [(a.id, a.name) for a in actors]
    form.genres.choices = [(g.id, g.name) for g in genres]
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            # Режиссер
            if form.new_director.data:
                director = Director(name=form.new_director.data)
                db.add(director)
                db.commit()
            elif form.director_id.data and form.director_id.data != 0:
                director = db.query(Director).filter_by(id=form.director_id.data).first()
            else:
                director = None
            # Актеры
            actor_objs = []
            if form.actors_ids.data:
                actor_objs = db.query(Actor).filter(Actor.id.in_(form.actors_ids.data)).all()
            if form.new_actors.data:
                for name in [n.strip() for n in form.new_actors.data.split(',') if n.strip()]:
                    actor = db.query(Actor).filter_by(name=name).first()
                    if not actor:
                        actor = Actor(name=name)
                        db.add(actor)
                        db.commit()
                    actor_objs.append(actor)
            poster_path = None
            if form.poster_file.data:
                filename = secure_filename(form.poster_file.data.filename)
                ext = filename.rsplit('.', 1)[-1].lower()
                unique_name = f"poster_{uuid.uuid4().hex[:8]}.{ext}"
                save_path = os.path.join('static', 'images', unique_name)
                form.poster_file.data.save(save_path)
                poster_path = f"/static/images/{unique_name}"
            movie = Movie(
                title=form.title.data,
                description=form.description.data,
                year=form.year.data,
                poster_path=poster_path,
                rating=0.0,
                director_id=director.id if director else None
            )
            db.add(movie)
            db.commit()
            # Жанры из списка
            if form.genres.data:
                movie.genres = db.query(Genre).filter(Genre.id.in_(form.genres.data)).all()
            # Новые жанры
            if form.new_genres.data:
                for genre_name in [g.strip() for g in form.new_genres.data.split(',') if g.strip()]:
                    genre = db.query(Genre).filter_by(name=genre_name).first()
                    if not genre:
                        genre = Genre(name=genre_name)
                        db.add(genre)
                        db.commit()
                    if genre not in movie.genres:
                        movie.genres.append(genre)
            # Актеры
            movie.actors = actor_objs
            db.commit()
            flash('Фильм успешно добавлен!', 'success')
            return redirect(url_for('movie_detail', movie_id=movie.id))
        except Exception as e:
            db.rollback()
            flash('Ошибка при добавлении фильма. Попробуйте еще раз.', 'danger')
        finally:
            db.close()
    db.close()
    return render_template('add_movie.html', form=form)

@app.route('/admin/delete_movie/<int:movie_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_movie(movie_id):
    """Удаление фильма"""
    db = SessionLocal()
    try:
        movie = db.query(Movie).filter_by(id=movie_id).first()
        if not movie:
            flash('Фильм не найден.', 'danger')
            return redirect(url_for('admin_panel'))
        
        db.delete(movie)
        db.commit()
        flash(f'Фильм "{movie.title}" удален.', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при удалении фильма.', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_review/<int:review_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_review_admin(review_id):
    """Удаление отзыва (администратор)"""
    db = SessionLocal()
    try:
        review = db.query(Review).filter_by(id=review_id).first()
        if not review:
            flash('Отзыв не найден.', 'danger')
            return redirect(request.referrer or url_for('admin_panel'))
        
        movie_id = review.movie_id
        db.delete(review)
        db.commit()
        
        # Пересчитываем рейтинг фильма
        all_reviews = db.query(Review).filter_by(movie_id=movie_id).all()
        avg_rating = sum([r.rating for r in all_reviews]) / len(all_reviews) if all_reviews else 0.0
        movie = db.query(Movie).filter_by(id=movie_id).first()
        movie.rating = avg_rating
        db.commit()
        
        flash('Отзыв удален.', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при удалении отзыва.', 'danger')
    finally:
        db.close()
    return redirect(request.referrer or url_for('admin_panel'))

# --- Панель модератора ---
@app.route('/moderator')
@login_required
@role_required(['moderator'])
def moderator_panel():
    """Панель модератора"""
    db = SessionLocal()
    try:
        movies = db.query(Movie).all()
        reviews = db.query(Review).all()
        return render_template('moderator_panel.html', movies=movies, reviews=reviews)
    finally:
        db.close()

@app.route('/moderator/edit_movie/<int:movie_id>', methods=['GET', 'POST'])
@login_required
@role_required(['moderator'])
def edit_movie(movie_id):
    db = SessionLocal()
    try:
        movie = db.query(Movie).filter_by(id=movie_id).first()
        if not movie:
            flash('Фильм не найден.', 'danger')
            return redirect(url_for('moderator_panel'))
        
        form = MovieForm()
        # choices для select
        directors = db.query(Director).order_by(Director.name).all()
        actors = db.query(Actor).order_by(Actor.name).all()
        genres = db.query(Genre).order_by(Genre.name).all()
        form.director_id.choices = [(0, '— выберите —')] + [(d.id, d.name) for d in directors]
        form.actors_ids.choices = [(a.id, a.name) for a in actors]
        form.genres.choices = [(g.id, g.name) for g in genres]
        
        if request.method == 'GET':
            # Заполняем форму данными фильма при GET-запросе
            form.title.data = movie.title
            form.description.data = movie.description
            form.year.data = movie.year
            if movie.director:
                form.director_id.data = movie.director.id
            if movie.genres:
                form.genres.data = [g.id for g in movie.genres]
            if movie.actors:
                form.actors_ids.data = [a.id for a in movie.actors]
            return render_template('edit_movie.html', form=form, movie=movie)
        
        if form.validate_on_submit():
            movie.title = form.title.data
            movie.description = form.description.data
            movie.year = form.year.data
            
            # Обновляем постер, если загружен новый
            if form.poster_file.data:
                filename = secure_filename(form.poster_file.data.filename)
                ext = filename.rsplit('.', 1)[-1].lower()
                unique_name = f"poster_{uuid.uuid4().hex[:8]}.{ext}"
                save_path = os.path.join('static', 'images', unique_name)
                form.poster_file.data.save(save_path)
                movie.poster_path = f"/static/images/{unique_name}"
            
            # Обновляем режиссера
            if form.new_director.data:
                director = Director(name=form.new_director.data)
                db.add(director)
                db.commit()
                movie.director_id = director.id
            elif form.director_id.data and form.director_id.data != 0:
                movie.director_id = form.director_id.data
            
            # Обновляем жанры
            movie.genres.clear()
            if form.genres.data:
                movie.genres = db.query(Genre).filter(Genre.id.in_(form.genres.data)).all()
            if form.new_genres.data:
                for genre_name in [g.strip() for g in form.new_genres.data.split(',') if g.strip()]:
                    genre = db.query(Genre).filter_by(name=genre_name).first()
                    if not genre:
                        genre = Genre(name=genre_name)
                        db.add(genre)
                        db.commit()
                    if genre not in movie.genres:
                        movie.genres.append(genre)
            
            # Обновляем актеров
            movie.actors.clear()
            actor_objs = []
            if form.actors_ids.data:
                actor_objs = db.query(Actor).filter(Actor.id.in_(form.actors_ids.data)).all()
            if form.new_actors.data:
                for name in [n.strip() for n in form.new_actors.data.split(',') if n.strip()]:
                    actor = db.query(Actor).filter_by(name=name).first()
                    if not actor:
                        actor = Actor(name=name)
                        db.add(actor)
                        db.commit()
                    actor_objs.append(actor)
            movie.actors = actor_objs
            
            db.commit()
            flash('Фильм успешно обновлен!', 'success')
            return redirect(url_for('movie_detail', movie_id=movie.id))
        
        # Если форма не прошла валидацию, заполняем её данными фильма
        form.title.data = movie.title
        form.description.data = movie.description
        form.year.data = movie.year
        if movie.director:
            form.director_id.data = movie.director.id
        if movie.genres:
            form.genres.data = [g.id for g in movie.genres]
        if movie.actors:
            form.actors_ids.data = [a.id for a in movie.actors]
        
        return render_template('edit_movie.html', form=form, movie=movie)
    finally:
        db.close()

@app.route('/moderator/delete_review/<int:review_id>', methods=['POST'])
@login_required
@role_required(['moderator'])
def delete_review_moderator(review_id):
    """Удаление отзыва (модератор)"""
    db = SessionLocal()
    try:
        review = db.query(Review).filter_by(id=review_id).first()
        if not review:
            flash('Отзыв не найден.', 'danger')
            return redirect(request.referrer or url_for('moderator_panel'))
        
        movie_id = review.movie_id
        db.delete(review)
        db.commit()
        
        # Пересчитываем рейтинг фильма
        all_reviews = db.query(Review).filter_by(movie_id=movie_id).all()
        avg_rating = sum([r.rating for r in all_reviews]) / len(all_reviews) if all_reviews else 0.0
        movie = db.query(Movie).filter_by(id=movie_id).first()
        movie.rating = avg_rating
        db.commit()
        
        flash('Отзыв удален.', 'success')
    except Exception as e:
        db.rollback()
        flash('Ошибка при удалении отзыва.', 'danger')
    finally:
        db.close()
    return redirect(request.referrer or url_for('moderator_panel'))

@app.route('/movies')
def movies_redirect():
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Инициализируем базу данных при первом запуске
    init_database()
    
    # Запускаем приложение
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
