from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy.sql import func
from pydantic import BaseModel, Field, validator
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    role_id = Column(Integer, nullable=False, default=1)
    subscription_id = Column(Integer, default = 1)

class Movies(Base):
    __tablename__ = "movies"

    id = Column(Integer, primary_key=True)
    title = Column(String)
    description = Column(String)
    poster_path = Column(String)
    rating = Column(Float)
    year = Column(Integer)

class Genres(Base):
    __tablename__ = "genres"
    id = Column(Integer, primary_key=True)
    name = Column(String)

class Actors(Base):
    __tablename__ = "actors"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    middle_name = Column(String)
    last_name = Column(String)

class Directors(Base):
    __tablename__ = "directors"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    middle_name = Column(String)
    last_name = Column(String)

class MovieGenres(Base):
    __tablename__ = "movie_genres"
    id = Column(Integer, primary_key=True)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    genre_id = Column(Integer, ForeignKey("genres.id"))

class MovieActors(Base):
    __tablename__ = "movie_actors"
    id = Column(Integer, primary_key=True)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    actor_id = Column(Integer, ForeignKey("actors.id"))

class MovieDirectors(Base):
    __tablename__ = "movie_directors"
    id = Column(Integer, primary_key=True)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    director_id = Column(Integer, ForeignKey("directors.id"))


# Модели для Pydantic

class UserBase(BaseModel):
    email: str
    username: str

class UserCreate(UserBase):
    password: str

class UserRequest(UserBase):
    id: int
    role_id: int

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: str
    password: str
    remember: bool = False

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

class DeleteAccount(BaseModel):
    password: str

class ChangeUsername(BaseModel):
    username: str
    password: str

    class Config:
        from_attributes = True

class MovieBase(BaseModel):
    title: str
    description: str
    poster_path: str
    rating: float
    year: int

class MovieResponse(MovieBase):
    id: int

    class Config:
        from_attributes = True  