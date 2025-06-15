from fastapi import FastAPI, Depends, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import SessionLocal, engine
from . import models
from .models import (
    User, LoginRequest, UserBase, UserRequest, UserCreate, 
    ChangePassword, DeleteAccount, ChangeUsername, 
    Movies, MovieResponse
)
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.responses import JSONResponse

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

SECRET_KEY = "your-secret-key-keep-it-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    try:
        if not (hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$')):
            return False
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def create_token(data: dict, token_type: str = "access"):
    to_encode = data.copy()
    if token_type == "access":
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": token_type})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid authentication credentials"}
            )
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "User not found"}
            )
        return user
    except JWTError:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid token"}
        )

@app.get("/me", response_model=UserRequest)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users", response_model=List[UserRequest])
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

@app.post("/register")
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        return JSONResponse(
            status_code=400,
            content={"detail": "Пользователь с таким email уже существует"}
        )
    
    existing_username = db.query(User).filter(User.username == user_data.username).first()
    if existing_username:
        return JSONResponse(
            status_code=400,
            content={"detail": "Пользователь с таким именем уже существует"}
        )
    
    try:
        hashed_password = pwd_context.hash(user_data.password)
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=hashed_password,
            role_id=1
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        access_token = create_token(data={"sub": new_user.email})
        
        return {
            "message": "Регистрация успешна",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "role_id": new_user.role_id
            },
            "access_token": access_token,
            "token_type": "bearer"
        }
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при регистрации пользователя"}
        )

@app.post("/login")
def login(login_data: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user:
        return JSONResponse(
            status_code=404,
            content={"detail": "Пользователь не найден"}
        )
    
    if not verify_password(login_data.password, user.password_hash):
        return JSONResponse(
            status_code=401,
            content={"detail": "Неверный пароль"}
        )
    
    access_token = create_token(data={"sub": user.email}, token_type="access")
    
    if login_data.remember:
        refresh_token = create_token(data={"sub": user.email}, token_type="refresh")
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )
    
    return {
        "message": "Вход выполнен успешно",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role_id": user.role_id
        },
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/logout")
def logout(response: Response):
    response = JSONResponse(content={"message": "Successfully logged out"})
    response.delete_cookie(key="refresh_token")
    return response

@app.post("/change-password")
def change_password(password_data: ChangePassword, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(password_data.current_password, current_user.password_hash):
        return JSONResponse(
            status_code=400,
            content={"detail": "Неверный текущий пароль"}
        )
    
    if password_data.current_password == password_data.new_password:
        return JSONResponse(
            status_code=400,
            content={"detail": "Новый пароль должен отличаться от текущего"}
        )
    
    try:
        current_user.password_hash = pwd_context.hash(password_data.new_password)
        db.commit()
        return {"message": "Пароль успешно изменен"}
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при изменении пароля"}
        )

@app.delete("/delete-account")
def delete_account(password_data: DeleteAccount, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(password_data.password, current_user.password_hash):
        return JSONResponse(
            status_code=400,
            content={"detail": "Неверный пароль"}
        )
    
    try:
        db.delete(current_user)
        db.commit()
        return {"message": "Аккаунт успешно удален"}
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при удалении аккаунта"}
        )

@app.post("/change-username")
def change_username(username_data: ChangeUsername, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.username == username_data.username:
        return JSONResponse(
            status_code=400,
            content={"detail": "Новое имя пользователя должно отличаться от текущего"}
        )
    
    if db.query(User).filter(User.username == username_data.username).first():
        return JSONResponse(
            status_code=400,
            content={"detail": "Имя пользователя уже занято"}
        )
    
    if not verify_password(username_data.password, current_user.password_hash):
        return JSONResponse(
            status_code=400,
            content={"detail": "Неверный пароль"}
        )
    
    try:
        current_user.username = username_data.username
        db.commit()
        return {"message": "Имя пользователя успешно изменено"}
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при изменении имени пользователя"}
        )

@app.get("/movies", response_model=List[MovieResponse])
def get_movies(db: Session = Depends(get_db)):
    try:
        movies = db.query(Movies).all()
        return movies
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при получении списка фильмов"}
        )

@app.get("/movies/{movie_id}", response_model=MovieResponse)
def get_movie(movie_id: int, db: Session = Depends(get_db)):
    try:
        movie = db.query(Movies).filter(Movies.id == movie_id).first()
        if not movie:
            return JSONResponse(
                status_code=404,
                content={"detail": "Фильм не найден"}
            )
        return movie
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при получении информации о фильме"}
        )