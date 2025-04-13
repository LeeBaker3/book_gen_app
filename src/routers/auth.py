from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import get_db
from src.models.user import User
from src.auth.security import hash_password, verify_password
from src.auth.jwt import create_access_token
from pydantic import BaseModel, EmailStr

router = APIRouter()

class RegisterUser(BaseModel):
    username: str
    email: EmailStr
    password: str

@router.post("/register")
def register_user(user: RegisterUser, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

class LoginUser(BaseModel):
    email: str
    password: str

@router.post("/login")
def login_user(user: LoginUser, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token(data={"sub": db_user.email, "admin": db_user.is_admin})
    return {"access_token": token, "token_type": "bearer"}

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str

@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = hash_password(request.new_password)
    db.commit()
    return {"message": "Password reset successfully"}