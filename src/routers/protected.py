from fastapi import APIRouter, Depends
from src.auth.dependencies import get_current_user, get_admin_user
from src.models.user import User

router = APIRouter()

@router.get("/user-dashboard")
def user_dashboard(user: User = Depends(get_current_user)):
    return {"message": f"Welcome, {user.username}"}

@router.get("/admin-dashboard")
def admin_dashboard(user: User = Depends(get_admin_user)):
    return {"message": "Welcome Admin"}