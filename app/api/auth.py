from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.schemas import LogoutIn, RefreshIn, TokenOut, UserLogin, UserRegister
from app.services.refresh_rotation_service import RefreshRotationService
from app.services.session_service import SessionService
from app.services.user_service import UserService
from app.utils import get_client_info

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=TokenOut,
    status_code=status.HTTP_201_CREATED,
    summary="Регистрация пользователя",
)
async def register(
    payload: UserRegister, request: Request, db: AsyncSession = Depends(get_db)
) -> TokenOut:
    user = await UserService.create_user(db, payload.username, payload.password)
    user_agent, ip = get_client_info(request)
    return await SessionService.create_session_with_tokens(user, db, user_agent, ip)


@router.post(
    "/login",
    response_model=TokenOut,
    summary="вход пользователя в сессию "
    "(обмен логина и пароля на пару токенов: JWT-access токен и refresh токен)",
)
async def login(
    payload: UserLogin, request: Request, db: AsyncSession = Depends(get_db)
) -> TokenOut:
    user_agent, ip = get_client_info(request)
    return await SessionService.login(
        db, payload.username, payload.password, user_agent, ip
    )


@router.post("/refresh", response_model=TokenOut, summary="Обновление пары токенов")
async def refresh_token(
    payload: RefreshIn, db: AsyncSession = Depends(get_db)
) -> TokenOut:
    return await RefreshRotationService.refresh_tokens(db, payload.refresh_token)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Выход пользователя из сессии",
)
async def logout(payload: LogoutIn, db: AsyncSession = Depends(get_db)) -> None:
    await SessionService.logout(db, payload.refresh_token)
