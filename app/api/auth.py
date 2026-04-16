from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Session, User
from app.schemas import LogoutIn, RefreshIn, TokenOut, UserLogin, UserRegister, UserRole
from app.services.refresh_rotation_service import RefreshRotationService
from app.services.token_service import TokenService
from app.utils import hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


def _get_client_info(request: Request) -> tuple[str | None, str | None]:
    """Извлекает user-agent и IP из запроса."""
    user_agent = request.headers.get("user-agent")

    # Handle various IP scenarios (proxies, etc.)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP in the chain
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else None

    return user_agent, ip


async def _issue_tokens_and_store_session(
    user: User, db: AsyncSession, user_agent: str | None = None, ip: str | None = None
) -> TokenOut:
    token_payload = RefreshRotationService._create_token_payload(user)

    access_token, refresh_token, refresh_jti, exp = (
        TokenService.create_token_pair_with_metadata(token_payload)
    )

    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

    session = Session(
        user_id=user.id,
        refresh_jti=refresh_jti,
        user_agent=user_agent,
        ip=ip,
        expires_at=expires_at,
    )

    db.add(session)
    await db.commit()
    await db.refresh(session)

    return TokenOut(access_token=access_token, refresh_token=refresh_token)


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegister, request: Request, db: AsyncSession = Depends(get_db)
) -> TokenOut:
    existing = await db.scalar(select(User).where(User.username == payload.username))
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=UserRole.CLIENT,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    user_agent, ip = _get_client_info(request)
    return await _issue_tokens_and_store_session(user, db, user_agent, ip)


@router.post("/login", response_model=TokenOut)
async def login(
    payload: UserLogin, request: Request, db: AsyncSession = Depends(get_db)
) -> TokenOut:
    user = await db.scalar(select(User).where(User.username == payload.username))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive")

    user_agent, ip = _get_client_info(request)
    return await _issue_tokens_and_store_session(user, db, user_agent, ip)


@router.post("/refresh", response_model=TokenOut)
async def refresh_token(
    payload: RefreshIn, db: AsyncSession = Depends(get_db)
) -> TokenOut:
    return await RefreshRotationService.refresh_tokens(db, payload.refresh_token)


@router.post("/logout", status_code=204)
async def logout(payload: LogoutIn, db: AsyncSession = Depends(get_db)) -> None:
    await RefreshRotationService.logout(db, payload.refresh_token)
