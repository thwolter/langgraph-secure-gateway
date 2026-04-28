"""HTTP routes for login and session introspection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import APIKeyCookie, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import get_session
from langgraph_secure_gateway.auth.dependencies import (
    AuthContext,
    get_auth_context,
    get_current_user,
)
from langgraph_secure_gateway.auth.models import (
    Agent,
    RefreshSession,
    User,
    UserAgentAccess,
)
from langgraph_secure_gateway.auth.security import (
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
    verify_password,
)

router = APIRouter(prefix='/auth', tags=['auth'])
refresh_cookie_scheme = APIKeyCookie(
    name=settings.refresh_cookie_name,
    scheme_name='RefreshCookie',
    description='Opaque refresh token stored as an HttpOnly cookie.',
    auto_error=False,
)
refresh_bearer_scheme = HTTPBearer(
    scheme_name='RefreshTokenBearer',
    bearerFormat='opaque-refresh-token',
    description='Opaque refresh token. This is not the JWT access token.',
    auto_error=False,
)


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    expires_in: int


class MeResponse(BaseModel):
    user_id: UUID
    email: str
    first_name: str | None
    last_name: str | None
    is_admin: bool


class SessionUserResponse(BaseModel):
    id: UUID
    email: str
    first_name: str | None
    last_name: str | None
    is_admin: bool


class SessionAgentResponse(BaseModel):
    id: UUID
    key: str
    name: str
    description: str | None
    url: str
    assistant_id: str | None
    graph_id: str | None


class SessionResponse(BaseModel):
    user: SessionUserResponse
    agents: list[SessionAgentResponse]


def _access_token_response(user_id: UUID) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user_id=user_id),
        expires_in=settings.jwt_expire_minutes * 60,
    )


def _refresh_cookie_max_age() -> int:
    return settings.refresh_token_expire_days * 24 * 60 * 60


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=refresh_token,
        max_age=_refresh_cookie_max_age(),
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        path=settings.refresh_cookie_path,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        path=settings.refresh_cookie_path,
    )


def _request_ip(request: Request) -> str | None:
    if request.client is None:
        return None
    return request.client.host


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _create_refresh_session(
    *,
    user: User,
    request: Request,
    session: Session,
) -> tuple[RefreshSession, str]:
    refresh_token = create_refresh_token()
    refresh_session = RefreshSession(
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        user_agent=request.headers.get('user-agent'),
        ip_address=_request_ip(request),
        expires_at=datetime.now(tz=UTC)
        + timedelta(days=settings.refresh_token_expire_days),
    )
    session.add(refresh_session)
    return refresh_session, refresh_token


def _find_refresh_session(
    *, refresh_token: str, session: Session
) -> RefreshSession | None:
    token_hash = hash_refresh_token(refresh_token)
    statement = select(RefreshSession).where(RefreshSession.token_hash == token_hash)
    return session.execute(statement).scalar_one_or_none()


def _get_refresh_token(
    request: Request,
    cookie_token: str | None,
    bearer_token: HTTPAuthorizationCredentials | None,
) -> str | None:
    return (
        cookie_token
        or request.cookies.get(settings.refresh_cookie_name)
        or (bearer_token.credentials if bearer_token is not None else None)
    )


def _revoke_user_refresh_sessions(*, user_id: UUID, session: Session) -> None:
    now = datetime.now(tz=UTC)
    statement = select(RefreshSession).where(
        RefreshSession.user_id == user_id,
        RefreshSession.revoked_at.is_(None),
    )
    for refresh_session in session.execute(statement).scalars():
        refresh_session.revoked_at = now


@router.post('/login', response_model=TokenResponse)
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    email = payload.email.strip().lower()
    statement = select(User).where(User.email == email).limit(1)
    user = session.execute(statement).scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail='Invalid credentials')

    _, refresh_token = _create_refresh_session(
        user=user, request=request, session=session
    )
    user.last_login_at = datetime.now(tz=UTC)
    session.commit()
    _set_refresh_cookie(response, refresh_token)

    return _access_token_response(user.id)


@router.post('/refresh', response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    cookie_token: Annotated[str | None, Depends(refresh_cookie_scheme)],
    bearer_token: Annotated[
        HTTPAuthorizationCredentials | None, Depends(refresh_bearer_scheme)
    ],
) -> TokenResponse:
    refresh_token = _get_refresh_token(request, cookie_token, bearer_token)
    if not refresh_token:
        raise HTTPException(status_code=401, detail='Missing refresh token')

    refresh_session = _find_refresh_session(
        refresh_token=refresh_token, session=session
    )
    if refresh_session is None:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail='Invalid refresh token')

    now = datetime.now(tz=UTC)
    if refresh_session.revoked_at is not None or refresh_session.rotated_at is not None:
        _revoke_user_refresh_sessions(user_id=refresh_session.user_id, session=session)
        session.commit()
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail='Invalid refresh token')

    if _as_aware_utc(refresh_session.expires_at) <= now:
        refresh_session.revoked_at = now
        session.commit()
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail='Expired refresh token')

    user = session.get(User, refresh_session.user_id)
    if user is None or not user.is_active:
        refresh_session.revoked_at = now
        session.commit()
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail='User is inactive or missing')

    new_refresh_session, new_refresh_token = _create_refresh_session(
        user=user, request=request, session=session
    )
    session.flush()
    refresh_session.rotated_at = now
    refresh_session.revoked_at = now
    refresh_session.replaced_by_id = new_refresh_session.id
    session.commit()
    _set_refresh_cookie(response, new_refresh_token)

    return _access_token_response(user.id)


@router.post('/logout')
def logout(
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    cookie_token: Annotated[str | None, Depends(refresh_cookie_scheme)],
    bearer_token: Annotated[
        HTTPAuthorizationCredentials | None, Depends(refresh_bearer_scheme)
    ],
) -> dict[str, bool]:
    refresh_token = _get_refresh_token(request, cookie_token, bearer_token)
    if refresh_token:
        refresh_session = _find_refresh_session(
            refresh_token=refresh_token, session=session
        )
        if refresh_session is not None and refresh_session.revoked_at is None:
            refresh_session.revoked_at = datetime.now(tz=UTC)
            session.commit()

    _clear_refresh_cookie(response)
    return {'ok': True}


@router.get('/me', response_model=MeResponse)
def me(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    user: Annotated[User, Depends(get_current_user)],
) -> MeResponse:
    return MeResponse(
        user_id=auth.user_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_admin=user.is_admin,
    )


@router.get('/session', response_model=SessionResponse)
def session_info(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
) -> SessionResponse:
    statement = (
        select(Agent)
        .join(UserAgentAccess, UserAgentAccess.agent_id == Agent.id)
        .where(
            UserAgentAccess.user_id == user.id,
            Agent.is_active.is_(True),
        )
        .order_by(Agent.name, Agent.key)
    )
    agents = session.execute(statement).scalars().all()
    root_url = str(request.base_url).rstrip('/')

    return SessionResponse(
        user=SessionUserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_admin=user.is_admin,
        ),
        agents=[
            SessionAgentResponse(
                id=agent.id,
                key=agent.key,
                name=agent.name,
                description=agent.description,
                url=f'{root_url}/agents/{agent.key}',
                assistant_id=agent.assistant_id,
                graph_id=agent.graph_id,
            )
            for agent in agents
        ],
    )
