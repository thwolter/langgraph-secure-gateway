"""HTTP routes for login and session introspection."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
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
from langgraph_secure_gateway.auth.models import Agent, User, UserAgentAccess
from langgraph_secure_gateway.auth.security import create_access_token, verify_password

router = APIRouter(prefix='/auth', tags=['auth'])


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


@router.post('/login', response_model=TokenResponse)
def login(
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

    token = create_access_token(user_id=user.id)
    user.last_login_at = datetime.now(tz=UTC)
    session.commit()

    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_expire_minutes * 60,
    )


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
