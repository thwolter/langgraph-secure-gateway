"""HTTP routes for login and session introspection."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import get_session
from langgraph_secure_gateway.auth.dependencies import AuthContext, get_auth_context
from langgraph_secure_gateway.auth.models import User
from langgraph_secure_gateway.auth.security import create_access_token, verify_password

router = APIRouter(prefix='/auth', tags=['auth'])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    expires_in: int


class MeResponse(BaseModel):
    user_id: UUID
    username: str
    is_admin: bool
    panels: list[str]


@router.post('/login', response_model=TokenResponse)
def login(
    payload: LoginRequest,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    statement = (
        select(User)
        .options(selectinload(User.panel_access))
        .where(User.username == payload.username)
        .limit(1)
    )
    user = session.execute(statement).scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail='Invalid credentials')

    panels = [entry.panel_key for entry in user.panel_access]
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        is_admin=user.is_admin,
        panels=panels,
    )

    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get('/me', response_model=MeResponse)
def me(auth: Annotated[AuthContext, Depends(get_auth_context)]) -> MeResponse:
    return MeResponse(
        user_id=auth.user_id,
        username=auth.username,
        is_admin=auth.is_admin,
        panels=list(auth.panels),
    )
