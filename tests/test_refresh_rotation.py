from __future__ import annotations

from collections.abc import Generator

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import get_session
from langgraph_secure_gateway.auth.models import Base, RefreshSession, User
from langgraph_secure_gateway.auth.routes import router
from langgraph_secure_gateway.auth.security import hash_password


def _build_client() -> tuple[TestClient, sessionmaker[Session]]:
    engine = create_engine(
        'sqlite+pysqlite:///:memory:',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with session_factory() as session:
        session.add(
            User(
                email='user@example.com',
                password_hash=hash_password('correct-password'),
                is_active=True,
            )
        )
        session.commit()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app = FastAPI()
    app.dependency_overrides[get_session] = override_get_session
    app.include_router(router)
    return TestClient(app), session_factory


def test_refresh_rotates_cookie_and_revokes_replayed_token() -> None:
    settings.refresh_cookie_secure = False
    settings.refresh_cookie_path = '/auth'

    client, session_factory = _build_client()

    login_response = client.post(
        '/auth/login',
        json={'email': 'user@example.com', 'password': 'correct-password'},
    )
    assert login_response.status_code == 200
    first_refresh_token = client.cookies.get(settings.refresh_cookie_name)
    assert first_refresh_token

    refresh_response = client.post('/auth/refresh')
    assert refresh_response.status_code == 200
    second_refresh_token = client.cookies.get(settings.refresh_cookie_name)
    assert second_refresh_token
    assert second_refresh_token != first_refresh_token

    with session_factory() as session:
        refresh_sessions = session.execute(select(RefreshSession)).scalars().all()
        assert len(refresh_sessions) == 2

        old_session = next(
            item for item in refresh_sessions if item.revoked_at is not None
        )
        new_session = next(item for item in refresh_sessions if item.revoked_at is None)
        assert old_session.rotated_at is not None
        assert old_session.replaced_by_id == new_session.id

    replay_client = TestClient(client.app)
    replay_response = replay_client.post(
        '/auth/refresh',
        headers={'authorization': f'Bearer {first_refresh_token}'},
    )
    assert replay_response.status_code == 401

    with session_factory() as session:
        active_sessions = (
            session.execute(
                select(RefreshSession).where(RefreshSession.revoked_at.is_(None))
            )
            .scalars()
            .all()
        )
        assert active_sessions == []
