"""SQLAlchemy models for user authentication and agent authorization."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM entities."""


class User(Base):
    """Application user with credentials and privilege flags."""

    __tablename__ = 'users'

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    first_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    agent_access: Mapped[list['UserAgentAccess']] = relationship(
        'UserAgentAccess',
        back_populates='user',
        cascade='all, delete-orphan',
        passive_deletes=True,
    )

    def __str__(self) -> str:
        return self.email


class Agent(Base):
    """Admin-managed LangGraph agent exposed through the gateway."""

    __tablename__ = 'agents'

    id: Mapped[UUID] = mapped_column(Uuid(), primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text(), nullable=True)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    assistant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    graph_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user_access: Mapped[list['UserAgentAccess']] = relationship(
        'UserAgentAccess',
        back_populates='agent',
        cascade='all, delete-orphan',
        passive_deletes=True,
    )

    def __str__(self) -> str:
        return f'{self.name} ({self.key})'


class UserAgentAccess(Base):
    """Agent authorization mapping for users."""

    __tablename__ = 'user_agent_access'
    __table_args__ = (UniqueConstraint('user_id', 'agent_id', name='uq_user_agent'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(),
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID] = mapped_column(
        Uuid(),
        ForeignKey('agents.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped[User] = relationship('User', back_populates='agent_access')
    agent: Mapped[Agent] = relationship('Agent', back_populates='user_access')
