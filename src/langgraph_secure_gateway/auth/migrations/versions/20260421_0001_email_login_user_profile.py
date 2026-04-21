"""Switch users to email login and profile fields.

Revision ID: 20260421_0001
Revises:
Create Date: 2026-04-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

revision: str = '20260421_0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_table(table_name: str) -> bool:
    return table_name in inspect(op.get_bind()).get_table_names()


def _columns(table_name: str) -> set[str]:
    return {column['name'] for column in inspect(op.get_bind()).get_columns(table_name)}


def _unique_constraints(table_name: str) -> set[str]:
    return {
        constraint['name']
        for constraint in inspect(op.get_bind()).get_unique_constraints(table_name)
        if constraint.get('name')
    }


def _create_users() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('first_name', sa.String(length=255), nullable=True),
        sa.Column('last_name', sa.String(length=255), nullable=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_admin', sa.Boolean(), nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email', name='uq_users_email'),
    )


def _create_panel_access() -> None:
    op.create_table(
        'panel_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('panel_key', sa.String(length=128), nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'panel_key', name='uq_user_panel'),
    )
    op.create_index('ix_panel_access_user_id', 'panel_access', ['user_id'])


def _upgrade_existing_users() -> None:
    existing_columns = _columns('users')

    if 'email' not in existing_columns:
        op.add_column('users', sa.Column('email', sa.String(length=255), nullable=True))
    if 'first_name' not in existing_columns:
        op.add_column(
            'users', sa.Column('first_name', sa.String(length=255), nullable=True)
        )
    if 'last_name' not in existing_columns:
        op.add_column(
            'users', sa.Column('last_name', sa.String(length=255), nullable=True)
        )
    if 'created_at' not in existing_columns:
        op.add_column(
            'users',
            sa.Column(
                'created_at',
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
    if 'updated_at' not in existing_columns:
        op.add_column(
            'users',
            sa.Column(
                'updated_at',
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
    if 'last_login_at' not in existing_columns:
        op.add_column(
            'users',
            sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        )

    refreshed_columns = _columns('users')
    if 'username' in refreshed_columns:
        op.execute(
            text("UPDATE users SET email = username WHERE email IS NULL OR email = ''")
        )

    op.execute(
        text(
            "UPDATE users SET email = 'user-' || id::text "
            "WHERE email IS NULL OR email = ''"
        )
    )
    op.alter_column(
        'users', 'email', existing_type=sa.String(length=255), nullable=False
    )

    if 'uq_users_email' not in _unique_constraints('users'):
        op.create_unique_constraint('uq_users_email', 'users', ['email'])


def upgrade() -> None:
    if not _has_table('users'):
        _create_users()
    else:
        _upgrade_existing_users()

    if not _has_table('panel_access'):
        _create_panel_access()


def downgrade() -> None:
    if _has_table('panel_access'):
        op.drop_table('panel_access')
    if _has_table('users'):
        op.drop_table('users')
