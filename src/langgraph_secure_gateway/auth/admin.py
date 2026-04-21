"""SQLAdmin setup for admin-only user and agent management."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sqladmin import Admin, ModelView, expose
from sqladmin.authentication import AuthenticationBackend
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from langgraph_secure_gateway.auth.config import settings
from langgraph_secure_gateway.auth.db import SessionLocal, engine
from langgraph_secure_gateway.auth.discovery import discover_langgraph_agents
from langgraph_secure_gateway.auth.models import Agent, User, UserAgentAccess
from langgraph_secure_gateway.auth.security import verify_password


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _get_user_by_email(session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == _normalize_email(email)).limit(1)
    return session.execute(statement).scalar_one_or_none()


class AdminAuth(AuthenticationBackend):
    def __init__(self) -> None:
        super().__init__(secret_key=settings.admin_session_secret)

    async def login(self, request: Request) -> bool:
        form = await request.form()
        email = _normalize_email(str(form.get('username', '')))
        password = str(form.get('password', '')).strip()

        with SessionLocal() as session:
            user = _get_user_by_email(session, email)
            if user is None or not user.is_active or not user.is_admin:
                return False
            if not verify_password(password, user.password_hash):
                return False

        request.session.update(
            {
                'token': f'admin:{user.id}',
                'admin_user_id': str(user.id),
                'admin_email': user.email,
            }
        )
        return True

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> Response | bool:
        user_id = request.session.get('admin_user_id')
        if user_id is None:
            return RedirectResponse(url='/admin/login', status_code=302)

        try:
            user_uuid = UUID(str(user_id))
        except (TypeError, ValueError):
            request.session.clear()
            return RedirectResponse(url='/admin/login', status_code=302)

        with SessionLocal() as session:
            user = session.get(User, user_uuid)
            if user is None or not user.is_active or not user.is_admin:
                request.session.clear()
                return RedirectResponse(url='/admin/login', status_code=302)

        return True


class UserAdmin(ModelView, model=User):
    name = 'User'
    name_plural = 'Users'
    icon = 'fa-solid fa-user'

    column_list = [
        User.id,
        User.email,
        User.first_name,
        User.last_name,
        User.is_active,
        User.is_admin,
        User.last_login_at,
        User.created_at,
        User.updated_at,
    ]
    column_searchable_list = [User.email, User.first_name, User.last_name]
    column_sortable_list = [
        User.id,
        User.email,
        User.first_name,
        User.last_name,
        User.is_active,
        User.is_admin,
        User.last_login_at,
        User.created_at,
        User.updated_at,
    ]
    column_details_exclude_list = [User.password_hash]
    column_labels = {User.password_hash: 'Password'}

    form_columns = [
        User.id,
        User.email,
        User.first_name,
        User.last_name,
        User.password_hash,
        User.is_active,
        User.is_admin,
    ]
    form_args = {
        'password_hash': {
            'label': 'Password',
        }
    }
    form_widget_args = {
        'password_hash': {
            'type': 'password',
            'autocomplete': 'new-password',
            'placeholder': 'Enter new password',
        }
    }

    async def on_model_change(
        self, data, model: User, is_created: bool, request: Request
    ) -> None:
        email = str(data.get('email', '')).strip().lower()
        if not email:
            raise ValueError('Email is required')
        data['email'] = email

        raw_password = str(data.get('password_hash', '')).strip()
        if not raw_password:
            if is_created:
                raise ValueError('Password is required')
            data.pop('password_hash', None)
            return

        from langgraph_secure_gateway.auth.security import hash_password

        data['password_hash'] = hash_password(raw_password)


class AgentAdmin(ModelView, model=Agent):
    name = 'Agent'
    name_plural = 'Agents'
    icon = 'fa-solid fa-robot'
    create_template = 'sqladmin/agent_create.html'
    edit_template = 'sqladmin/agent_edit.html'

    column_list = [
        Agent.id,
        Agent.key,
        Agent.name,
        Agent.base_url,
        Agent.assistant_id,
        Agent.graph_id,
        Agent.is_active,
        Agent.created_at,
        Agent.updated_at,
    ]
    column_searchable_list = [Agent.key, Agent.name, Agent.base_url]
    column_sortable_list = [
        Agent.id,
        Agent.key,
        Agent.name,
        Agent.base_url,
        Agent.assistant_id,
        Agent.graph_id,
        Agent.is_active,
        Agent.created_at,
        Agent.updated_at,
    ]
    form_columns = [
        Agent.id,
        Agent.key,
        Agent.name,
        Agent.description,
        Agent.base_url,
        Agent.assistant_id,
        Agent.graph_id,
        Agent.is_active,
    ]

    async def on_model_change(
        self, data, model: Agent, is_created: bool, request: Request
    ) -> None:
        key = str(data.get('key', '')).strip()
        if not key:
            raise ValueError('Agent key is required')
        data['key'] = key

        name = str(data.get('name', '')).strip()
        if not name:
            raise ValueError('Agent name is required')
        data['name'] = name

        base_url = str(data.get('base_url', '')).strip().rstrip('/')
        if not base_url:
            raise ValueError('Agent base URL is required')
        data['base_url'] = base_url

    @expose('/discovery/agents', methods=['GET'], include_in_schema=False)
    async def discovery_agents(self, request: Request) -> JSONResponse:
        base_url = str(request.query_params.get('base_url', ''))
        try:
            agents = await discover_langgraph_agents(base_url)
        except Exception as exc:
            return JSONResponse({'detail': str(exc)}, status_code=400)
        return JSONResponse({'agents': agents})


class UserAgentAccessAdmin(ModelView, model=UserAgentAccess):
    name = 'User Agent Access'
    name_plural = 'User Agent Access'
    icon = 'fa-solid fa-key'

    column_list = [
        UserAgentAccess.id,
        UserAgentAccess.user,
        UserAgentAccess.agent,
        UserAgentAccess.created_at,
    ]
    column_sortable_list = [
        UserAgentAccess.id,
        UserAgentAccess.user_id,
        UserAgentAccess.agent_id,
        UserAgentAccess.created_at,
    ]
    form_columns = [UserAgentAccess.user, UserAgentAccess.agent]

    form_ajax_refs = {
        'user': {
            'fields': ('email', 'first_name', 'last_name'),
            'order_by': 'email',
        },
        'agent': {
            'fields': ('key', 'name'),
            'order_by': 'name',
        },
    }


def mount_admin(app) -> None:
    templates_dir = Path(__file__).resolve().parents[1] / 'templates'
    admin = Admin(
        app,
        engine,
        authentication_backend=AdminAuth(),
        templates_dir=str(templates_dir),
    )
    admin.add_view(UserAdmin)
    admin.add_view(AgentAdmin)
    admin.add_view(UserAgentAccessAdmin)
