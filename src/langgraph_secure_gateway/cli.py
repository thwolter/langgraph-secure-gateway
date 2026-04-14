"""CLI for secure LangGraph deploy and gateway operations."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import typer

from langgraph_secure_gateway.auth.db import ensure_auth_schema
from langgraph_secure_gateway.auth_cli import create_or_update_admin_user
from langgraph_secure_gateway.templates import (
    COMPOSE_TEMPLATE,
    DOCKERFILE_TEMPLATE,
    ENV_EXAMPLE_TEMPLATE,
    write_if_missing,
)

app = typer.Typer(help='Security and deploy tooling for LangGraph apps.')


@app.command('build')
def build(
    tag: str = typer.Option('langgraph-app', '--tag', '-t'),
    config: Path = typer.Option(Path('langgraph.json'), '--config', '-c'),
    base_image: str = typer.Option(
        'langchain/langgraph-api:3.11-wolfi', '--base-image'
    ),
    api_version: str | None = typer.Option(None, '--api-version'),
    engine_runtime_mode: str = typer.Option(
        'combined_queue_worker', '--engine-runtime-mode'
    ),
    no_pull: bool = typer.Option(False, '--no-pull'),
    extra: list[str] = typer.Argument(None),
) -> None:
    """Wrap langgraph build and apply baseline secure defaults."""
    cmd = [
        'langgraph',
        'build',
        '-t',
        tag,
        '-c',
        str(config),
        '--base-image',
        base_image,
        '--engine-runtime-mode',
        engine_runtime_mode,
    ]
    if api_version:
        cmd.extend(['--api-version', api_version])
    if no_pull:
        cmd.append('--no-pull')
    if extra:
        cmd.extend(extra)

    raise SystemExit(subprocess.call(cmd))


@app.command('create-admin-user')
def create_admin_user(
    username: str = typer.Option(..., '--username'),
    password: str = typer.Option(..., '--password'),
    inactive: bool = typer.Option(False, '--inactive'),
) -> None:
    """Create or rotate an admin user in the auth database."""
    action = create_or_update_admin_user(
        username=username, password=password, inactive=inactive
    )
    typer.echo(f"Admin user '{username}' {action}.")


@app.command('init-db')
def init_db() -> None:
    """Create auth schema tables in Postgres if they do not exist."""
    ensure_auth_schema()
    typer.echo('Auth schema ensured.')


@app.command('init-deploy')
def init_deploy(
    cwd: Path = typer.Option(Path('.'), '--cwd'),
    image_tag: str = typer.Option('langgraph-app', '--image-tag'),
    force: bool = typer.Option(False, '--force'),
    include_dockerfile: bool = typer.Option(
        True, '--include-dockerfile/--no-include-dockerfile'
    ),
    security_dependency: str = typer.Option(
        'langgraph-secure-gateway',
        '--security-dependency',
        help='Dependency string to inject into langgraph.json dependencies if missing.',
    ),
) -> None:
    """Generate deploy files for a LangGraph project with secure gateway."""
    target = cwd.resolve()
    compose_path = target / 'docker-compose.yaml'
    env_example_path = target / '.env.example'
    dockerfile_path = target / 'Dockerfile'

    wrote_compose = write_if_missing(
        compose_path,
        COMPOSE_TEMPLATE.format(image_tag=image_tag),
        force=force,
    )
    wrote_env = write_if_missing(env_example_path, ENV_EXAMPLE_TEMPLATE, force=force)
    wrote_dockerfile = False
    if include_dockerfile:
        wrote_dockerfile = write_if_missing(
            dockerfile_path, DOCKERFILE_TEMPLATE, force=force
        )

    langgraph_config_path = target / 'langgraph.json'
    if langgraph_config_path.exists():
        data = json.loads(langgraph_config_path.read_text(encoding='utf-8'))
        dependencies = data.get('dependencies') or []
        if security_dependency not in dependencies:
            dependencies.append(security_dependency)
            data['dependencies'] = dependencies
            langgraph_config_path.write_text(
                json.dumps(data, indent=2) + '\n', encoding='utf-8'
            )
            typer.echo(f'updated: {langgraph_config_path}')

    for path, wrote in [
        (compose_path, wrote_compose),
        (env_example_path, wrote_env),
        (dockerfile_path, wrote_dockerfile if include_dockerfile else False),
    ]:
        if include_dockerfile or path != dockerfile_path:
            status = 'created' if wrote else 'skipped'
            typer.echo(f'{status}: {path}')
