## 0.6.0 (2026-04-21)

### BREAKING CHANGE

- Authentication now requires email; username is deprecated. Update configurations and scripts to use `--email` instead of `--username`.

### Feat

- **devops**: add Docker support with Compose for local development
- **auth**: replace username with email for authentication and user profiles
- **auth**: add LangGraph `auth.py` handlers and auto-configure `langgraph.json`
- **gateway**: enforce canonical runtime identity in run payloads

## 0.5.0 (2026-04-16)

### Feat

- **gateway**: add identity injection into request payloads

## 0.4.0 (2026-04-15)

### BREAKING CHANGE

- User IDs are now UUIDs, affecting database schema, API responses, and JWT payload structure. Use `reset-db` to migrate.

### Feat

- **auth**: migrate user IDs to UUIDs and update related logic
- **deps**: update dependencies and enhance compatibility

## 0.3.0 (2026-04-14)

### Feat

- **gateway**: add custom OpenAPI endpoints and update API docs
- **admin**: improve user management form customization

## 0.2.0 (2026-04-14)

### BREAKING CHANGE

- Removed SQL file-based schema initialization in favor of runtime and CLI-based schema setup.

### Feat

- add pre-commit
- **auth**: add database schema initialization for auth tables
