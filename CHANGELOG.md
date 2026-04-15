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
