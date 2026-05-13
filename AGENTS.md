# Repository Guidelines

## Project Structure & Module Organization
- `public/` holds the web entry points. `public/index.php` renders the agent status page, and `public/api/index.php` exposes the demo JSON API.
- `.docker/` contains the Dockerfile and Apache vhost config used for container builds.
- `.github/workflows/` defines the CI workflow for building/pushing Docker images.
- `temporary_http2tcp-server-test/` is a reference README for server-side signing flow examples.

## Build, Test, and Development Commands
- Build a production image:
  ```bash
  docker build -f .docker/Dockerfile --target prod -t http2tcp-local-agent .
  ```
- Build a dev image (same Dockerfile, dev target):
  ```bash
  docker build -f .docker/Dockerfile --target dev -t http2tcp-local-agent-dev .
  ```
- Run locally (matches README defaults):
  ```bash
  docker run -d --restart=unless-stopped --name http2tcp-agent -p 127.0.0.1:34279:80 http2tcp-local-agent
  ```

## Coding Style & Naming Conventions
- PHP files use standard PHP formatting with 4-space indentation.
- Keep public endpoints in `public/` and route-specific handlers in `public/api/`.
- Use clear, lowercase, hyphenated instruction names (e.g., `test-connection`, `print-recipe`).
- Prefer environment configuration via Dockerfile/env vars (e.g., `HTTP2TCP_CORS_ALLOW_ORIGIN`).

## Testing Guidelines
- There are no automated tests in this repository yet.
- If you add tests, document the framework and add a matching command in this file.

## Commit & Pull Request Guidelines
- Current git history uses very short messages (e.g., `build`). No formal convention is enforced.
- For PRs: include a concise description, how to verify (commands or endpoints), and any relevant screenshots if UI output changes.

## Security & Configuration Tips
- CORS origin is controlled by `HTTP2TCP_CORS_ALLOW_ORIGIN` (set in the Dockerfile by default).
- The agent expects signed requests and uses TOFU key pairing; keep key material on the server side and never embed private keys in the agent.
- Runtime signature verification uses libsodium (`sodium_crypto_sign_verify_detached`) — bundled with PHP 8.x, no external binaries required.
- All configuration keys use the `HTTP2TCP_` prefix (see `.env` for defaults).
