# Copilot instructions for Projekt-zespolowy

Short, actionable notes to help an AI code assistant be productive immediately.

- Project type: small PHP monolith serving a voting portal (no framework).
- DB: MySQL initialized from `wybory_portal.sql` / `init_db.sh`. The DB connection and common helpers live in `core.php` (exports `$conn`, CSRF helpers and security helpers).
- Auth model: users are identified by `pesel` (normal users) and `admin_username` (admins). See `login.php` and `register.php` for the canonical flows.
- Voting flow: tokens live in `vote_tokens`. `vote.php` validates a token, marks it used and increments candidate votes inside a transaction. Pay attention to transaction usage and token expiry logic.
- Results API: `results_api.php` returns JSON arrays `names` and `votes` used by the Chart.js front-end in `index.php`.

Important files to reference:
- `core.php` — DB connection, `checkCSRFOrDie()`, `getCSRFInput()`, and `PasswordSecurity` helpers.
- `login.php` / `register.php` — unified login (PESEL or admin_username) and registration including PESEL validation.
- `vote.php` — token validation and vote transaction semantics.
- `admin_panel.php` — admin-only flows (create elections, add candidates, promote users). Uses `$_SESSION['is_admin']` gating.
- `results_api.php` & `index.php` — public results pipeline (server-side JSON → Chart.js client).
- `init_db.sh`, `wybory_portal.sql`, `Dockerfile`, `docker-compose.yml` — environment and DB initialization.

Patterns & conventions (project-specific):
- Always use `$conn` from `core.php`. Most DB access uses prepared statements (`$conn->prepare`) — follow that pattern. Some places rely on casting to int before interpolating (e.g., `vote.php`), but prefer prepared statements when adding features.
- CSRF: POST forms include `<?= getCSRFInput() ?>` and server-side calls `checkCSRFOrDie()`; preserve this pattern for all state-changing endpoints.
- Sessions: `session_start()` is used; session flags are set in `login.php` (`user_id`, `is_admin`, `admin_username`, etc.). Rely on these keys for authorization checks.
- Input sanitization: HTML output uses `htmlspecialchars()` in views; JSON endpoints rely on `json_encode()`.
- Transactions: when updating multiple related rows (vote increment + token mark, or user promotion), use `$conn->begin_transaction()`, `commit()`, `rollback()` on errors.

Developer workflows (how to run & debug):
- Local quick run (PHP built-in):
  php -S localhost:8000 -t .
- Docker: use the provided `docker-compose.yml` to build and run full environment (database initialization uses `init_db.sh`). Typical command:
  docker-compose up --build
- DB initialization: run `bash init_db.sh` or import `wybory_portal.sql` into MySQL if running standalone.
- Logs & debugging: code uses `error_log()` in several places (see `login.php`). Check PHP / container logs for these messages.

Security notes (observed from code):
- Prepared statements used widely — continue this practice. When adding direct queries, cast inputs to ints or use prepared statements.
- CSRF helpers are mandatory for POST endpoints; do not bypass.
- Password handling uses `PasswordSecurity` wrapper around `password_hash`/`password_verify` — use it consistently.

If you modify or add endpoints, follow these steps:
1. Add server-side CSRF enforcement (`checkCSRFOrDie()` on POST).
2. Use prepared statements and transactions for multi-step updates.
3. Update front-end (Chart.js fetch URL or form actions) and ensure `results_api.php` JSON shape (`names`, `votes`) stays compatible.

If any part of this file is unclear or you'd like deeper examples (e.g., typical prepared-statement template or session checks), tell me which area and I will expand with concrete snippets.
