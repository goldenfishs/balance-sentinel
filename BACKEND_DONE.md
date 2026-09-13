Backend implementation is complete in `backend/main.py` with FastAPI + SQLite, Dockerfile, docker-compose.yml, requirements.txt, and README.md.

Endpoints: `/api/accounts` CRUD, `/api/accounts/{id}/check`, `/api/accounts/check-all`, `/api/accounts/{id}/history`, `/api/health`.

Supports Sub2API `/v1/usage`; New API account `/api/user/self`; New API API-key `/api/usage/token/` with `quota_per_unit` conversion. Includes background polling and CORS. `python3 -m py_compile backend/main.py` passed.
