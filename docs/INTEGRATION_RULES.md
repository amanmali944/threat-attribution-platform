# Platform Integration & Hand-off Rules

## 1. Boundary & Governance Principles

- **Developer B (Platform & Presentation Owner):** Owns database schemas, ORM models, Pydantic contracts, API controllers, Docker infrastructure, and UI presentation components.
- **Developer A (ML & Attribution Owner):** Owns rule evaluation algorithms, cross-layer graph correlation logic, TTP mapping, and ML detection pipelines.

---

## 2. Technical Integration Rules

1. **No Direct SQL in Detection Engine:** Developer A's logic must interact with data via ORM models (`backend/app/models/`) or designated service layer methods, never executing un-parameterized raw SQL.
2. **Schema Integrity:** Any addition or modification to telemetry fields, database columns, or API response bodies MUST be updated in `docs/` contracts first before updating code.
3. **Pydantic Validation:** All API inputs and engine responses MUST pass Pydantic schema validation (`backend/app/schemas/`).
4. **Environment Isolation:** Secrets and infrastructure settings (database credentials, API keys) must be fetched exclusively via `backend/app/core/config.py` backed by `.env`. Hardcoded credentials are strictly forbidden.
5. **Fixtures as Test Bench:** The data fixtures in `data/fixtures/` serve as the golden baseline test vectors for offline testing of both detection algorithms and API response parsing.
