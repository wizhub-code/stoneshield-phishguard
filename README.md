# 🛡️ Stoneshield PhishGuard

**Affordable phishing detection and social engineering protection for businesses, startups, and NGOs.**

---

## Architecture Overview

```
stoneshield/
├── app/
│   ├── main.py                    # FastAPI app entry point
│   ├── core/
│   │   ├── config.py              # Pydantic settings (.env)
│   │   ├── database.py            # SQLAlchemy + SQLite setup
│   │   └── security.py            # bcrypt + JWT auth
│   ├── models/
│   │   ├── user.py                # User ORM model
│   │   └── scan.py                # Scan ORM model
│   ├── schemas/
│   │   ├── auth.py                # Auth request/response schemas
│   │   └── scan.py                # Scan request/response schemas
│   ├── routers/
│   │   ├── auth.py                # /api/v1/auth/* endpoints
│   │   └── scan.py                # /api/v1/scans/* endpoints
│   └── services/
│       └── detection_engine.py    # Phishing detection core
├── tests/
│   └── test_core.py               # Pytest test suite
├── Dockerfile                     # Multi-stage Docker build
├── docker-compose.yml             # Local dev + production stack
├── requirements.txt               # Python dependencies
├── alembic.ini                    # DB migrations config
├── .env.example                   # Environment variable template
└── README.md
```

---

## Quick Start

### Option 1 — Local Python

```bash
# 1. Clone and enter project
cd stoneshield

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — at minimum change SECRET_KEY

# 5. Run the server
uvicorn app.main:app --reload --port 8000
```

API live at: http://localhost:8000
Interactive docs: http://localhost:8000/docs

---

### Option 2 — Docker (recommended for production)

```bash
# Build and start all services
docker-compose up --build -d

# View logs
docker-compose logs -f api

# Stop
docker-compose down
```

---

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/signup` | Register new account |
| POST | `/api/v1/auth/token` | Login (OAuth2 form) |
| POST | `/api/v1/auth/login` | Login (JSON body) |
| GET | `/api/v1/auth/me` | Get current user |
| PUT | `/api/v1/auth/me` | Update profile |

### Phishing Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scans/analyze` | Analyze message for threats |
| GET | `/api/v1/scans/` | List scan history (paginated) |
| GET | `/api/v1/scans/stats` | Get aggregate statistics |
| GET | `/api/v1/scans/{id}` | Get single scan result |
| DELETE | `/api/v1/scans/{id}` | Delete a scan |
| DELETE | `/api/v1/scans/` | Delete all scans |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |
| GET | `/redoc` | ReDoc UI |

---

## Detection Engine

Four detection modules, each with pattern matching and weighted scoring:

| Module | Weight | Detects |
|--------|--------|---------|
| Suspicious Links | 35 | IP URLs, lookalike domains, shorteners, bad TLDs |
| Urgency Language | 25 | Pressure tactics, account threats, deadlines |
| Impersonation | 30 | Banks, PayPal, Microsoft, Apple, IRS, Google |
| Credential Harvesting | 40 | Password/SSN/card requests |

**Risk Classification:**
- `SAFE` — Score 0–19
- `SUSPICIOUS` — Score 20–54
- `DANGEROUS` — Score 55–100

---

## Example API Usage

### Signup
```bash
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name": "Jane Smith", "email": "jane@company.com", "password": "secure123", "organization": "Acme Corp"}'
```

### Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -F "username=jane@company.com" \
  -F "password=secure123"
```

### Scan a Message
```bash
curl -X POST http://localhost:8000/api/v1/scans/analyze \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content": "URGENT: Your PayPal account is compromised. Click http://paypa1-xyz.tk to verify now."}'
```

### Example Response
```json
{
  "id": "abc123",
  "risk_level": "DANGEROUS",
  "risk_score": 87,
  "flagged_categories": ["Suspicious Links", "Urgency Language", "Impersonation Attempt"],
  "detection_results": {
    "suspicious_links": { "label": "Suspicious Links", "score": 35, "match_count": 2, "matches": ["http://paypa1-xyz.tk"] },
    "urgency_language": { "label": "Urgency Language", "score": 25, "match_count": 1, "matches": ["URGENT"] },
    "impersonation":    { "label": "Impersonation Attempt", "score": 30, "match_count": 1, "matches": ["PayPal"] },
    "credential_harvesting": { "label": "Credential Harvesting", "score": 0, "match_count": 0, "matches": [] }
  },
  "recommendation": "HIGH RISK — Strong phishing indicators detected...",
  "scan_duration_ms": 3,
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Security Notes

- Passwords hashed with **bcrypt** via `passlib`
- Authentication via signed **JWT** tokens (python-jose)
- **Multi-tenant**: users can only access their own scan data
- All routes except `/health`, `/docs`, `/api/v1/auth/*` require Bearer token
- Change `SECRET_KEY` in `.env` before any production deployment

---

## Roadmap

- [ ] AI/LLM-powered semantic analysis (OpenAI / local model)
- [ ] Real-time email scanning (Gmail API, Microsoft Graph)
- [ ] Slack / Teams bot integration
- [ ] Webhook alerts for high-risk detections
- [ ] Enterprise reporting + PDF exports
- [ ] Subscription billing (Stripe)
- [ ] PostgreSQL support for production scale
- [ ] Admin dashboard for multi-user management
- [ ] API key management for B2B integrations

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API Framework | FastAPI |
| Database ORM | SQLAlchemy 2.0 |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Migrations | Alembic |
| Password Hashing | passlib + bcrypt |
| Authentication | JWT (python-jose) |
| Validation | Pydantic v2 |
| Server | Uvicorn |
| Containerization | Docker + Docker Compose |
| Testing | Pytest |

---

Built by Stoneshield Security — Protecting underserved organizations from phishing attacks.
