# CyberTwin – AI-Powered SOC Assistant
# Final Year Design Project

## Project Structure

```
FINALYP/
├── cybertwin-frontend/   React + Vite dashboard & chat UI
├── cybertwin-backend/    Python FastAPI REST API + WebSocket
├── docker-compose.yml    One-command full stack startup
└── README.md
```

## Quick Start (Development)

### Option A: Without Docker (recommended for dev)

**1. Start PostgreSQL**
```powershell
# Using Docker for just the DB:
docker-compose up -d db
```

**2. Start Backend**
```powershell
cd cybertwin-backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**3. Start Frontend**
```powershell
cd cybertwin-frontend
npm install
npm run dev
```

Open: http://localhost:5173

### Option B: Full Docker Stack
```powershell
docker-compose up --build
```

## Running Tests
```powershell
cd cybertwin-backend
venv\Scripts\activate
pytest tests/ -v
```

## Phase Status

| Phase | Description | Status |
|--|--|--|
| 1 | Foundation & UI | ✅ Complete |
| 2 | Real-Time Monitoring | 🔜 Next |
| 3 | AI Core & Threat Intel | ⏳ Planned |
| 4 | Action & Approval Workflow | ⏳ Planned |
| 5 | Voice & Simulation | ⏳ Planned |

## API Endpoints

| Method | Endpoint | Description |
|--|--|--|
| GET | /api/health | Backend health check |
| POST | /api/chat | Send message, get reply |
| GET | /api/incidents | List incidents (Phase 2+) |
| WS | /ws/logs | Live log stream (Phase 2+) |
