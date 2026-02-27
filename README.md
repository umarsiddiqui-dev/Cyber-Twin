# CyberTwin — AI-Powered SOC Assistant 🛡️

CyberTwin is an advanced Cybersecurity Incident Response platform designed to augment SOC (Security Operations Center) analysts. It provides real-time threat detection, AI-driven remediation playbooks, interactive attack simulation, and live threat intelligence integration.

![CyberTwin Logo](cybertwin-frontend/public/vite.svg) (*Placeholder for Logo*)

---

## ✨ Key Features

- **AI Triage & Remediation**: Automatically parses syslog/Snort/OSSEC logs and proposes concrete shell actions (e.g., firewall IP blocks, process kills) via OpenAI's GPT models.
- **Zero-Trust Execution Gate**: Strictly enforced JWT-based authentication ensures that remediation commands cannot be executed or spoofed without analyst cryptographic approval.
- **Live Threat Intelligence**: Hot-loads MITRE ATT&CK® STIX 2.0 bundles to accurately classify network incidents against known CTI (Cyber Threat Intelligence) frameworks.
- **Integrated Attack Simulator**: Built-in Atomic Red Team–inspired simulations (e.g., brute-force, ransomware, network scanning) that stream realistic log sequences into the ingest pipeline for training and system testing.
- **Data Integrity & Audit Logging**: Cryptographically tamper-evident audit logs (using immutable SQLAlchemy event hooks) track the complete lifecycle of every AI decision.

---

## 🏗️ Project Architecture

CyberTwin operates on a modern decoupled architecture:

* **Backend**: Python 3.12+ with FastAPI, SQLAlchemy (SQLite/Async), HTTPX, and Python-JOSE.
* **Frontend**: React 18 with Vite, Axios, and raw CSS for ultra-fast, tailored dark-mode aesthetics.
* **Real-time Pipeline**: WebSockets provide sub-millisecond transmission of incoming server logs and AI reasoning streams to the analyst dashboard.

---

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed:
- **Python 3.11+**
- **Node.js 18+** & **npm**
- An **OpenAI API Key** (for AI analysis and action generation)

---

## 🚀 Setup Instructions

### 1. Backend Initialization

Open a terminal and navigate to the backend directory:

```bash
cd cybertwin-backend
```

Create and activate a Python virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Configure Environment Variables:
Copy the `.env.example` (if present) or create a `.env` file in the `cybertwin-backend` directory:
```env
# cybertwin-backend/.env
OPENAI_API_KEY=sk-your-openai-api-key-here
SECRET_KEY=generate-a-secure-64-char-hex-string
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
DEBUG=false
```

### 2. Frontend Initialization

Open a *new* terminal block and navigate to the frontend directory:

```bash
cd cybertwin-frontend
```

Install Node modules:
```bash
npm install
```

Configure Environment Variables:
Create a `.env` file in the `cybertwin-frontend` directory:
```env
# cybertwin-frontend/.env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/logs
```

---

## 💻 Running the Application

### Start the Backend Server
From the `cybertwin-backend` directory (with your virtual environment activated):
```bash
uvicorn app.main:app --reload --port 8000
```
*Note: If `LOG_FILE_PATH` is not configured in your `.env`, the backend will safely boot in **Simulation Mode**, actively tailing an internal mock stream rather than a live system file.*

### Start the Frontend Dev Server
From the `cybertwin-frontend` directory:
```bash
npm run dev
```

Navigate to `http://localhost:5173` in your browser. You will be greeted by the CyberTwin Login screen. Enter the `ADMIN_USERNAME` and `ADMIN_PASSWORD` you configured in your backend `.env` file to access the SOC Dashboard.

---

## 🧪 Running Tests

CyberTwin maintains a robust Pytest suite testing all core logic, authentication boundaries, and edge cases. To run the tests:

```bash
cd cybertwin-backend
# Ensure the virtual environment is activated
python -m pytest tests/ -v
```

---

## 🔒 Security Posture & Hardening

As an incident response platform, CyberTwin employs strict hardening:
1. **Never** run the frontend in production with `VITE_API_URL` pointing to localhost unless accessing it locally.
2. The `cybertwin.db` SQLite database must be strictly permissioned on the host OS.
3. In production environments, replace the in-memory SQLite database with a hardened PostgreSQL instance via SQLAlchemy's connection string in `app/database.py`.

---
*Developed as a Final Year Project for Advanced AI Cybersecurity Operations.*
