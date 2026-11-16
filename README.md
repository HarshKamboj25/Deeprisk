# Deeprisk

**Explainable Software Supply-Chain Vulnerability Scanner**

Deeprisk is a software supply-chain security platform designed to analyze npm dependencies, identify known vulnerabilities, assess dependency risk, and generate structured security reports.

It combines dependency analysis, vulnerability intelligence, persistent scan history, and an interactive web interface to help developers understand and prioritize software supply-chain risks.

## Key Features

- **Dependency Analysis:** Parse npm lockfiles and identify project dependencies.
- **Vulnerability Intelligence:** Integrate vulnerability information from OSV and enrichment sources.
- **Dependency Graph:** Visualize relationships between packages.
- **Risk Prioritization:** Evaluate findings using explainable risk-scoring logic.
- **Security Reports:** Generate structured JSON reports for scan results.
- **Repository Scanning:** Scan supported local repositories and GitHub repositories.
- **Scan History:** Store and retrieve previous scan records.
- **Background Processing:** Execute scans through a background worker pool.
- **REST API:** Access scanning and reporting functionality through versioned API endpoints.
- **Web Dashboard:** Explore repositories, findings, reports, remediation information, and scan history.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, Vite, JavaScript |
| UI and Visualization | CSS, Recharts, Cytoscape, 3D Force Graph |
| Backend | Python, FastAPI |
| Database | SQLAlchemy, SQLite, PostgreSQL |
| Migrations | Alembic |
| HTTP Client | HTTPX, Axios |
| Testing | Pytest |
| Code Quality | Ruff, Oxlint |

## Project Structure

```text
Deeprisk/
â”‚
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ src/deprisk/
â”‚   â”‚   â”œâ”€â”€ api/
â”‚   â”‚   â”œâ”€â”€ core/
â”‚   â”‚   â”œâ”€â”€ persistence/
â”‚   â”‚   â”œâ”€â”€ vulnerability/
â”‚   â”‚   â”œâ”€â”€ cli.py
â”‚   â”‚   â”œâ”€â”€ scan.py
â”‚   â”‚   â”œâ”€â”€ report.py
â”‚   â”‚   â””â”€â”€ scanner_services.py
â”‚   â”‚
â”‚   â”œâ”€â”€ migrations/
â”‚   â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ alembic.ini
â”‚   â”œâ”€â”€ pyproject.toml
â”‚   â””â”€â”€ requirements-lock.txt
â”‚
â”œâ”€â”€ frontend/
â”‚   â”œâ”€â”€ public/
â”‚   â”œâ”€â”€ src/
â”‚   â”‚   â”œâ”€â”€ api/
â”‚   â”‚   â”œâ”€â”€ components/
â”‚   â”‚   â”œâ”€â”€ pages/
â”‚   â”‚   â”œâ”€â”€ App.jsx
â”‚   â”‚   â””â”€â”€ main.jsx
â”‚   â””â”€â”€ package.json
â”‚
â”œâ”€â”€ docs/
â””â”€â”€ README.md
```

## Prerequisites

Install the following before running Deeprisk:

- Python 3.12 or later
- Node.js and npm
- Git

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/HarshKamboj25/Deeprisk.git
cd Deeprisk
```

### 2. Set Up the Backend

Open a terminal:

```bash
cd backend

python -m venv .venv
```

Activate the virtual environment.

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the backend and development dependencies:

```bash
pip install -e ".[sqlite,dev]"
```

### 3. Configure the Backend

For local development, the default database is SQLite.

Configure the local scan workspace in PowerShell:

```powershell
$env:DEPRISK_WORKSPACE_ROOT = "C:\path\to\your\scan-workspace"
```

Optionally configure the database URL:

```powershell
$env:DEPRISK_DATABASE_URL = "sqlite+aiosqlite:///./deprisk.db"
```

The configured workspace must exist and be a directory.

### 4. Initialize the Database

From the `backend` directory:

```bash
alembic -c alembic.ini upgrade head
```

### 5. Start the Backend API

```bash
uvicorn deprisk.api.app:app --reload
```

Backend API:

`http://127.0.0.1:8000`

API documentation:

`http://127.0.0.1:8000/docs`

### 6. Set Up the Frontend

Open another terminal:

```bash
cd frontend
npm ci
```

Start the frontend development server:

```bash
npm run dev
```

Frontend:

`http://localhost:5173`

The frontend uses `VITE_API_BASE_URL` when configured and otherwise defaults to `http://127.0.0.1:8000`.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | API health check |
| GET | `/health/ready` | Database readiness check |
| GET | `/api/v1/configuration` | Workspace configuration |
| POST | `/api/v1/scans` | Submit a repository scan |
| GET | `/api/v1/scans` | Retrieve scan history |
| GET | `/api/v1/scans/{scan_id}` | Retrieve scan status |
| GET | `/api/v1/scans/{scan_id}/report` | Retrieve scan report |
| GET | `/api/v1/repositories` | List registered repositories |

## Command-Line Usage

Deeprisk also provides a command-line interface.

Scan a local repository:

```bash
python -m deprisk scan "C:\path\to\repository"
```

Scan a GitHub repository:

```bash
python -m deprisk scan "https://github.com/owner/repository"
```

Specify a report output path:

```bash
python -m deprisk scan "https://github.com/owner/repository" --output report.json
```

The CLI generates a JSON report containing the scan results.

## Database Support

Deeprisk supports:

- SQLite through `aiosqlite`
- PostgreSQL through `asyncpg`

Database configuration is controlled through `DEPRISK_DATABASE_URL`.

## Testing

Run backend tests from the `backend` directory:

```bash
pytest
```

Run lint checks:

```bash
ruff check src tests
```

Run frontend lint:

```bash
cd frontend
npm run lint
```

Build the frontend:

```bash
npm run build
```

## Security and Configuration

- Keep credentials and environment-specific configuration outside version control.
- Do not commit `.env` files, local databases, scan workspaces, or generated reports.
- Configure the local scan workspace explicitly before enabling local repository scanning.
- Use a properly configured database for persistent deployments.

## Project Status

Deeprisk is under active development. Features, scoring logic, integrations, and interface capabilities continue to evolve.

## License

A license has not yet been specified. All rights reserved unless a license is added to this repository.
