# Network Security and Firewall Monitoring System

A responsive Flask + SQLite cybersecurity dashboard for demonstrating network traffic monitoring, firewall policy evaluation, suspicious-activity heuristics, alerts, and audit logging.

## Features
- Session-based administrator login
- Dashboard KPIs and Chart.js visualizations
- Simulated traffic feed with automatic refresh
- Search and filter traffic by IP, protocol, and access status
- Firewall rule CRUD, enable/disable, and first-match packet filtering
- Suspicious-activity heuristics: connection bursts, repeated blocks, unusual ports, and possible port scans
- Security alerts with resolve action
- Searchable security event log
- SQLite persistence and sample traffic

## Requirements
- Python 3.9+
- pip
- Internet connection on first dashboard load for Chart.js and Google Fonts CDN (the core Flask app itself is local)

## Run on Windows
1. Extract the project ZIP.
2. Open Command Prompt or PowerShell in the extracted folder.
3. Create a virtual environment:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   ```
4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
5. Start the server:
   ```powershell
   py app.py
   ```
6. Open http://127.0.0.1:5000

## Run on Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Demo login
- Username: `admin`
- Password: `admin123`

Change the demo password and `SECRET_KEY` before any deployment. This sample intentionally uses a local development secret and debug mode for classroom demonstration.

## How to demonstrate
1. Sign in and review the dashboard charts and KPI cards.
2. Open **Network Traffic** and filter by source IP, TCP/UDP, or ALLOWED/BLOCKED.
3. Add a firewall rule, for example source `*`, destination `*`, port `23`, protocol `TCP`, action `BLOCK`.
4. Add a traffic record targeting TCP port 23 and verify that it is classified as BLOCKED.
5. Use **Generate test traffic** to append simulated traffic. Some generated events deliberately create burst or unusual-port patterns.
6. Review **Suspicious Activities** and **Security Alerts**, then resolve an alert.
7. Open **Security Logs** to inspect traffic and administrative events.

## Firewall matching logic
- `*` matches any source or destination IP.
- CIDR networks such as `192.168.1.0/24` are supported.
- Port `0` matches any port.
- Protocol `ANY` matches TCP and UDP.
- Rules are evaluated in ascending rule ID (first match wins).
- If no rule matches, the demonstration default policy allows the record.

## API endpoints
All API endpoints require an authenticated session.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/dashboard` | KPI and chart data |
| GET | `/api/traffic` | Traffic records (`q`, `protocol`, `status` filters) |
| POST | `/api/traffic` | Submit a traffic record for rule evaluation |
| GET / POST | `/api/rules` | List / create firewall rules |
| PUT / DELETE | `/api/rules/<id>` | Update / delete a firewall rule |
| GET | `/api/suspicious` | Suspicious source summary |
| GET | `/api/alerts` | List security alerts |
| POST | `/api/alerts/<id>/resolve` | Resolve an alert |
| GET | `/api/logs` | Search security logs (`q` filter) |
| POST | `/api/simulate` | Generate one simulated traffic event |
| GET | `/api/settings` | Read demonstration settings |

## Database
The SQLite database `security_monitor.db` is created automatically on first run and seeded with example rules and simulated traffic. Delete that file to reset the demo data (stop the app first).

## Safety and scope
This project uses **simulated network traffic**. It does not sniff live packets, scan external systems, or change operating-system firewall settings. Any future packet-capture integration or real firewall modification must be separately implemented with explicit administrator authorization, least privilege, and a clearly defined network scope. Do not deploy the demo credentials or development settings to a public server.
