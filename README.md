# Flask Webhook Manager (RBAC)

A Flask app that:
- Manages webhook targets (name + URL)
- Manages "Functions" that store JSON templates
- Manages users (add/edit/delete) and maintains an audit log (CSV exportable)
- Sends webhooks by selecting a target + function template, with an editable JSON payload
- Login-protected (Flask-Login) with RBAC: **admin**, **user**, **reviewer**
- Consistent styling via a local `static/style.css`
- Inline module auto-install in `app.py` to fetch missing dependencies on first start

## RBAC (Roles)
- **admin**: full control (Targets, Functions, Users, Send, Audit + CSV export)
- **user**: view Targets/Functions, can **Send**, no Users/Audit
- **reviewer**: **Audit** (view + CSV), no Manage/Send

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # optional (app can auto-install)

# Initialize DB and a default admin user (admin / admin123)
python seed.py

# Run the app
export FLASK_APP=main.py          # Windows: set FLASK_APP=main.py
flask run --port 5000
```

Open http://127.0.0.1:5000

**Default Admin**
- username: `admin`
- password: `admin123` (change it immediately)

## Inline Dependency Installation
`main.py` will attempt to install missing modules (Flask, Flask-Login, Flask-SQLAlchemy, requests, Werkzeug) at startup.
Disable via: `DISABLE_AUTO_PIP=1`.
