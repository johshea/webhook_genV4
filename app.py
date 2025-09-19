import os
import sys
import subprocess
import json
from datetime import datetime
from io import StringIO
from functools import wraps

# ---------- Inline dependency installation ----------
REQUIRED = [
    ("Flask", "flask"),
    ("Flask-Login", "flask_login"),
    ("Flask-SQLAlchemy", "flask_sqlalchemy"),
    ("Werkzeug", "werkzeug"),
    ("requests", "requests"),
]

def ensure_dependencies():
    if os.environ.get("DISABLE_AUTO_PIP") == "1":
        return
    missing = []
    for pkg, mod in REQUIRED:
        try:
            __import__(mod)
        except Exception:
            missing.append(pkg)
    if missing:
        print(f"[auto-pip] Installing missing packages: {missing}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])

ensure_dependencies()

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import requests

from models import db, User, WebhookTarget, FunctionTemplate, AuditLog

# ---------- RBAC helpers ----------
def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please login", "error")
                return redirect(url_for("login"))
            if current_user.role not in roles:
                try:
                    _audit("rbac.denied", f"user={current_user.username} role={current_user.role} tried {request.method} {request.path}")
                except Exception:
                    pass
                flash("You do not have permission to access this resource", "error")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)
        return decorated
    return wrapper

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'change-me'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webhooks.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route('/')
    def index():
        return render_template('index.html', title="Home")

    # ---------- Auth ----------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                _audit('login', f'user {username} logged in')
                if user.role == "reviewer":
                    return redirect(url_for('audit'))
                return redirect(url_for('manage'))
            flash('Invalid credentials', 'error')
        return render_template('login.html', title="Login")

    @app.route('/logout')
    @login_required
    def logout():
        _audit('logout', f'user {current_user.username} logged out')
        logout_user()
        return redirect(url_for('login'))

    # ---------- Manage (Tabbed) ----------
    @app.route('/manage')
    @login_required
    @role_required('admin', 'user')
    def manage():
        tab = request.args.get('tab', 'targets')
        if current_user.role == 'user' and tab == 'users':
            tab = 'targets'
        targets = WebhookTarget.query.order_by(WebhookTarget.name.asc()).all()
        functions = FunctionTemplate.query.order_by(FunctionTemplate.name.asc()).all()
        users = User.query.order_by(User.username.asc()).all() if current_user.role == 'admin' else []
        return render_template('manage.html', title="Manage", tab=tab, targets=targets, functions=functions, users=users)

    # Targets CRUD
    @app.post('/targets/create')
    @login_required
    @role_required('admin')
    def create_target():
        name = request.form.get('name','').strip()
        url = request.form.get('url','').strip()
        if not name or not url:
            flash('Name and URL are required', 'error')
            return redirect(url_for('manage', tab='targets'))
        t = WebhookTarget(name=name, url=url)
        db.session.add(t)
        db.session.commit()
        _audit('target.create', f'created target {name} -> {url}')
        flash('Target created', 'success')
        return redirect(url_for('manage', tab='targets'))

    @app.route('/targets/<int:target_id>/edit', methods=['GET', 'POST'])
    @login_required
    @role_required('admin')
    def edit_target(target_id):
        t = WebhookTarget.query.get_or_404(target_id)
        if request.method == 'POST':
            old = (t.name, t.url)
            t.name = request.form.get('name','').strip()
            t.url = request.form.get('url','').strip()
            db.session.commit()
            _audit('target.update', f'updated target {old} -> {(t.name, t.url)}')
            flash('Target updated', 'success')
            return redirect(url_for('manage', tab='targets'))
        return render_template('edit_target.html', title="Edit Target", target=t)

    @app.post('/targets/<int:target_id>/delete')
    @login_required
    @role_required('admin')
    def delete_target(target_id):
        t = WebhookTarget.query.get_or_404(target_id)
        _audit('target.delete', f'deleted target {t.name}')
        db.session.delete(t)
        db.session.commit()
        flash('Target deleted', 'success')
        return redirect(url_for('manage', tab='targets'))

    # Functions CRUD
    @app.post('/functions/create')
    @login_required
    @role_required('admin')
    def create_function():
        name = request.form.get('name','').strip()
        json_template = request.form.get('json_template','').strip()
        if not name or not json_template:
            flash('Name and JSON Template are required', 'error')
            return redirect(url_for('manage', tab='functions'))
        try:
            json.loads(json_template)
        except Exception as e:
            flash(f'Invalid JSON: {e}', 'error')
            return redirect(url_for('manage', tab='functions'))
        f = FunctionTemplate(name=name, json_template=json_template)
        db.session.add(f)
        db.session.commit()
        _audit('function.create', f'created function {name}')
        flash('Function created', 'success')
        return redirect(url_for('manage', tab='functions'))

    @app.route('/functions/<int:function_id>/edit', methods=['GET', 'POST'])
    @login_required
    @role_required('admin')
    def edit_function(function_id):
        f = FunctionTemplate.query.get_or_404(function_id)
        if request.method == 'POST':
            old = (f.name,)
            name = request.form.get('name','').strip()
            json_template = request.form.get('json_template','').strip()
            try:
                json.loads(json_template)
            except Exception as e:
                flash(f'Invalid JSON: {e}', 'error')
                return render_template('edit_function.html', title="Edit Function", function=f)
            f.name = name
            f.json_template = json_template
            db.session.commit()
            _audit('function.update', f'updated function {old} -> {(f.name,)}')
            flash('Function updated', 'success')
            return redirect(url_for('manage', tab='functions'))
        return render_template('edit_function.html', title="Edit Function", function=f)

    @app.post('/functions/<int:function_id>/delete')
    @login_required
    @role_required('admin')
    def delete_function(function_id):
        f = FunctionTemplate.query.get_or_404(function_id)
        _audit('function.delete', f'deleted function {f.name}')
        db.session.delete(f)
        db.session.commit()
        flash('Function deleted', 'success')
        return redirect(url_for('manage', tab='functions'))

    # Users CRUD (admin-only)
    @app.post('/users/create')
    @login_required
    @role_required('admin')
    def create_user():
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        role = request.form.get('role','user')
        if not username or not password:
            flash('Username and password required', 'error')
            return redirect(url_for('manage', tab='users'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('manage', tab='users'))
        u = User(username=username, password_hash=generate_password_hash(password), role=role)
        db.session.add(u)
        db.session.commit()
        _audit('user.create', f'created user {username} role={role}')
        flash('User created', 'success')
        return redirect(url_for('manage', tab='users'))

    @app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
    @login_required
    @role_required('admin')
    def edit_user(user_id):
        u = User.query.get_or_404(user_id)
        if request.method == 'POST':
            old = (u.username, u.role)
            u.username = request.form.get('username','').strip()
            pwd = request.form.get('password','')
            if pwd:
                u.password_hash = generate_password_hash(pwd)
            u.role = request.form.get('role','user')
            db.session.commit()
            _audit('user.update', f'updated user {old} -> {(u.username, u.role)}')
            flash('User updated', 'success')
            return redirect(url_for('manage', tab='users'))
        return render_template('edit_user.html', title="Edit User", user=u)

    @app.post('/users/<int:user_id>/delete')
    @login_required
    @role_required('admin')
    def delete_user(user_id):
        u = User.query.get_or_404(user_id)
        if u.id == current_user.id:
            flash('You cannot delete your own account', 'error')
            return redirect(url_for('manage', tab='users'))
        _audit('user.delete', f'deleted user {u.username}')
        db.session.delete(u)
        db.session.commit()
        flash('User deleted', 'success')
        return redirect(url_for('manage', tab='users'))

    # ---------- Send Webhook ----------
    @app.route('/send', methods=['GET', 'POST'])
    @login_required
    @role_required('admin', 'user')
    def send():
        targets = WebhookTarget.query.order_by(WebhookTarget.name.asc()).all()
        functions = FunctionTemplate.query.order_by(FunctionTemplate.name.asc()).all()

        selected_function = None
        selected_target = None
        payload = None
        response_text = None

        if request.method == 'POST':
            target_id = request.form.get('target_id')
            function_id = request.form.get('function_id')
            action = request.form.get('action')

            if function_id:
                selected_function = FunctionTemplate.query.get(int(function_id))
                if not request.form.get('payload'):
                    payload = selected_function.json_template

            if target_id:
                selected_target = WebhookTarget.query.get(int(target_id))

            if action == 'send':
                payload = request.form.get('payload') or (selected_function.json_template if selected_function else None)
                if not (selected_target and payload):
                    flash('Select a target and provide a JSON payload', 'error')
                else:
                    try:
                        body = json.loads(payload)
                    except Exception as e:
                        flash(f'Invalid JSON: {e}', 'error')
                        return render_template('send.html', title="Send", targets=targets, functions=functions,
                                               selected_function=selected_function, selected_target=selected_target, payload=payload)
                    try:
                        r = requests.post(selected_target.url, json=body, timeout=15)
                        response_text = f"HTTP {r.status_code}\n\n" + (r.text or "")
                        _audit('webhook.send', f"sent to {selected_target.name} ({selected_target.url}) status={r.status_code}")
                    except Exception as e:
                        response_text = f"Error sending request: {e}"
                        _audit('webhook.error', f"error sending to {selected_target.name if selected_target else 'N/A'}: {e}")
        return render_template('send.html', title="Send", targets=targets, functions=functions,
                               selected_function=selected_function, selected_target=selected_target,
                               payload=payload, response=response_text)

    # ---------- Audit ----------
    @app.route('/audit')
    @login_required
    @role_required('admin', 'reviewer')
    def audit():
        audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(500).all()
        return render_template('audit.html', title="Audit Log", audits=audits)

    @app.route('/audit/export')
    @login_required
    @role_required('admin', 'reviewer')
    def export_audit_csv():
        audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5000).all()
        sio = StringIO()
        sio.write('timestamp,username,action,details\n')
        for a in audits:
            user = a.user.username if a.user else ''
            details = (a.details or '').replace('"','""')
            sio.write(f'"{a.timestamp}","{user}","{a.action}","{details}"\n')
        sio.seek(0)
        return Response(
            sio.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=audit_log.csv'}
        )

    # ---------- Helpers ----------
    def _audit(action, details):
        entry = AuditLog(user_id=current_user.id if hasattr(current_user, 'id') else None,
                         action=action, details=details)
        db.session.add(entry)
        db.session.commit()

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
