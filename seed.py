from main import create_app
from models import db, User
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin",
                     password_hash=generate_password_hash("admin123"),
                     role="admin")
        db.session.add(admin)
        db.session.commit()
        print("Created default admin: admin / admin123")
    else:
        print("Admin user already exists")


# Self-delete after successful run to prevent reuse
try:
    import pathlib
    pathlib.Path(__file__).unlink(missing_ok=True)
    print("seed.py removed after initialization.")
except Exception as e:
    print(f"Warning: could not remove seed.py: {e}")
