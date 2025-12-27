import os
import random
import logging
import secrets

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import event

# -------------------------------------------------
# BOOTSTRAP
# -------------------------------------------------
load_dotenv()

REQUIRED_ENV_VARS = ["SECRET_KEY", "DATABASE_URL"]
missing = [k for k in REQUIRED_ENV_VARS if not os.getenv(k)]
if missing:
    raise RuntimeError(
        "Missing required environment variables: " + ", ".join(missing)
    )

db_url = os.getenv("DATABASE_URL").replace("postgres://", "postgresql://", 1)

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_SECURE_COOKIES", "1") == "1",
)

# -------------------------------------------------
# DATABASE
# -------------------------------------------------
db = SQLAlchemy(app)

with app.app_context():
    engine = db.engine

    @event.listens_for(engine, "connect")
    def on_connect(dbapi_connection, _):
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql"):
            cursor = dbapi_connection.cursor()
            cursor.execute("SET statement_timeout = 2000")
            cursor.execute("SET lock_timeout = 600")
            cursor.execute("SET idle_in_transaction_session_timeout = 4000")
            cursor.close()

# -------------------------------------------------
# LOGGING
# -------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plinko")

# -------------------------------------------------
# LOGIN
# -------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------------------------------
# RATE LIMIT
# -------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["600 per minute"],
)

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    balance = db.Column(db.Float, default=10.0)
    winnings = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default="new")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -------------------------------------------------
# SLOT CONFIG (MUST MATCH FRONTEND)
# -------------------------------------------------
SLOT_LAYOUT = [
    1000, 100, 50, 25, 10, 5, 2, 1,
    0, 0,
    1, 2, 5, 10, 25, 50, 100, 1000
]

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("game"))

    error = None
    if request.method == "POST":
        user = User.query.filter_by(
            username=(request.form.get("username") or "").strip()
        ).first()

        if user and check_password_hash(user.password_hash, request.form.get("password")):
            login_user(user)
            user.status = "playing"
            db.session.commit()
            return redirect(url_for("game"))

        error = "اسم المستخدم أو كلمة المرور غير صحيحة"

    return render_template("login.html", error=error)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))

@app.route("/game")
@login_required
def game():
    if current_user.balance < 1:
        return redirect(url_for("result"))

    return render_template(
        "game.html",
        balance=current_user.balance,
        winnings=current_user.winnings,
        username=current_user.username,
    )

# -------------------------------------------------
# DROP (SLOT-INDEX-ONLY)
# -------------------------------------------------
@app.route("/api/drop", methods=["POST"])
@login_required
@limiter.limit("8 per second")
def drop_ball():
    try:
        user = db.session.query(User).with_for_update().get(current_user.id)

        if user.balance < 1:
            return jsonify({"error": "No balls left"}), 400

        slot_index = random.randrange(len(SLOT_LAYOUT))

        if slot_index < 0 or slot_index >= len(SLOT_LAYOUT):
            logger.error("Invalid slot index", extra={"slot_index": slot_index})
            db.session.rollback()
            return jsonify({"error": "Invalid slot"}), 500

        win_amount = float(SLOT_LAYOUT[slot_index])

        user.balance -= 1.0
        user.winnings += win_amount

        game_over = user.balance < 1
        if game_over:
            user.status = "finished"

        db.session.commit()

        return jsonify({
            "slot_index": slot_index,
            "win_amount": win_amount,
            "new_balance": user.balance,
            "new_winnings": user.winnings,
            "game_over": game_over,
        })

    except Exception:
        db.session.rollback()
        logger.exception("Drop failed")
        return jsonify({"error": "Server error"}), 500

@app.route("/api/finish", methods=["POST"])
@login_required
def finish_game():
    current_user.status = "finished"
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/result")
@login_required
def result():
    current_user.status = "finished"
    db.session.commit()

    return render_template(
        "result.html",
        amount=current_user.winnings,
        is_winner=current_user.winnings > 0,
    )

# -------------------------------------------------
# ENTRY
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5010")))
