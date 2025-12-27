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
# RENDER-PRO READY BOOTSTRAP
# -------------------------------------------------
load_dotenv()

REQUIRED_ENV_VARS = ["SECRET_KEY", "DATABASE_URL"]
missing = [k for k in REQUIRED_ENV_VARS if not os.getenv(k)]
if missing:
    raise RuntimeError(
        "Missing required environment variables: "
        + ", ".join(missing)
        + ". Set them in Render (Environment tab)."
    )

db_url = os.getenv("DATABASE_URL", "").strip()
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

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
)

secure_cookies = os.getenv("FLASK_SECURE_COOKIES", "1") == "1"
app.config["SESSION_COOKIE_SECURE"] = secure_cookies

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": int(os.getenv("DB_POOL_SIZE", "5")),
    "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "10")),
}

# -------------------------------------------------
# DATABASE (✅ FIXED: SINGLE INIT)
# -------------------------------------------------
db = SQLAlchemy()
db.init_app(app)

# -------------------------------------------------
# DATABASE EVENTS (✅ CONTEXT SAFE)
# -------------------------------------------------
with app.app_context():
    engine = db.engine

    @event.listens_for(engine, "connect")
    def on_connect(dbapi_connection, _):
        cursor = dbapi_connection.cursor()
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql"):
            cursor.execute(
                f"SET statement_timeout = {os.getenv('DB_STATEMENT_TIMEOUT_MS', '2000')}"
            )
            cursor.execute(
                f"SET lock_timeout = {os.getenv('DB_LOCK_TIMEOUT_MS', '600')}"
            )
            cursor.execute(
                f"SET idle_in_transaction_session_timeout = {os.getenv('DB_IDLE_TX_TIMEOUT_MS', '4000')}"
            )
        cursor.close()

# -------------------------------------------------
# CSRF HELPERS
# -------------------------------------------------
def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token

def validate_csrf_token(token_from_form: str) -> bool:
    token_in_session = session.pop("csrf_token", None)
    return bool(token_in_session and token_from_form and token_in_session == token_from_form)

# -------------------------------------------------
# LOGGING
# -------------------------------------------------
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("app")

# -------------------------------------------------
# LOGIN MANAGER
# -------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# -------------------------------------------------
# RATE LIMITING
# -------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.getenv("LIMITER_STORAGE_URI", "memory://"),
    default_limits=["600 per minute"],
)

# -------------------------------------------------
# DATABASE MODELS
# -------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    balance = db.Column(db.Float, default=10.0)
    winnings = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default="new")

    assigned_prize = db.Column(db.Float, default=0.0)
    prize_claimed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))

# -------------------------------------------------
# SLOT CONFIG
# -------------------------------------------------
# MUST MATCH FRONTEND SLOT_VALUES_KWD EXACTLY
SLOT_LAYOUT = [
    1000, 200, 100, 50, 25, 10, 5, 2,
    0, 0,
    2, 5, 10, 25, 50, 100, 200, 1000
]


# -------------------------------------------------
# HEALTHCHECK
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"ok": True}), 200
    except Exception as e:
        logger.exception("Healthcheck failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------------------------------------
# ROUTES (UNCHANGED LOGIC)
# -------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit(f"{1000 // int(os.getenv('FINISH_MIN_INTERVAL_MS', '300'))} per second")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("result" if current_user.status == "finished" else "game"))

    error = None
    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token", "")):
            error = "انتهت الجلسة، يرجى المحاولة مرة أخرى"
            return render_template("login.html", error=error, csrf_token=generate_csrf_token())

        user = User.query.filter_by(
            username=(request.form.get("username") or "").strip()
        ).first()

        if user and check_password_hash(user.password_hash, request.form.get("password") or ""):
            login_user(user)

            if user.status == "new":
                user.status = "playing"
                db.session.commit()

            session["play_login_sound"] = True
            return redirect(url_for("game"))

        error = "اسم المستخدم أو كلمة المرور غير صحيحة"

    return render_template("login.html", error=error, csrf_token=generate_csrf_token())

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))

@app.route("/game")
@login_required
def game():
    if current_user.status == "finished" or current_user.balance < 1:
        return redirect(url_for("result"))

    return render_template(
        "game.html",
        balance=current_user.balance,
        winnings=current_user.winnings,
        username=current_user.username,
        play_login_sound=session.pop("play_login_sound", False),
    )

@app.route("/api/drop", methods=["POST"])
@login_required
@limiter.limit(f"{1000 // int(os.getenv('DROP_MIN_INTERVAL_MS', '150'))} per second")
def drop_ball():
    try:
        user = (
            db.session.query(User)
            .filter(User.id == current_user.id)
            .with_for_update()
            .first()
        )

        if not user:
            return jsonify({"error": "User not found"}), 404

        if user.status == "finished":
            return jsonify({"error": "Game finished"}), 400

        if user.balance < 1.0:
            return jsonify({"error": "No balls left"}), 400

        # -------------------------------------------------
        # BET CONFIG
        # -------------------------------------------------
        bet_amount = 1.0

        # -------------------------------------------------
        # SLOT-INDEX-ONLY LOGIC (SINGLE SOURCE OF TRUTH)
        # -------------------------------------------------
        slot_index = random.randrange(len(SLOT_LAYOUT))

        # 🛡️ SAFETY CHECK (CRITICAL)
        if slot_index < 0 or slot_index >= len(SLOT_LAYOUT):
            logger.error(
                "Invalid slot index generated",
                extra={
                    "slot_index": slot_index,
                    "slot_layout_len": len(SLOT_LAYOUT),
                    "user_id": user.id,
                },
            )
            db.session.rollback()
            return jsonify({"error": "Invalid slot"}), 500

        # Prize value comes directly from slot index
        win_amount = float(SLOT_LAYOUT[slot_index])

        # -------------------------------------------------
        # APPLY RESULT
        # -------------------------------------------------
        user.balance -= bet_amount
        user.winnings += win_amount

        game_over = user.balance < 1.0

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
@limiter.limit(f"{1000 // int(os.getenv('FINISH_MIN_INTERVAL_MS', '300'))} per second")
def finish_game():
    try:
        user = (
            db.session.query(User)
            .filter(User.id == current_user.id)
            .with_for_update()
            .first()
        )

        if not user:
            return jsonify({"error": "User not found"}), 404

        user.status = "finished"
        db.session.commit()

        return jsonify({"redirect": url_for("result")})

    except Exception:
        db.session.rollback()
        logger.exception("Finish failed")
        return jsonify({"error": "Server error"}), 500


@app.route("/result")
@login_required
def result():
    if current_user.status != "finished":
        current_user.status = "finished"
        db.session.commit()

    return render_template(
        "result.html",
        amount=current_user.winnings,
        is_winner=current_user.winnings > 0,
        status="win" if current_user.winnings > 0 else "lose",
    )

# -------------------------------------------------
# CLI COMMANDS (UNCHANGED)
# -------------------------------------------------
@app.cli.command("init-game")
def init_game():
    db.drop_all()
    db.create_all()

    pool = (
        [1000] * 2 + [100] * 20 + [50] * 43 + [25] * 60 +
        [10] * 100 + [5] * 200 + [1] * 350 + [0] * 555
    )
    random.shuffle(pool)

    users = [
        User(
            username=f"user{i+1}",
            password_hash=generate_password_hash("123456"),
            assigned_prize=float(prize),
        )
        for i, prize in enumerate(pool)
    ]

    db.session.add_all(users)
    db.session.commit()
    logger.info("✅ 1330 users created")

# -------------------------------------------------
# ENTRY
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5010")))
