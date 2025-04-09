from flask import Blueprint, request, render_template, redirect, url_for, flash

from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        is_admin = bool(request.form.get("is_admin"))

        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="User already exists")

        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("auth.login"))

    return render_template("register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for("auth.admin_dashboard"))
            else:
                return redirect(url_for("auth.user_dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'}), 200
    
@auth_bp.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for("auth.user_dashboard"))
    return render_template("admin_dashboard.html")


@auth_bp.route("/user_dashboard")
@login_required
def user_dashboard():
    return render_template("user_dashboard.html")

