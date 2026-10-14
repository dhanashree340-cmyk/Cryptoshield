"""
auth/routes.py
/register, /login and /logout, using Flask sessions.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from audit_module import log
from .utils import (
    valid_username, valid_password, create_user, username_taken, check_login,
    is_blocked, record_failure, clear_failures, current_user,
    MIN_PASSWORD_LEN, MAX_PASSWORD_LEN,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not valid_username(username):
            flash("Username must be 3-30 characters: letters, numbers, dot, dash or underscore.", "error")
        elif not valid_password(password):
            flash(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif username_taken(username) or not create_user(username, password):
            flash("That username is already registered.", "error")
        else:
            log("REGISTERED", username)
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        throttle_key = ("login", request.remote_addr, username.lower())

        if is_blocked(throttle_key):
            flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
            return render_template("login.html"), 429

        user = check_login(username, password) if valid_username(username) and isinstance(password, str) else None
        if user is None:
            record_failure(throttle_key)
            # Only log names that pass validation (keeps the log clean/safe)
            log("LOGIN FAILED", username if valid_username(username) else "(invalid-name)")
            flash("Invalid username or password", "error")
            return render_template("login.html"), 401

        clear_failures(throttle_key)
        session.clear()                      # fresh session after login
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        log("LOGIN SUCCESS", user["username"])
        return redirect(url_for("index"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user:
        log("LOGOUT", user["username"])
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
