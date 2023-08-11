from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in!", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Incorrect Password!", category="error")
        else:
            flash("No account detected!", category="error")
    return render_template("login.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        first_name = request.form.get("fName")
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already Exists!", category="error")
        elif len(first_name) < 2:
            flash(
                "First name and Last name must be greater than 2 characters",
                category="error",
            )
        elif len(email) < 4:
            flash("Email must be greater than 3 character!", category="error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters", category="error")
        else:
            new_user = User(
                first_name=first_name,
                email=email,
                password=generate_password_hash(password, method="sha256"),
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash("Account Created!", category="success")
            return redirect(url_for("views.home"))

    return render_template("signUp.html", user=current_user)
