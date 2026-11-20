import os

from flask import Flask, Response
from flask_login import LoginManager

from .models import User, db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET", "dev-only-change-me")
    # Session cookie hardening.
    #   HttpOnly: script cannot read the cookie (defence in depth for XSS).
    #   SameSite=Lax: the browser will not attach the cookie to cross-site POSTs.
    #   Secure needs HTTPS, so it is OFF on this plain-http lab server; turn it
    #   on in production (behind TLS) with SESSION_COOKIE_SECURE = True.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        app.instance_path, "portal.db")
    if os.environ.get("PORTAL_DB"):  # tooling hook: an explicit SQLite file path
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.environ["PORTAL_DB"]
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    from . import auth
    app.register_blueprint(auth.bp)
    from . import api, courses, staff
    app.register_blueprint(courses.bp)
    app.register_blueprint(staff.bp)
    app.register_blueprint(api.bp)

    from . import policy
    policy.install(app)                     # one before_request hook for every route

    @app.get("/robots.txt")
    @policy.requires(policy.PUBLIC)
    def robots():
        return Response("User-agent: *\nDisallow: /registrar-x9k2\n", mimetype="text/plain")

    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING") and User.query.first() is None:
            from .seed import seed
            seed()
    return app