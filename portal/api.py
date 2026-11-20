from flask import Blueprint, jsonify, request
from flask_login import current_user

from .models import User, db
from .policy import AUTHENTICATED, requires

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/me")
@requires(AUTHENTICATED)
def me():
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


@bp.put("/users/<int:uid>/email")
@requires("change_email", load=lambda: db.session.get(User, request.view_args["uid"]))
def set_email(uid):
    new_email = request.get_json()["email"]
    # A user may change only their own address, and not to one already in use.
    if User.query.filter(User.email == new_email, User.id != current_user.id).first():
        return jsonify(status="error", detail="email in use"), 409
    current_user.email = new_email
    db.session.commit()
    return jsonify(status="ok")