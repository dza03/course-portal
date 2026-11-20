from markupsafe import escape
from flask import Blueprint, render_template, request
from flask_login import current_user

from .models import Assignment, Course, Submission, db
from .policy import AUTHENTICATED, requires

bp = Blueprint("courses", __name__)


@bp.get("/")
@requires(AUTHENTICATED)
def dashboard():
    ids = current_user.enrolled_in | current_user.staff_of
    courses = Course.query.filter(Course.id.in_(ids)).all() if ids else []
    return render_template("dashboard.html", courses=courses)


@bp.get("/courses/<int:cid>/materials")
@requires("view_material", load=lambda: db.session.get(Course, request.view_args["cid"]))
def materials(cid):
    return render_template("materials.html", course=db.get_or_404(Course, cid))


@bp.post("/assignments/<int:aid>/submit")
@requires("submit", load=lambda: db.session.get(Assignment, request.view_args["aid"]))
def submit(aid):
    assignment = db.get_or_404(Assignment, aid)
    sub = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
    if sub is None:
        sub = Submission(assignment_id=aid, student_id=current_user.id)
        db.session.add(sub)
    sub.body = request.form.get("body", "")
    db.session.commit()
    return render_template("submission.html", sub=sub)


@bp.get("/submissions/<int:sid>")
@requires("view_submission", load=lambda: db.session.get(Submission, request.view_args["sid"]))
def view_submission(sid):
    sub = db.get_or_404(Submission, sid)
    return render_template("submission.html", sub=sub)


@bp.post("/submissions/<int:sid>/grade")
@requires("grade", load=lambda: db.session.get(Submission, request.view_args["sid"]))
def grade(sid):
    sub = db.get_or_404(Submission, sid)
    sub.grade = request.form.get("grade")
    db.session.commit()
    return f"Grade for submission {sub.id} set to {escape(sub.grade)}."


@bp.post("/submissions/<int:sid>/change")
@requires("change_grade", load=lambda: db.session.get(Submission, request.view_args["sid"]))
def change(sid):
    sub = db.get_or_404(Submission, sid)
    return render_template("change_confirm.html", sub=sub,
                           grade=request.form.get("grade"))


@bp.post("/submissions/<int:sid>/change/confirm")
@requires("change_grade", load=lambda: db.session.get(Submission, request.view_args["sid"]))
def change_confirm(sid):
    sub = db.get_or_404(Submission, sid)
    if request.form.get("confirmed") == "true":
        sub.grade = request.form.get("grade")
        db.session.commit()
        return f"Grade for submission {sub.id} changed to {escape(sub.grade)}."
    return "Change cancelled."


@bp.get("/gradebook/<int:cid>")
@requires("view_gradebook", load=lambda: db.session.get(Course, request.view_args["cid"]))
def gradebook(cid):
    course = db.get_or_404(Course, cid)
    subs = (Submission.query.join(Assignment)
            .filter(Assignment.course_id == cid).all())
    return render_template("gradebook.html", course=course, subs=subs)