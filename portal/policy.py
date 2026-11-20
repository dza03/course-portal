"""Access control policy for the Course Portal (Level 4, Part 4).

  ROLE_PERMISSIONS   RBAC: which permissions each role could ever use.
  CONDITIONS         ABAC: one function per permission, (user, obj, ctx) -> bool.
  can()              step 1 RBAC, step 2 ABAC; anything unknown is denied.
  requires()         declare, next to a route, the permission it needs and how
                     to load the object it is about.
  install(app)       one before_request hook that checks every request.
"""

import hmac

from flask import abort, request, session
from flask_login import current_user

from .models import utcnow

# Sentinels for routes that are not permission-gated.
PUBLIC = "__public__"            # anyone, signed in or not
AUTHENTICATED = "__auth__"       # any signed-in user, no specific permission

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


# --- Step 1: RBAC -----------------------------------------------------------
# Which permissions each role could EVER use. The condition still has to pass.
ROLE_PERMISSIONS = {
    "student":    {"view_material", "submit", "view_grade", "view_submission",
                   "change_email"},
    "ta":         {"view_material", "view_submission", "grade", "view_gradebook",
                   "change_email"},
    "instructor": {"view_material", "view_submission", "create_assignment", "grade",
                   "change_grade", "view_gradebook", "release_grades", "change_email"},
    "registrar":  {"enroll", "manage_roles", "assign_staff", "change_email"},
    "chair":      {"view_gradebook", "change_email"},
}


# --- Step 2: ABAC -----------------------------------------------------------
# One function per permission. obj and ctx may be None.

def _course_id_of(obj):
    """Accept a Course, Assignment or Submission and return its course id."""
    if obj is None:
        return None
    return getattr(obj, "course_id", None) or getattr(obj, "id", None)


CONDITIONS = {
    # R1: the course is one I study or one I staff.
    "view_material":     lambda u, o, c: _course_id_of(o) in (u.enrolled_in | u.staff_of),
    # R2: I am enrolled and the deadline has not passed (server clock).
    "submit":            lambda u, o, c: o is not None and o.course_id in u.enrolled_in
                                          and utcnow() < o.deadline,
    # R3: my own submission, and it has been released.
    "view_grade":        lambda u, o, c: o is not None and o.student_id == u.id and o.released,
    # my own submission, or one in a course I staff (for the submission page).
    "view_submission":   lambda u, o, c: o is not None and (
                                          o.student_id == u.id or o.course_id in u.staff_of),
    # R4: the course is one I teach.
    "create_assignment": lambda u, o, c: _course_id_of(o) in u.teaches,
    # R5 (grade): course I staff, and not yet released.
    "grade":             lambda u, o, c: o is not None and o.course_id in u.staff_of
                                          and not o.released,
    # R5 (change): course I teach, and before the term grade deadline.
    "change_grade":      lambda u, o, c: o is not None and o.course_id in u.teaches
                                          and utcnow() < o.course.grade_deadline,
    # R6: registrar only (role gate); no object condition.
    "enroll":            lambda u, o, c: True,
    # Attack 1: only the registrar manages roles.
    "manage_roles":      lambda u, o, c: True,
    # Attack 2: gradebook of a course I staff.
    "view_gradebook":    lambda u, o, c: _course_id_of(o) in u.staff_of or u.role == "chair",
    # Attack 3: release grades of a course I teach.
    "release_grades":    lambda u, o, c: _course_id_of(o) in u.teaches,
    # Attack 7: registrar assigns staff; no object condition.
    "assign_staff":      lambda u, o, c: True,
    # Attack 5: a user may change only their own e-mail address.
    "change_email":      lambda u, o, c: o is not None and o.id == u.id,
}


def can(user, perm, obj=None, ctx=None):
    """True only if the role holds the permission AND its condition passes.
    A permission nobody defined is denied."""
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if perm not in CONDITIONS:                       # deny by default
        return False
    if perm not in ROLE_PERMISSIONS.get(user.role, set()):
        return False
    try:
        return bool(CONDITIONS[perm](user, obj, ctx))
    except Exception:
        return False


def role_holds(user, perm):
    return perm in ROLE_PERMISSIONS.get(getattr(user, "role", None), set())


# --- Route declarations -----------------------------------------------------

def requires(perm, load=None):
    """Attach an access rule to a view. `load` is a zero-arg callable that
    reads the current request and returns the object the permission is about
    (or None if it does not exist)."""
    def deco(f):
        f._acl = (perm, load)
        return f
    return deco


def _valid_csrf():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    good = session.get("csrf_token", "")
    return bool(good) and hmac.compare_digest(str(sent), str(good))


# --- Step 3: one hook for every request ------------------------------------

def install(app):

    @app.context_processor
    def _inject_csrf():
        return {"csrf_token": session.get("csrf_token", "")}

    @app.before_request
    def _guard():
        endpoint = request.endpoint
        if endpoint == "static":                     # static files are public
            return
        view = app.view_functions.get(endpoint)
        rule = getattr(view, "_acl", None)

        # A route with no rule is refused, not left open.
        if rule is None:
            abort(403)
        perm, load = rule

        if perm == PUBLIC:
            return                                   # no auth, no CSRF

        # Every non-public route needs a signed-in user.
        if not current_user.is_authenticated:
            abort(401)

        if perm != AUTHENTICATED:
            obj = load() if load else None
            # The object does not exist -> 404 (also hides it from guessing).
            if load is not None and obj is None:
                abort(404)
            ctx = {"network": "campus" if request.remote_addr in ("127.0.0.1", None)
                   else "external"}
            if not can(current_user, perm, obj, ctx):
                # Role can never do this -> 403 (vertical).
                # Role could, but not on this object -> 404, so a probe for
                # another student's record cannot tell "exists" from "forbidden".
                abort(403 if not role_holds(current_user, perm) else 404)

        # CSRF: every state-changing request must carry this session's token.
        if request.method in UNSAFE and not _valid_csrf():
            abort(403)