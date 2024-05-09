from flask import Flask, session, request, make_response, url_for, redirect, abort
from yarl import URL
from urllib.parse import urlencode, parse_qs
import base64
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix
import jwt
import base64


app = Flask(__name__)
app.secret_key = '145d2ac3deb58753d1623ae2cede10d2b5b3269e833dee4f83f8d8cbc59af3d4'
app.config["JWT_LIFETIME_SECS"] = timedelta(hours=6).total_seconds()
app.config["JWT_REFRESH_LEEWAY_SECS"] = timedelta(hours=6).total_seconds()

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

def _compute_sso_hash(sso):
    return hmac.new(DISCOURSE_KEY, sso, hashlib.sha256).hexdigest()

@app.route("/login")
def login():
    resp = validate_jwt()
    if resp:
        return resp

    resp = validate_sso()
    if resp:
        return resp

    nonce = secrets.token_urlsafe()
    session["nonce"] = nonce
    return_url = request.headers["X-Original-Uri"]
    return_sso_url = url_for("login", _external=True, return_url=return_url)
    qs = {"nonce": nonce, "return_sso_url": return_sso_url}
    query_string = urlencode(qs)
    encoded_str = base64.b64encode(query_string.encode("utf-8"))
    remote_url = URL("https://bristolhackspace.discourse.group").with_path("/session/sso_provider")
    remote_url = remote_url.with_query(
        {
            "sso": encoded_str.decode("utf-8"),
            "sig": _compute_sso_hash(encoded_str),
        }
    )
    return redirect(str(remote_url), 302)


def validate_jwt():
    # This lets us refresh a JWT that's just expired instead of going through the whole
    # Discourse SSO login flow
    token = request.cookies.get("jwtauth", "")
    if not token:
        return False

    key = base64.b64decode(app.config["JWT_KEY"])
    leeway = app.config["JWT_REFRESH_LEEWAY_SECS"]
    try:
        claims = jwt.decode(token, key, leeway=leeway)
    except jwt.exceptions.InvalidTokenError:
        return False

    lifetime = app.config["JWT_LIFETIME_SECS"]
    new_expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=lifetime)
    claims["exp"] = new_expiry
    token = jwt.encode(claims, key)
    resp = make_response(redirect(request.args["return_url"], 307))
    resp.set_cookie("jwtauth", token, httponly=True)
    return resp


def validate_sso():
    sso = request.args.get("sso", "")
    sig = request.args.get("sig", "")
    if not sso:
        return False

    if sig != _compute_sso_hash(sso.encode("utf-8")):
        return make_response("Signature verif failed", 400)
    qs = base64.b64decode(sso).decode("utf-8")
    args = parse_qs(qs)

    session_nonce = session.pop("nonce", None)
    if args["nonce"][0] != session_nonce:
        return make_response("Nonce already used", 400)

    jwtargs = {
        "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=app.config["JWT_LIFETIME_SECS"]),
        "sub": args["username"][0],
        "discourse_id": args["external_id"][0]
    }
    key = base64.b64decode(app.config["JWT_KEY"])
    token = jwt.encode(jwtargs, key)

    resp = make_response(redirect(request.args["return_url"], 302))
    resp.set_cookie("jwtauth", token, httponly=True)
    return resp