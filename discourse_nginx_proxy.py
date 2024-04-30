from flask import Flask, session, request, make_response, url_for, redirect, abort
from yarl import URL
from urllib.parse import urlencode, parse_qs
import base64
import hmac
import hashlib
import time
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
app.secret_key = '145d2ac3deb58753d1623ae2cede10d2b5b3269e833dee4f83f8d8cbc59af3d4'
DISCOURSE_KEY = b'sssssecret'

app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

def _compute_sso_hash(sso):
    return hmac.new(DISCOURSE_KEY, sso, hashlib.sha256).hexdigest()

@app.route("/auth")
def auth():
    now = time.time()
    if session.get("expiry", 0) < now:
        app.logger.info(request.headers)
        response = make_response("", 401)
        response.headers["X-Auth-Login-URI"] = url_for(
            "login",
            _external=True,
            return_url=request.headers["X-Original-Uri"]
            )
        return response
    
    response = make_response("", 200)
    response.headers["X-Auth-Username"] = session["username"]
    response.headers["X-Auth-User-Id"] = session["user_id"]
    session["expiry"] = now + 3600 * 2

    return response


@app.route("/login")
def login():
    nonce = secrets.token_urlsafe()
    session["nonce"] = nonce
    return_url = request.args["return_url"]
    return_sso_url = url_for("validate", _external=True, return_url=return_url)
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


@app.route("/validate")
def validate():
    sig = request.args.get("sig", "")
    sso = request.args.get("sso", "")

    if sig != _compute_sso_hash(sso.encode("utf-8")):
        abort(403, "signature mismatch")

    qs = base64.b64decode(sso).decode("utf-8")
    args = parse_qs(qs)
    try:
        session_nonce = session.pop("nonce")
        if args["nonce"][0] != session_nonce:
            abort(403, "missing nonce")

        return_url = request.args["return_url"]
        session["username"] = args["username"][0]
        session["user_id"] = args["external_id"][0]
        session["expiry"] = time.time() + 3600*2

        return redirect(return_url, 302)

    except KeyError as ex:
        abort(403, ex)