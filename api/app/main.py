import uuid
import msal
from flask import (
    Flask, session, jsonify,
    request, redirect, url_for, Response
    )
from flask_session import Session

import config.auth_config as config
import app.core.auth as auth

app = Flask(__name__)
app.config.from_object(config)
Session(app)

@app.errorhandler(auth.AuthError)
def handle_auth_error(ex: auth.AuthError) -> Response:
    """
    serializes the given AuthError as json and sets the response status code accordingly.
    :param ex: an auth error
    :return: json serialized ex response
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    return session.get("user")

@app.route("/private")
@auth.requires_auth
def private_endpoint(token_claims):
    print(token_claims)
    # if not session.get("user"):
    #     return jsonify({'message': 'Unauthorized.'}), 403
    return jsonify({'message': 'Hello from a private endpoint! You need to be authenticated to see this..'}), 200

###############################################################################

#                       TOKEN CACHING AND AUTH FUNCTIONS                      #

###############################################################################

# Its absolute URL must match your app's redirect_uri set in AAD
@app.route("/get_auth_token")
def authorized():
    if request.args['state'] != session.get("state"):
        return redirect(url_for("login"))
    cache = _load_cache()
    result = _build_msal_app(cache).acquire_token_by_authorization_code(
        request.args['code'],
        scopes=config.SCOPE,
        redirect_uri=url_for("authorized", _external=True))
    print(result)
    if "error" in result:
        return "Login failure: %s, %s" % (
            result["error"], result.get("error_description"))
    session["user"] = result.get("id_token_claims")
    _save_cache(cache)
    return redirect(url_for("index"))


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        config.CLIENT_ID, authority=authority or config.AUTHORITY,
        client_credential=config.CLIENT_SECRET, token_cache=cache)


def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache)
    accounts = cca.get_accounts()
    if accounts:  # So all accounts belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result

def get_token(scope):
    token = _get_token_from_cache(scope)
    if not token:
        return redirect(url_for("login"))
    return token

###############################################################################

#                       LOGN/LOGOUT FUNCTIONS                                 #

###############################################################################

@app.route("/login")
def login():
    session["state"] = str(uuid.uuid4())
    auth_url = _build_msal_app().get_authorization_request_url(
        config.SCOPE,
        state=session["state"],
        redirect_uri=url_for("authorized", _external=True))
    return "<a href='%s'>Login with Microsoft Identity</a>" % auth_url


@app.route("/logout")
def logout():
    session.clear()  # Wipe out the user and the token cache from the session
    return redirect(  # Also need to log out from the Microsoft Identity platform
        "https://login.microsoftonline.com/common/oauth2/v2.0/logout"
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

if __name__ == "__main__":
    app.run()