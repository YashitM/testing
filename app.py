import os
import json
import datetime
import requests

from flask import make_response, send_file
from datetime import timedelta
from flask import Flask, url_for, redirect, \
    render_template, session, request, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError

basedir = os.path.abspath(os.path.dirname(__file__))
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

"""App Configuration"""

SESSION_TIMEOUT = 60
REDIRECT_URL = "http://34.219.188.123/"

class Auth:
    """Google Project Credentials"""
    CLIENT_ID = ('59342058181-q1pdc4mtac3o45h27rbvncoa5ah06m5q.apps.googleusercontent.com')

    CLIENT_SECRET = 'WKdb1qDKI4AQ-DDrOKyPnwzl'
    REDIRECT_URI = 'http://ec2-34-221-15-125.us-west-2.compute.amazonaws.com:8081/gCallback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']


class Config:
    """Base config"""
    APP_NAME = "Test Google Login"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "somethingsecret"
                
        
class DevConfig(Config):
    """Dev config"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "test.db")


class ProdConfig(Config):
    """Production config"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, "prod.db")


config = {
    "dev": DevConfig,
    "prod": ProdConfig,
    "default": DevConfig
}

"""APP creation and configuration"""
app = Flask(__name__)
app.config.from_object(config['dev'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

""" DB Models """

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())    


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
""" OAuth Session creation """


def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth


@app.route('/')
@login_required
def index():
    print(request.path)
    """resp = requests.request(
        method=request.method,
        url=request.url.replace(request.host_url, 'http://34.219.188.123/'),
        #url=request.url.replace(request.host_url, 'https://www.instagram.com/'),
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

#    print(headers)

    response = Response(resp.content, resp.status_code, headers)
    return response"""
    return redirect(REDIRECT_URL)

@app.route('/test')
def test():
    return "asdfasdf"

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return redirect(auth_url)


@app.route('/gCallback')
def callback():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            if email.split('@')[1] != 'grofers.com':
                flash('You cannot login using this email', 'error')
                return redirect(url_for('login'))
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        return 'Could not fetch your information.'


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

"""@app.route('/<path:path>', methods=["GET","POST"])
def static_content(path):
    print(path, request.method)
    if request.method == "GET":
        response = requests.get(REDIRECT_URL + path).content
        if ".ico" in path or '.svg' in path or '.png' in path:
            open(path.replace("/", "_"),'wb').write(response)
            return send_file(path.replace("/", "_"), mimetype="image/png")
        return response
    elif request.method == "POST":
        print(request.data)
        return requests.post(REDIRECT_URL + path, data=request.data).content"""

if __name__ == "__main__":
    db.create_all()
    app.run(host="0.0.0.0", port=8081)
